"""Command line entry point.

  easebot scan demo/            # local run (no GitHub needed)
  easebot scan --llm mock demo/ # fully offline
  easebot pr                    # inside GitHub Actions on a pull_request event
"""
from __future__ import annotations

import argparse
import json
import os
import pathlib
import subprocess
import sys

from . import __version__
from .llm import get_llm
from .repair import DEFAULT_DEFERRED, repair_file
from .report import MARKER, summary_markdown, to_json
from .scanners import available_scanners, detect_kind
from .suggest import split_postable, suggestions

VERDICT_ORDER = ["clean", "skipped", "verified", "partial", "error", "rejected"]


def log(msg: str):
    print(msg, file=sys.stderr, flush=True)


def _common(p):
    p.add_argument("--llm", default=os.environ.get("EASEBOT_LLM", "groq"),
                   choices=["groq", "openai-compatible", "mock"], help="LLM provider (default: groq)")
    p.add_argument("--model", default=None, help="model id (default openai/gpt-oss-120b)")
    p.add_argument("--base-url", default=None, help="OpenAI-compatible base URL")
    p.add_argument("--scanners", default="checkov,trivy", help="comma list; missing scanners are skipped")
    p.add_argument("--max-rounds", type=int, default=3, help="repair rounds per file")
    p.add_argument("--no-tool-validate", "--no-terraform-validate", dest="no_tool_validate", action="store_true",
                   help="skip `terraform validate` and kubeconform (YAML/brace checks only)")
    p.add_argument("--defer-checks", default="default",
                   help="comma list of rule ids to report but not auto-fix; 'default' or 'none'")
    p.add_argument("--json", dest="json_out", help="write a JSON report here")
    p.add_argument("--markdown", dest="md_out", help="write the Markdown summary here")
    p.add_argument("--fail-on", default="none", choices=["none", "rejected", "findings"],
                   help="exit 1 if any file is rejected / if any finding is left unfixed")


def _setup(args):
    scanners = available_scanners([s.strip() for s in args.scanners.split(",") if s.strip()])
    if "checkov" not in scanners:
        log("error: checkov is required (pip install checkov)")
        raise SystemExit(2)
    llm = get_llm(args.llm, args.model, args.base_url)
    model = getattr(llm, "name", args.llm)
    d = args.defer_checks.strip()
    args.deferred = (set(DEFAULT_DEFERRED) if d == "default" else set() if d in ("", "none")
                     else {x.strip() for x in d.split(",") if x.strip()})
    return scanners, llm, model


def _exit_code(results, fail_on):
    if fail_on == "rejected" and any(r.verdict in ("rejected", "error") for r in results):
        return 1
    if fail_on == "findings" and any(r.before and r.verdict != "verified" for r in results):
        return 1
    return 0


def _write_outputs(args, results, md):
    if args.json_out:
        pathlib.Path(args.json_out).write_text(json.dumps(to_json(results), indent=2))
    if args.md_out:
        pathlib.Path(args.md_out).write_text(md)
    if os.environ.get("GITHUB_STEP_SUMMARY"):
        with open(os.environ["GITHUB_STEP_SUMMARY"], "a") as fh:
            fh.write(md.replace(MARKER, "") + "\n")
    if os.environ.get("GITHUB_OUTPUT"):
        with open(os.environ["GITHUB_OUTPUT"], "a") as fh:
            for v in VERDICT_ORDER:
                fh.write(f"{v}={sum(r.verdict == v for r in results)}\n")


def iter_files(paths):
    for p in paths:
        p = pathlib.Path(p)
        files = [p] if p.is_file() else sorted(x for x in p.rglob("*") if x.is_file() and ".terraform" not in x.parts)
        for f in files:
            try:
                text = f.read_text()
            except (UnicodeDecodeError, OSError):
                continue
            kind = detect_kind(str(f), text)
            if kind:
                yield f, kind, text


def git_show(ref: str, path: pathlib.Path) -> str | None:
    try:
        top = subprocess.run(["git", "rev-parse", "--show-toplevel"], cwd=path.parent, capture_output=True,
                             text=True, check=True).stdout.strip()
        rel = path.resolve().relative_to(top)
        r = subprocess.run(["git", "show", f"{ref}:{rel}"], cwd=top, capture_output=True, text=True)
        return r.stdout if r.returncode == 0 else None
    except Exception:
        return None


def cmd_scan(args) -> int:
    scanners, llm, model = _setup(args)
    results = []
    for f, kind, text in iter_files(args.paths):
        log(f"[ease-bot] {f} ({kind})")
        base = git_show(args.base, f) if args.base else None
        r = repair_file(str(f), text, kind, llm, scanners, base_content=base, context_dir=str(f.parent),
                        max_rounds=args.max_rounds, use_tools=not args.no_tool_validate,
                        deferred=args.deferred)
        log(f"           {r.verdict}: {r.reason}")
        if args.write and r.fixed_file and r.verdict in ("verified", "partial"):
            f.write_text(r.fixed_file)
            log("           fix written to disk")
        results.append(r)
    md = summary_markdown(results, model, scanners)
    _write_outputs(args, results, md)
    if not args.md_out and not args.json_out:
        print(md)
    return _exit_code(results, args.fail_on)


def cmd_pr(args) -> int:
    from .github import GitHub

    event = json.loads(pathlib.Path(os.environ["GITHUB_EVENT_PATH"]).read_text())
    pr = event.get("pull_request")
    if not pr:
        log("not a pull_request event; nothing to do")
        return 0
    token = os.environ.get("GITHUB_TOKEN")
    if not token:
        log("error: GITHUB_TOKEN is not set")
        return 2
    repo = os.environ["GITHUB_REPOSITORY"]
    number, head, base = pr["number"], pr["head"]["sha"], pr["base"]["sha"]
    gh = GitHub(repo, token)
    scanners, llm, model = _setup(args)
    workspace = pathlib.Path(os.environ.get("GITHUB_WORKSPACE", "."))

    files = [f for f in gh.pr_files(number) if f.get("status") != "removed"]
    targets = []
    for f in files:
        name = f["filename"]
        if not name.lower().endswith((".tf", ".yaml", ".yml")):
            continue
        content = gh.file_at(name, head)
        if content is None:
            continue
        kind = detect_kind(name, content)
        if kind:
            targets.append((f, kind, content))
    skipped_note = ""
    if len(targets) > args.max_files:
        skipped_note = f"Only the first {args.max_files} of {len(targets)} IaC files were checked."
        targets = targets[: args.max_files]

    results, posted = [], {}
    existing = {(c.get("path"), c.get("line"), c.get("body")) for c in gh.review_comments(number)}
    review_comments = []
    for f, kind, content in targets:
        name = f["filename"]
        log(f"[ease-bot] {name} ({kind})")
        base_content = gh.file_at(name, base) if f.get("status") != "added" else ""
        ctx = workspace / pathlib.Path(name).parent
        r = repair_file(name, content, kind, llm, scanners, base_content=base_content, context_dir=str(ctx),
                        max_rounds=args.max_rounds, use_tools=not args.no_tool_validate,
                        deferred=args.deferred)
        log(f"           {r.verdict}: {r.reason}")
        results.append(r)
        if r.fixed_file and r.verdict in ("verified", "partial"):
            postable, _ = split_postable(suggestions(content, r.fixed_file), f.get("patch"))
            label = "✅ verified" if r.verdict == "verified" else "🟡 partial"
            fixes = ", ".join(f"`{x}`" for x in r.fixed) or "n/a"
            for s in postable:
                body = (f"**EASE-Bot** ({label}): part of the checked fix for this file (fixes {fixes}).\n\n"
                        f"{s.body()}")
                if (name, s.end, body) in existing:
                    continue
                c = {"path": name, "line": s.end, "side": "RIGHT", "body": body}
                if s.start != s.end:
                    c.update(start_line=s.start, start_side="RIGHT")
                review_comments.append(c)
                posted[name] = posted.get(name, 0) + 1

    md = summary_markdown(results, model, scanners, posted, skipped_note)
    if review_comments:
        try:
            gh.create_review(number, head, "EASE-Bot suggested fixes (each one re-scanned and validated).",
                             review_comments)
        except Exception as e:  # e.g. fork PRs with a read-only token
            log(f"warning: could not post inline suggestions: {e}")
            md = summary_markdown(results, model, scanners, {}, skipped_note)
    try:
        url = gh.upsert_comment(number, MARKER, md)
        log(f"summary comment: {url}")
    except Exception as e:
        log(f"warning: could not post summary comment: {e}")
    _write_outputs(args, results, md)
    return _exit_code(results, args.fail_on)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="easebot", description="Verified LLM repair of IaC misconfigurations")
    ap.add_argument("--version", action="version", version=f"ease-bot {__version__}")
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("scan", help="scan and repair local files or folders")
    s.add_argument("paths", nargs="+")
    s.add_argument("--write", action="store_true", help="apply verified/partial fixes to the files")
    s.add_argument("--base", help="git ref to compare against, to mark findings introduced since then")
    _common(s)
    p = sub.add_parser("pr", help="run on a GitHub pull_request event and comment on the PR")
    p.add_argument("--max-files", type=int, default=10)
    _common(p)
    args = ap.parse_args(argv)
    return cmd_scan(args) if args.cmd == "scan" else cmd_pr(args)
