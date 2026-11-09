"""Markdown and JSON reports. Nothing here ever includes credentials."""
from __future__ import annotations

from .repair import FileResult
from .suggest import unified

MARKER = "<!-- ease-bot:summary -->"
ICON = {"verified": "✅", "partial": "🟡", "rejected": "❌", "clean": "⚪", "skipped": "⏭️", "error": "⚠️"}


def summary_markdown(results: list[FileResult], model: str, scanners: list[str], posted: dict | None = None,
                     footer_note: str = "") -> str:
    posted = posted or {}
    counts = {}
    for r in results:
        counts[r.verdict] = counts.get(r.verdict, 0) + 1
    total_before = sum(len(r.before) for r in results)
    total_fixed = sum(len(r.before) - len(r.after) for r in results if r.after is not None)
    lines = [MARKER, "## 🛡️ EASE-Bot: verified IaC security fixes", ""]
    if not results:
        lines += ["No Terraform or Kubernetes files changed in this PR.", ""]
    else:
        lines += [f"Scanned **{len(results)}** changed IaC file(s) with {', '.join(scanners)}: "
                  f"**{total_before}** fixable finding(s), **{total_fixed}** removed by a checked suggestion"
                  f" ({sum(len(r.deferred) for r in results)} more need a human decision).", "",
                  "| File | Verdict | Fixable findings before → after | Deferred | New in this PR | Note |",
                  "|---|---|---|---|---|---|"]
        for r in results:
            after = "–" if r.after is None else str(len(r.after))
            n_new = len(r.introduced_by_pr)
            newpr = "–" if not n_new else ("all" if n_new == len({f.rule_id for f in r.before}) else
                                           ", ".join(f"`{x}`" for x in r.introduced_by_pr[:6]) +
                                           (f" +{n_new - 6}" if n_new > 6 else ""))
            lines.append(f"| `{r.path}` | {ICON.get(r.verdict, '')} {r.verdict} | {len(r.before)} → {after} | "
                         f"{len(r.deferred)} | {newpr} | {r.reason.replace('|', '/')} |")
        lines.append("")
        for r in results:
            if not r.before and not r.deferred:
                continue
            lines.append(f"<details><summary><b>{r.path}</b>: {ICON.get(r.verdict, '')} {r.verdict}</summary>\n")
            lines.append("**Findings**\n")
            fixed = set(r.fixed)
            for f in r.before:
                mark = "✔ fixed" if f.rule_id in fixed else "open"
                tag = " 🆕" if f.rule_id in r.introduced_by_pr and len(r.introduced_by_pr) < len(r.before) else ""
                lines.append(f"- `{f.rule_id}` ({f.scanner}) {f.title}, resource `{f.resource or 'n/a'}`: {mark}{tag}")
            if r.deferred:
                lines.append("\n**Needs a human decision (reported, not auto-fixed)**\n")
                lines += [f"- `{f.rule_id}` ({f.scanner}) {f.title}" for f in r.deferred]
            if r.checks:
                lines.append("\n**Verification**\n")
                lines += [f"- {c}" for c in r.checks]
            if r.attempts:
                lines.append("\n**Repair rounds**\n")
                lines += [f"- {a}" for a in r.attempts]
            if r.notes:
                lines.append("\n**What the model changed**\n")
                still_open = {f.rule_id for f in (r.after or [])}
                lines += [f"- {n.get('rule_id', '')}: {n.get('change', '')}"
                          + (" ⚠️ *the model says this is fixed, but the re-scan still reports it*"
                             if n.get("rule_id") in still_open else "") for n in r.notes[:15]]
            if r.fixed_file:
                n = posted.get(r.path, 0)
                if n:
                    lines.append(f"\n{n} inline suggestion(s) posted on the diff. To apply, use **Add suggestion to batch** "
                                 "on each part, then **Commit suggestions**.")
                lines.append("\n**Full patch**\n\n```diff\n" + unified(r.original, r.fixed_file, r.path) + "```")
            lines.append("\n</details>\n")
    lines += ["---",
              f"<sub>Model: {model}. Scanners: {', '.join(scanners)}. A fix is shown only if the file still parses, "
              "keeps every original resource, adds no new findings and removes at least one. "
              "Scanner-clean is not the same as deployable: review every suggestion before merging. "
              f"{footer_note}</sub>"]
    return "\n".join(lines)


def to_json(results: list[FileResult]) -> list[dict]:
    return [r.to_dict() for r in results]
