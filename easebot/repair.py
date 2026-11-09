"""Scan -> LLM fix -> verify loop. A candidate is accepted only if it is valid, keeps every original
resource, introduces no new findings, and removes at least one finding."""
from __future__ import annotations

from dataclasses import dataclass, field

from . import llm as llm_mod
from .scanners import Finding, scan as default_scan
from .validate import intent_check, syntax_check

MAX_CHARS = 14000  # keeps prompts inside free-tier token limits

# Checks that need a design decision or a value the model cannot know (another bucket for logs, a
# replication region, a KMS key, a real image digest, which resource a security group belongs to).
# They are reported but never auto-fixed: in testing, "fixing" them made the model invent resources.
DEFAULT_DEFERRED = frozenset({
    "CKV2_AWS_5", "CKV2_AWS_61", "CKV2_AWS_62", "CKV_AWS_144", "CKV_AWS_145", "CKV_AWS_18", "CKV_AWS_189",
    "CKV_K8S_43", "CKV2_K8S_6", "AWS-0027", "AWS-0089", "AWS-0132", "KSV-0125",
})


@dataclass
class FileResult:
    path: str
    kind: str
    verdict: str = "clean"  # clean | verified | partial | rejected | skipped | error
    reason: str = ""
    before: list[Finding] = field(default_factory=list)
    deferred: list[Finding] = field(default_factory=list)
    after: list[Finding] | None = None
    introduced_by_pr: list[str] = field(default_factory=list)
    fixed: list[str] = field(default_factory=list)
    new: list[str] = field(default_factory=list)
    original: str = ""
    fixed_file: str | None = None
    notes: list[dict] = field(default_factory=list)
    checks: list[str] = field(default_factory=list)
    rounds: int = 0
    attempts: list[str] = field(default_factory=list)

    def to_dict(self):
        d = {k: v for k, v in self.__dict__.items() if k not in ("original",)}
        d["before"] = [f.to_dict() for f in self.before]
        d["deferred"] = [f.to_dict() for f in self.deferred]
        d["after"] = None if self.after is None else [f.to_dict() for f in self.after]
        return d


def _fmt(findings: list[Finding]) -> str:
    return "\n".join(f"- [{f.scanner}] {f.rule_id}: {f.title} (resource: {f.resource or 'n/a'}, line {f.line})"
                     for f in findings)


def repair_file(path: str, content: str, kind: str, llm, scanners: list[str], *, base_content: str | None = None,
                context_dir: str | None = None, max_rounds: int = 3, use_tools: bool = True,
                scan=default_scan, deferred=DEFAULT_DEFERRED) -> FileResult:
    res = FileResult(path=path, kind=kind, original=content)
    if len(content) > MAX_CHARS:
        res.verdict, res.reason = "skipped", f"file larger than {MAX_CHARS} characters"
        return res
    deferred = set(deferred or ())

    def actionable(fs):
        return [f for f in fs if f.rule_id not in deferred]

    allf = scan(content, kind, scanners, path)
    res.before = actionable(allf)
    res.deferred = [f for f in allf if f.rule_id in deferred]
    if base_content is not None:
        base_keys = {f.key for f in scan(base_content, kind, scanners, path)} if base_content.strip() else set()
        res.introduced_by_pr = sorted({f.rule_id for f in res.before if f.key not in base_keys})
    if not res.before:
        res.verdict = "clean"
        res.reason = "no findings" if not res.deferred else f"only {len(res.deferred)} deferred finding(s) need a human"
        return res

    current, current_findings = content, res.before
    best = None  # (fixed_text, findings, notes, checks)
    reason, feedback = "", ""
    for rnd in range(1, max_rounds + 1):
        res.rounds = rnd
        prompt = llm_mod.PROMPT.format(kind=kind, path=path, findings=_fmt(current_findings), content=current,
                                       feedback=feedback)
        try:
            reply = llm_mod.parse_reply(llm(prompt))
        except Exception as e:  # LLM/network/format problems never crash the run
            reason = f"LLM error: {e}"
            if best is None and rnd < max_rounds and "format" not in str(e).lower():
                feedback = "\nYour previous answer could not be parsed. Follow the answer format exactly.\n"
                continue
            break
        cand = reply["fixed_file"]
        if not cand.endswith("\n") and content.endswith("\n"):
            cand += "\n"
        problem, checks = None, []
        if cand == current:
            problem = "the file came back unchanged"
        else:
            ok, msg = syntax_check(cand, kind, path, context_dir, use_tools, original=content)
            checks.append(("valid" if ok else "unchecked" if ok is None else "INVALID") + f": {msg}")
            if ok is False:
                problem = f"the file is not valid ({msg})"
            else:
                iok, imsg, _ = intent_check(content, cand, kind)
                checks.append(("intent kept" if iok else "INTENT CHANGED") + f": {imsg}")
                if not iok:
                    problem = imsg
                else:
                    after = actionable(scan(cand, kind, scanners, path))
                    before_keys = {f.key for f in res.before}
                    new = [f for f in after if f.key not in before_keys]
                    if new:
                        ids = sorted({f.rule_id for f in new})
                        titles = sorted({f"{f.rule_id} ({f.title})" for f in new})
                        problem = "it introduced new findings: " + "; ".join(titles)
                        res.new = ids
                    elif len(after) >= len(current_findings):
                        problem = "it removed no findings"
        if problem:
            reason = f"round {rnd} candidate rejected: {problem}"
            res.attempts.append(reason)
            feedback = (f"\nA previous attempt was REJECTED by the verifier because {problem}. "
                        "Do not repeat that. It is fine to fix fewer findings.\n")
            continue
        res.attempts.append(f"round {rnd}: accepted, {len(current_findings) - len(after)} finding(s) removed")
        best = (cand, after, reply["notes"], checks)
        current, current_findings, feedback, reason = cand, after, "", ""
        if not after:
            break

    if best is None:
        res.verdict, res.reason = ("error" if reason.startswith("LLM error") else "rejected"), reason
        return res
    cand, after, notes, checks = best
    res.fixed_file, res.after, res.notes, res.checks = cand, after, notes, checks
    after_keys = {f.key for f in after}
    res.fixed = sorted({f.rule_id for f in res.before if f.key not in after_keys})
    if not after:
        res.verdict = "verified"
        res.reason = "re-scan clean, no new findings, file valid, resources preserved"
    else:
        res.verdict = "partial"
        res.reason = f"{len(res.before) - len(after)} of {len(res.before)} findings fixed; {len(after)} remain" + (
            f" ({reason})" if reason else "")
    if any(c.startswith("unchecked") for c in checks) and res.verdict == "verified":
        res.reason += " (syntax only partly checked)"
    return res
