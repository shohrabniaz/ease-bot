from conftest import ScriptedLLM

from easebot.llm import LLMError
from easebot.repair import MAX_CHARS, repair_file

BASE = "apiVersion: v1\nkind: Pod\nmetadata:\n  name: web\nspec: {}\n"


def run(content, llm, fake_scan, **kw):
    kw.setdefault("deferred", {"DEFERRED_1"})
    return repair_file("k.yaml", content, "kubernetes", llm, ["checkov"], scan=fake_scan, use_tools=False, **kw)


def test_clean_file_never_calls_llm(fake_scan):
    llm = ScriptedLLM()
    r = run(BASE, llm, fake_scan)
    assert r.verdict == "clean" and llm.prompts == []


def test_verified_when_rescan_is_clean(fake_scan):
    r = run(BASE + "# BAD1\n", ScriptedLLM(BASE), fake_scan)
    assert r.verdict == "verified" and r.fixed == ["R1"] and r.after == []


def test_partial_when_some_findings_remain(fake_scan):
    r = run(BASE + "# BAD1 BAD2\n", ScriptedLLM(BASE + "# BAD2\n", BASE + "# BAD2\n"), fake_scan, max_rounds=2)
    assert r.verdict == "partial" and r.fixed == ["R1"] and [f.rule_id for f in r.after] == ["R2"]


def test_second_round_finishes_the_job(fake_scan):
    r = run(BASE + "# BAD1 BAD2\n", ScriptedLLM(BASE + "# BAD2\n", BASE), fake_scan)
    assert r.verdict == "verified" and r.rounds == 2


def test_new_finding_rejects_candidate_and_feeds_back(fake_scan):
    llm = ScriptedLLM(BASE + "# NEWBAD\n", BASE)
    r = run(BASE + "# BAD1\n", llm, fake_scan)
    assert r.verdict == "verified"
    assert "introduced new findings: RNEW" in r.attempts[0]
    assert "REJECTED by the verifier" in llm.prompts[1]


def test_rejected_after_all_rounds_fail(fake_scan):
    r = run(BASE + "# BAD1\n", ScriptedLLM(*(["kind: [\n"] * 3)), fake_scan)
    assert r.verdict == "rejected" and r.fixed_file is None and len(r.attempts) == 3


def test_renamed_object_is_rejected(fake_scan):
    r = run(BASE + "# BAD1\n", ScriptedLLM(BASE.replace("web", "web2")), fake_scan, max_rounds=1)
    assert r.verdict == "rejected" and "Pod/web" in r.reason


def test_unchanged_file_is_rejected(fake_scan):
    r = run(BASE + "# BAD1\n", ScriptedLLM(BASE + "# BAD1\n"), fake_scan, max_rounds=1)
    assert r.verdict == "rejected" and "unchanged" in r.reason


def test_deferred_findings_are_reported_not_fixed(fake_scan):
    llm = ScriptedLLM(BASE + "# DEFER\n")
    r = run(BASE + "# BAD1 DEFER\n", llm, fake_scan)
    assert r.verdict == "verified"
    assert [f.rule_id for f in r.deferred] == ["DEFERRED_1"]
    assert "DEFERRED_1" not in llm.prompts[0].split("File:")[0]


def test_only_deferred_is_clean(fake_scan):
    r = run(BASE + "# DEFER\n", ScriptedLLM(), fake_scan)
    assert r.verdict == "clean" and "deferred" in r.reason


def test_llm_error_is_reported_not_raised(fake_scan):
    r = run(BASE + "# BAD1\n", ScriptedLLM(LLMError("HTTP 500"), LLMError("HTTP 500"), LLMError("HTTP 500")),
            fake_scan)
    assert r.verdict == "error" and "HTTP 500" in r.reason


def test_findings_introduced_by_pr(fake_scan):
    r = run(BASE + "# BAD1 BAD2\n", ScriptedLLM(BASE), fake_scan, base_content=BASE + "# BAD1\n")
    assert r.introduced_by_pr == ["R2"]


def test_new_file_marks_everything_introduced(fake_scan):
    r = run(BASE + "# BAD1\n", ScriptedLLM(BASE), fake_scan, base_content="")
    assert r.introduced_by_pr == ["R1"]


def test_large_file_skipped(fake_scan):
    r = run(BASE + "#" * (MAX_CHARS + 1), ScriptedLLM(), fake_scan)
    assert r.verdict == "skipped"
