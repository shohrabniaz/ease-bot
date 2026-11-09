import json
import shutil

import pytest
from conftest import F

from easebot import cli, report
from easebot.repair import FileResult

SECRET = "gsk_DO_NOT_LEAK_123"


def test_report_has_marker_verdicts_and_no_secret(monkeypatch):
    monkeypatch.setenv("GROQ_API_KEY", SECRET)
    r = FileResult(path="a.tf", kind="terraform", verdict="verified", reason="ok", before=[F("R1")], after=[],
                   fixed=["R1"], original="a\n", fixed_file="b\n", deferred=[F("D1")])
    md = report.summary_markdown([r], "openai/gpt-oss-120b", ["checkov"], {"a.tf": 1})
    assert report.MARKER in md and "✅ verified" in md and "Needs a human decision" in md
    assert "Commit suggestion" in md and SECRET not in md
    assert json.dumps(report.to_json([r]))


def test_report_when_no_iac_files():
    assert "No Terraform or Kubernetes files changed" in report.summary_markdown([], "m", ["checkov"])


class FakeGitHub:
    instances = []

    old_comments = []

    def __init__(self, repo, token):
        self.reviews, self.comments, self.deleted = [], [], []
        FakeGitHub.instances.append(self)

    def pr_files(self, number):
        patch = "@@ -0,0 +1,6 @@\n" + "".join("+" + l + "\n" for l in HEAD.splitlines())
        return [{"filename": "k8s/pod.yaml", "status": "added", "patch": patch},
                {"filename": "README.md", "status": "modified", "patch": ""}]

    def file_at(self, path, ref):
        return HEAD if ref == "headsha" else None

    def review_comments(self, number):
        return FakeGitHub.old_comments

    def delete_review_comment(self, cid):
        self.deleted.append(cid)

    def create_review(self, number, commit_id, body, comments):
        self.reviews.append((commit_id, comments))

    def upsert_comment(self, number, marker, body):
        self.comments.append(body)
        return "https://example/comment"


HEAD = "apiVersion: v1\nkind: Pod\nmetadata:\n  name: web\nspec:\n  hostNetwork: true\n"


def _pr_flow(tmp_path, monkeypatch, expect_deleted=()):
    import easebot.github as ghmod
    from conftest import FakeScanner

    event = tmp_path / "event.json"
    event.write_text(json.dumps({"pull_request": {"number": 7, "head": {"sha": "headsha"},
                                                  "base": {"sha": "basesha"}}}))
    for k, v in {"GITHUB_EVENT_PATH": str(event), "GITHUB_TOKEN": "t", "GITHUB_REPOSITORY": "o/r",
                 "GITHUB_WORKSPACE": str(tmp_path), "GITHUB_STEP_SUMMARY": str(tmp_path / "sum.md"),
                 "GITHUB_OUTPUT": str(tmp_path / "out.txt"), "GROQ_API_KEY": SECRET}.items():
        monkeypatch.setenv(k, v)
    monkeypatch.setattr(ghmod, "GitHub", FakeGitHub)
    fake = FakeScanner({"hostNetwork: true": "CKV_K8S_19"})
    monkeypatch.setattr("easebot.repair.default_scan", fake)
    monkeypatch.setattr(cli, "available_scanners", lambda req: ["checkov"])
    import easebot.repair as rp
    orig = rp.repair_file
    monkeypatch.setattr(cli, "repair_file", lambda *a, **k: orig(*a, scan=fake, **{**k, "use_tools": False}))

    code = cli.main(["pr", "--llm", "mock", "--fail-on", "findings"])
    gh = FakeGitHub.instances[-1]
    assert code == 0
    (commit, comments), = gh.reviews
    assert commit == "headsha" and comments[0]["path"] == "k8s/pod.yaml" and comments[0]["line"] == 6
    assert "```suggestion\n  hostNetwork: false\n```" in comments[0]["body"]
    assert "✅ verified" in gh.comments[0] and SECRET not in gh.comments[0]
    assert "| all |" in gh.comments[0]  # every finding is new because the file was added
    assert "verified=1" in (tmp_path / "out.txt").read_text()
    assert report.MARKER not in (tmp_path / "sum.md").read_text()
    assert gh.deleted == list(expect_deleted)


def test_pr_flow_posts_suggestion_and_summary(tmp_path, monkeypatch):
    _pr_flow(tmp_path, monkeypatch)


def test_pr_rerun_replaces_old_bot_suggestions(tmp_path, monkeypatch):
    FakeGitHub.old_comments = [
        {"id": 1, "path": "k8s/pod.yaml", "line": 3, "body": "**EASE-Bot** stale", "user": {"type": "Bot"}},
        {"id": 2, "path": "k8s/pod.yaml", "line": 3, "body": "**EASE-Bot** by a human", "user": {"type": "User"}},
    ]
    try:
        _pr_flow(tmp_path, monkeypatch, expect_deleted=[1])
    finally:
        FakeGitHub.old_comments = []


@pytest.mark.integration
@pytest.mark.skipif(not shutil.which("checkov") and not __import__("easebot.scanners").scanners._bin("checkov"),
                    reason="checkov not installed")
def test_cli_scan_demo_offline_with_real_checkov(tmp_path):
    demo = tmp_path / "demo"
    shutil.copytree("demo", demo)
    out = tmp_path / "r.json"
    code = cli.main(["scan", str(demo), "--llm", "mock", "--scanners", "checkov", "--no-tool-validate",
                     "--json", str(out), "--markdown", str(tmp_path / "r.md"), "--write"])
    assert code == 0
    res = {pathlib_name(r["path"]): r for r in json.loads(out.read_text())}
    assert res["deployment.yaml"]["verdict"] in ("partial", "verified")
    assert "CKV_K8S_16" in res["deployment.yaml"]["fixed"]
    assert "CKV_AWS_20" in res["storage.tf"]["fixed"]
    assert "privileged: false" in (demo / "k8s" / "deployment.yaml").read_text()


def pathlib_name(p):
    import pathlib
    return pathlib.Path(p).name
