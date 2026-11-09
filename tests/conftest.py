import pytest

from easebot.scanners import Finding


def F(rule, resource="r", scanner="checkov", title=None):
    return Finding(scanner, rule, title or f"title {rule}", resource, 1, None)


class FakeScanner:
    """Findings are driven by marker words in the file text, e.g. 'BAD1' -> rule R1."""

    def __init__(self, rules=None):
        self.rules = rules or {"BAD1": "R1", "BAD2": "R2", "BAD3": "R3", "NEWBAD": "RNEW", "DEFER": "DEFERRED_1"}

    def __call__(self, content, kind, scanners, path):
        return [F(rule) for word, rule in self.rules.items() if word in content]


class ScriptedLLM:
    """Returns pre-baked replies in order and records prompts."""

    def __init__(self, *files):
        self.files = list(files)
        self.prompts = []

    def __call__(self, prompt):
        self.prompts.append(prompt)
        f = self.files.pop(0)
        if isinstance(f, Exception):
            raise f
        return f"NOTES:\n- R1: fixed it\nFIXED_FILE:\n```yaml\n{f}```\n"


@pytest.fixture
def fake_scan():
    return FakeScanner()
