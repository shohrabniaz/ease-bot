import json

import pytest

from easebot import llm


def test_parse_fenced_reply():
    r = llm.parse_reply("NOTES:\n- CKV_1: did x\n- CKV_2: did y\nFIXED_FILE:\n```hcl\na = 1\n```")
    assert r["fixed_file"] == "a = 1\n"
    assert [n["rule_id"] for n in r["notes"]] == ["CKV_1", "CKV_2"]


def test_parse_reply_tolerates_missing_closing_fence():
    r = llm.parse_reply("NOTES:\nFIXED_FILE:\n```yaml\nkind: Pod\n")
    assert r["fixed_file"].strip() == "kind: Pod"


def test_parse_reply_keeps_inner_backticks():
    r = llm.parse_reply("FIXED_FILE:\n````\n# ```not a fence```\nx: 1\n````")
    assert "```not a fence```" in r["fixed_file"]


def test_parse_json_reply():
    r = llm.parse_reply(json.dumps({"fixed_file": "x: 1\n", "notes": [{"rule_id": "A", "change": "b"}]}))
    assert r["fixed_file"] == "x: 1\n" and r["notes"][0]["rule_id"] == "A"


@pytest.mark.parametrize("bad", ["no sections here", "FIXED_FILE:\n```\n\n```"])
def test_parse_reply_rejects_garbage(bad):
    with pytest.raises(llm.LLMError):
        llm.parse_reply(bad)


def test_mock_llm_flips_known_values():
    out = llm.parse_reply(llm.MockLLM()(llm.PROMPT.format(kind="k", path="p", findings="", feedback="",
                                                           content="privileged: true\nacl = \"public-read\"\n")))
    assert "privileged: false" in out["fixed_file"] and '"private"' in out["fixed_file"]


def test_groq_requires_key(monkeypatch):
    monkeypatch.delenv("GROQ_API_KEY", raising=False)
    with pytest.raises(llm.LLMError, match="GROQ_API_KEY is not set"):
        llm.get_llm("groq")("hi")


class _Resp:
    def __init__(self, status, body=None, headers=None):
        self.status_code, self._body, self.headers = status, body or {}, headers or {}
        self.text = json.dumps(self._body)

    def json(self):
        return self._body


def test_groq_retries_429_and_never_leaks_key(monkeypatch):
    secret = "gsk_TEST_SECRET_VALUE"
    monkeypatch.setenv("GROQ_API_KEY", secret)
    monkeypatch.setattr(llm.time, "sleep", lambda s: None)
    calls = []

    def fake_post(url, json, timeout, headers):
        calls.append(headers)
        if len(calls) == 1:
            return _Resp(429, {"error": "slow down"}, {"retry-after": "1"})
        return _Resp(200, {"choices": [{"message": {"content": "ok"}}]})

    monkeypatch.setattr(llm.requests, "post", fake_post)
    assert llm.get_llm("groq")("prompt") == "ok"
    assert len(calls) == 2 and calls[0]["Authorization"] == f"Bearer {secret}"


def test_groq_error_message_has_no_key(monkeypatch):
    secret = "gsk_TEST_SECRET_VALUE"
    monkeypatch.setenv("GROQ_API_KEY", secret)
    monkeypatch.setattr(llm.requests, "post", lambda *a, **k: _Resp(401, {"error": "invalid api key"}))
    with pytest.raises(llm.LLMError) as e:
        llm.get_llm("groq")("prompt")
    assert secret not in str(e.value)


def test_unknown_provider():
    with pytest.raises(ValueError):
        llm.get_llm("nope")
