"""LLM providers. Groq (free tier, OpenAI-compatible) by default; `mock` for offline tests and demos.

The API key is read from the environment only and is never logged or written to reports.
"""
from __future__ import annotations

import json
import os
import re
import time

import requests

DEFAULT_MODEL = "openai/gpt-oss-120b"
DEFAULT_BASE_URL = "https://api.groq.com/openai/v1"

PROMPT = """You repair security misconfigurations in {kind} files found in a pull request.
File path: {path}
Scanner findings to fix:
{findings}

Rules:
- Return the FULL corrected file, not a diff.
- Change only what is needed to fix the findings. Keep formatting, comments and ordering.
- Never rename or delete resources, Kubernetes objects or containers. Never change images, ports,
  replicas, names, bucket names or variables unless a finding requires it.
- You may add new resources/blocks if that is the standard fix (e.g. a public access block).
- Never delete blocks such as ingress/egress rules or ports to silence a finding; restrict them instead.
  If the safe value is something only the user knows (e.g. an allowed CIDR), add a clearly named
  Terraform variable with a description and no default, and use it.
- Never invent values you cannot know (image digests, KMS key ARNs, AMI IDs, account IDs, IP ranges of
  the user's network). Never add unrelated resources (e.g. instances) just to satisfy a check.
- If a finding cannot be fixed safely without more context, leave it unfixed and say why in NOTES.
{feedback}Answer in exactly this format and nothing else:
NOTES:
- <rule_id>: <one short sentence about what you changed>
FIXED_FILE:
```
<the full corrected file>
```

File:
{content}"""


class LLMError(RuntimeError):
    pass


def _strip_fences(s: str) -> str:
    m = re.match(r"^\s*```[a-zA-Z]*\n(.*)\n```\s*$", s, re.S)
    return m.group(1) if m else s


FENCE = re.compile(r"^(`{3,})[^\n]*\n(.*?)\n\1[ \t]*$", re.S | re.M)


def parse_reply(text: str) -> dict:
    """Parse the NOTES/FIXED_FILE format (or a JSON object, for providers that prefer it)."""
    text = text.strip()
    if text.startswith("{"):
        try:
            out = json.loads(text)
            fixed = out.get("fixed_file")
            if isinstance(fixed, str) and fixed.strip():
                return {"fixed_file": _strip_fences(fixed),
                        "notes": [n for n in out.get("notes") or [] if isinstance(n, dict)]}
        except json.JSONDecodeError:
            pass
    head, sep, tail = text.partition("FIXED_FILE:")
    if not sep:
        raise LLMError("model reply has no FIXED_FILE section")
    m = FENCE.search(tail)
    if m:
        fixed = m.group(2)
    else:  # tolerate a missing closing fence or no fence at all
        body = tail.strip("\n")
        if body.lstrip().startswith("```"):
            body = body.lstrip().split("\n", 1)[1] if "\n" in body else ""
        fixed = body.rstrip().rstrip("`").rstrip()
    if not fixed.strip():
        raise LLMError("model returned an empty file")
    notes = []
    for line in head.splitlines():
        line = line.strip()
        if line.startswith("- "):
            rid, _, change = line[2:].partition(":")
            notes.append({"rule_id": rid.strip().strip("`"), "change": change.strip()})
    return {"fixed_file": fixed + "\n", "notes": notes}


class OpenAICompatLLM:
    """Works with Groq and any OpenAI-compatible chat endpoint."""

    def __init__(self, model: str | None = None, base_url: str | None = None, api_key_env: str = "GROQ_API_KEY",
                 retries: int = 4):
        self.model = model or os.environ.get("EASEBOT_MODEL") or DEFAULT_MODEL
        self.base_url = (base_url or os.environ.get("EASEBOT_BASE_URL") or DEFAULT_BASE_URL).rstrip("/")
        self.api_key_env = api_key_env
        self.retries = retries
        self.name = f"{self.model}"

    def __call__(self, prompt: str) -> str:
        key = os.environ.get(self.api_key_env)
        if not key:
            raise LLMError(f"{self.api_key_env} is not set")
        body = {"model": self.model, "temperature": 0,
                "messages": [{"role": "user", "content": prompt}]}
        last = None
        for attempt in range(self.retries):
            try:
                r = requests.post(f"{self.base_url}/chat/completions", json=body, timeout=180,
                                  headers={"Authorization": f"Bearer {key}"})
            except requests.RequestException as e:
                last = f"network error: {type(e).__name__}"
                time.sleep(2 ** attempt)
                continue
            if r.status_code == 429 or r.status_code >= 500:
                last = f"HTTP {r.status_code}"
                wait = float(r.headers.get("retry-after") or 2 ** (attempt + 1))
                time.sleep(min(wait, 30))
                continue
            if r.status_code >= 400:
                # Do not echo request headers; the body from the provider has no secrets.
                raise LLMError(f"HTTP {r.status_code}: {r.text[:200]}")
            return r.json()["choices"][0]["message"]["content"]
        raise LLMError(f"LLM unavailable after {self.retries} tries ({last})")


# Deterministic stand-in used for offline runs and tests. It is NOT a repair engine: it only
# flips a handful of well-known insecure values so the pipeline can be exercised without a key.
MOCK_RULES = [
    (r"(privileged:\s*)true", r"\1false", "set privileged to false"),
    (r"(allowPrivilegeEscalation:\s*)true", r"\1false", "disallow privilege escalation"),
    (r"(hostNetwork:\s*)true", r"\1false", "disable host networking"),
    (r"(hostPID:\s*)true", r"\1false", "disable host PID namespace"),
    (r'(acl\s*=\s*)"public-read(-write)?"', r'\1"private"', "make bucket ACL private"),
    (r"(encrypted\s*=\s*)false", r"\1true", "enable encryption"),
    (r'(cidr_blocks\s*=\s*\[)"0\.0\.0\.0/0"(\])', r'\1"10.0.0.0/8"\2', "restrict ingress CIDR"),
]


class MockLLM:
    name = "mock (offline)"

    def __call__(self, prompt: str) -> str:
        content = prompt.split("\nFile:\n", 1)[1]
        notes = []
        for pat, rep, why in MOCK_RULES:
            content, n = re.subn(pat, rep, content)
            if n:
                notes.append({"rule_id": "mock", "change": why})
        note_lines = "\n".join(f"- {n['rule_id']}: {n['change']}" for n in notes)
        return f"NOTES:\n{note_lines}\nFIXED_FILE:\n```\n{content.rstrip(chr(10))}\n```\n"


def get_llm(provider: str, model: str | None = None, base_url: str | None = None):
    if provider == "mock":
        return MockLLM()
    if provider in ("groq", "openai-compatible"):
        env = "GROQ_API_KEY" if provider == "groq" else "EASEBOT_API_KEY"
        return OpenAICompatLLM(model=model, base_url=base_url, api_key_env=env)
    raise ValueError(f"unknown LLM provider {provider!r}")
