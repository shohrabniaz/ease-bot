"""Minimal GitHub REST client for the pull-request flow. Uses the workflow's GITHUB_TOKEN."""
from __future__ import annotations

import os
import urllib.parse

import requests

API = os.environ.get("GITHUB_API_URL", "https://api.github.com")


class GitHub:
    def __init__(self, repo: str, token: str):
        self.repo = repo
        self.s = requests.Session()
        self.s.headers.update({"Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json",
                               "X-GitHub-Api-Version": "2022-11-28", "User-Agent": "ease-bot"})

    def _url(self, path: str) -> str:
        return f"{API}/repos/{self.repo}{path}"

    def _get_all(self, path: str) -> list:
        out, url = [], self._url(path)
        params = {"per_page": 100}
        while url:
            r = self.s.get(url, params=params, timeout=60)
            r.raise_for_status()
            out.extend(r.json())
            url, params = r.links.get("next", {}).get("url"), None
        return out

    def pr_files(self, number: int) -> list[dict]:
        return self._get_all(f"/pulls/{number}/files")

    def file_at(self, path: str, ref: str) -> str | None:
        r = self.s.get(self._url(f"/contents/{urllib.parse.quote(path)}"), params={"ref": ref}, timeout=60,
                       headers={"Accept": "application/vnd.github.raw+json"})
        if r.status_code == 404:
            return None
        r.raise_for_status()
        return r.text

    def review_comments(self, number: int) -> list[dict]:
        return self._get_all(f"/pulls/{number}/comments")

    def create_review(self, number: int, commit_id: str, body: str, comments: list[dict]) -> dict:
        r = self.s.post(self._url(f"/pulls/{number}/reviews"), timeout=60,
                        json={"commit_id": commit_id, "body": body, "event": "COMMENT", "comments": comments})
        if r.status_code >= 400:
            raise RuntimeError(f"create review failed: HTTP {r.status_code} {r.text[:300]}")
        return r.json()

    def upsert_comment(self, number: int, marker: str, body: str) -> str:
        for c in self._get_all(f"/issues/{number}/comments"):
            if marker in (c.get("body") or ""):
                r = self.s.patch(self._url(f"/issues/comments/{c['id']}"), json={"body": body}, timeout=60)
                r.raise_for_status()
                return r.json()["html_url"]
        r = self.s.post(self._url(f"/issues/{number}/comments"), json={"body": body}, timeout=60)
        r.raise_for_status()
        return r.json()["html_url"]
