"""Scanner adapters (Checkov always, Trivy when installed). Each returns a list of Finding."""
from __future__ import annotations

import json
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass, asdict


@dataclass(frozen=True)
class Finding:
    scanner: str
    rule_id: str
    title: str
    resource: str
    line: int | None = None
    severity: str | None = None

    @property
    def key(self):
        # Line numbers move when a file is edited, so identity is scanner+rule+resource.
        return (self.scanner, self.rule_id, self.resource)

    def to_dict(self):
        return asdict(self)


def detect_kind(path: str, content: str = "") -> str | None:
    n = path.lower()
    if n.endswith(".tf"):
        return "terraform"
    if n.endswith((".yaml", ".yml")):
        # Only treat YAML as Kubernetes if it looks like a manifest.
        if "apiVersion" in content and "kind" in content:
            return "kubernetes"
        return None
    return None


def _bin(name: str) -> str | None:
    venv = pathlib.Path(sys.executable).parent / name
    if venv.exists():
        return str(venv)
    return shutil.which(name)


def _stage(content: str, kind: str, context_dir: str | None, filename: str) -> tempfile.TemporaryDirectory:
    """Write the file into a temp dir (with sibling .tf files for Terraform context)."""
    d = tempfile.TemporaryDirectory(prefix="easebot-")
    if context_dir and kind == "terraform" and os.path.isdir(context_dir):
        for f in os.listdir(context_dir):
            if f.endswith((".tf", ".tfvars")) and f != filename:
                shutil.copy(os.path.join(context_dir, f), d.name)
    pathlib.Path(d.name, filename).write_text(content)
    return d


def checkov_scan(content: str, kind: str, filename: str = "main") -> list[Finding]:
    exe = _bin("checkov")
    if not exe:
        raise RuntimeError("checkov is not installed")
    ext = ".tf" if kind == "terraform" else ".yaml"
    fname = pathlib.Path(filename).name
    if not fname.endswith(ext):
        fname += ext
    with _stage(content, kind, None, fname) as d:
        p = pathlib.Path(d, fname)
        r = subprocess.run([exe, "-f", str(p), "--framework", kind, "-o", "json", "--quiet", "--compact",
                            "--skip-download"], capture_output=True, text=True, timeout=300)
    out = r.stdout.strip()
    if not out:
        return []
    data = json.loads(out)
    if isinstance(data, list):
        data = data[0] if data else {}
    fails = (data.get("results") or {}).get("failed_checks", []) if isinstance(data, dict) else []
    res = []
    for f in fails:
        lr = f.get("file_line_range") or [None]
        res.append(Finding("checkov", f["check_id"], f.get("check_name", ""), f.get("resource", ""),
                           lr[0], f.get("severity")))
    return sorted(set(res), key=lambda x: (x.rule_id, x.resource))


def trivy_scan(content: str, kind: str, filename: str = "main") -> list[Finding]:
    exe = _bin("trivy")
    if not exe:
        raise RuntimeError("trivy is not installed")
    ext = ".tf" if kind == "terraform" else ".yaml"
    fname = pathlib.Path(filename).name
    if not fname.endswith(ext):
        fname += ext
    with _stage(content, kind, None, fname) as d:
        r = subprocess.run([exe, "config", "--quiet", "-f", "json", d], capture_output=True, text=True, timeout=300)
    if r.returncode != 0 or not r.stdout.strip():
        raise RuntimeError("trivy failed: " + r.stderr[-300:])
    data = json.loads(r.stdout)
    res = []
    for t in data.get("Results") or []:
        if t.get("Target") != fname:
            continue
        for m in t.get("Misconfigurations") or []:
            if m.get("Status") != "FAIL":
                continue
            cm = m.get("CauseMetadata") or {}
            res.append(Finding("trivy", m.get("ID") or m.get("AVDID") or "?", m.get("Title", ""),
                               cm.get("Resource") or "", cm.get("StartLine"), m.get("Severity")))
    return sorted(set(res), key=lambda x: (x.rule_id, x.resource))


SCANNERS = {"checkov": checkov_scan, "trivy": trivy_scan}


def available_scanners(requested: list[str]) -> list[str]:
    out = []
    for s in requested:
        if s in SCANNERS and _bin(s):
            out.append(s)
    return out


def scan(content: str, kind: str, scanners: list[str], filename: str = "main") -> list[Finding]:
    res: list[Finding] = []
    for s in scanners:
        res.extend(SCANNERS[s](content, kind, filename))
    return res
