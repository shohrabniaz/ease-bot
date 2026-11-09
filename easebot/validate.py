"""Validity and intent-preservation checks applied to every LLM candidate fix.

A scanner-clean file is not automatically a good fix (the EASE study found fixes that pass the
scanner but no longer parse, or that silently rename/delete resources). So each candidate must:
  1. parse (YAML for Kubernetes; `terraform validate` for Terraform when available), and
  2. keep every resource the original declared (no renames, deletions or image swaps).
"""
from __future__ import annotations

import os
import pathlib
import re
import shutil
import subprocess
import tempfile

import yaml

TF_BLOCK = re.compile(r'^\s*(resource|data)\s+"([^"]+)"\s+"([^"]+)"', re.M)
TF_MODULE = re.compile(r'^\s*module\s+"([^"]+)"', re.M)


def tf_identities(content: str) -> set[str]:
    ids = {f"{'data.' if k == 'data' else ''}{t}.{n}" for k, t, n in TF_BLOCK.findall(content)}
    ids |= {f"module.{m}" for m in TF_MODULE.findall(content)}
    return ids


def tf_blocks(content: str) -> dict[str, dict[str, int]]:
    """Nested block counts per resource (e.g. how many `ingress` blocks a security group has).
    Uses the HCL parser that ships with Checkov; returns {} if it is not installed."""
    try:
        import hcl2  # provided by checkov's bc-python-hcl2
    except ImportError:
        return {}
    import io
    data = hcl2.load(io.StringIO(content))
    out = {}
    for item in data.get("resource", []):
        for rtype, named in item.items():
            for name, body in named.items():
                counts = {}
                for k, v in body.items():
                    if k.startswith("__") or not isinstance(v, list):
                        continue
                    if v and all(isinstance(x, dict) for x in v):
                        counts[k] = len(v)
                out[f"{rtype}.{name}"] = counts
    return out


def k8s_docs(content: str):
    return [d for d in yaml.safe_load_all(content) if d]


def _containers(doc: dict):
    spec = doc.get("spec") or {}
    if isinstance(spec.get("template"), dict):  # Deployment, StatefulSet, Job, ...
        spec = spec["template"].get("spec") or {}
    if isinstance(spec.get("jobTemplate"), dict):  # CronJob
        spec = ((spec["jobTemplate"].get("spec") or {}).get("template") or {}).get("spec") or {}
    for key in ("initContainers", "containers"):
        for c in spec.get(key) or []:
            if isinstance(c, dict):
                yield c


def k8s_identities(content: str) -> set[str]:
    ids = set()
    for d in k8s_docs(content):
        if not isinstance(d, dict):
            continue
        name = (d.get("metadata") or {}).get("name", "")
        ids.add(f"{d.get('kind')}/{name}")
        for c in _containers(d):
            ids.add(f"{d.get('kind')}/{name}/container:{c.get('name')}={c.get('image')}")
            for p in c.get("ports") or []:
                if isinstance(p, dict):
                    ids.add(f"{d.get('kind')}/{name}/container:{c.get('name')}/port:{p.get('containerPort')}")
        if d.get("kind") == "Service":
            for p in (d.get("spec") or {}).get("ports") or []:
                if isinstance(p, dict):
                    ids.add(f"Service/{name}/port:{p.get('port')}")
    return ids


def identities(content: str, kind: str) -> set[str]:
    return tf_identities(content) if kind == "terraform" else k8s_identities(content)


def intent_check(original: str, fixed: str, kind: str) -> tuple[bool, str, list[str]]:
    """Return (ok, message, added). Removing/renaming anything is a hard fail; additions are reported."""
    try:
        before, after = identities(original, kind), identities(fixed, kind)
    except Exception as e:  # unparsable candidate
        return False, f"could not read resources: {e}", []
    missing = sorted(before - after)
    added = sorted(after - before)
    if missing:
        return False, "fix removed or renamed: " + ", ".join(missing), added
    if kind == "terraform":
        try:
            b0, b1 = tf_blocks(original), tf_blocks(fixed)
        except Exception as e:
            return False, f"could not parse Terraform: {str(e)[:120]}", added
        dropped = [f"{blk} block(s) from {addr}" for addr, counts in b0.items()
                   for blk, n in counts.items() if b1.get(addr, {}).get(blk, 0) < n]
        if dropped:
            return False, ("fix deleted " + ", ".join(dropped) +
                           " (that changes behaviour; restrict it instead of removing it)"), added
    return True, "all original resources kept" + (f"; added {', '.join(added)}" if added else ""), added


def _kubeconform(kc: str, content: str) -> tuple[bool, str]:
    import json
    with tempfile.TemporaryDirectory(prefix="easebot-k8s-") as d:
        p = pathlib.Path(d, "manifest.yaml")
        p.write_text(content)
        r = subprocess.run([kc, "-strict", "-ignore-missing-schemas", "-summary", "-output", "json", str(p)],
                           capture_output=True, text=True, timeout=180)
    if r.returncode == 0:
        return True, "valid"
    try:
        errs = []
        for res in json.loads(r.stdout).get("resources", []):
            for e in res.get("validationErrors") or [{"path": "", "msg": res.get("msg", "")}]:
                errs.append(f"{res.get('kind')}/{res.get('name')} {e.get('path')}: {e.get('msg')}")
        return False, "; ".join(errs)[:400]
    except Exception:
        return False, (r.stdout + r.stderr)[-300:]


def _tf_validate(dirpath: str, tf: str) -> tuple[bool, str]:
    env = dict(os.environ, TF_IN_AUTOMATION="1", CHECKPOINT_DISABLE="1")
    i = subprocess.run([tf, "init", "-backend=false", "-input=false", "-no-color"], cwd=dirpath,
                       capture_output=True, text=True, timeout=600, env=env)
    if i.returncode:
        return False, "terraform init failed: " + (i.stderr or i.stdout)[-400:].strip()
    v = subprocess.run([tf, "validate", "-no-color"], cwd=dirpath, capture_output=True, text=True,
                       timeout=300, env=env)
    return v.returncode == 0, (v.stdout + v.stderr).strip()[-400:]


def syntax_check(content: str, kind: str, filename: str = "main.tf", context_dir: str | None = None,
                 use_tools: bool = True, original: str | None = None) -> tuple[bool | None, str]:
    """Return (ok, message). ok=None means 'could not be checked' (never counted as a pass)."""
    if kind == "kubernetes":
        try:
            docs = k8s_docs(content)
        except Exception as e:
            return False, f"YAML error: {str(e)[:200]}"
        ok = bool(docs) and all(isinstance(d, dict) and d.get("kind") and d.get("apiVersion") for d in docs)
        if not ok:
            return False, "not a Kubernetes manifest"
        kc = shutil.which("kubeconform") if use_tools else None
        if not kc:
            return None, "YAML parses (kubeconform not installed: schema not checked)"
        ok, msg = _kubeconform(kc, content)
        if ok:
            return True, "kubeconform -strict: valid against the Kubernetes schema"
        if original is not None and not _kubeconform(kc, original)[0]:
            return None, "schema check skipped: original manifest does not pass kubeconform either"
        return False, "kubeconform -strict failed: " + msg
    tf = shutil.which("terraform") if use_tools else None
    if not tf:
        balanced = content.count("{") == content.count("}") and content.count('"') % 2 == 0
        return (None if balanced else False), ("terraform not installed: only brace balance checked"
                                               if balanced else "unbalanced braces/quotes")
    name = pathlib.Path(filename).name

    def run(text: str):
        with tempfile.TemporaryDirectory(prefix="easebot-tf-") as d:
            if context_dir and os.path.isdir(context_dir):
                for f in os.listdir(context_dir):
                    if f.endswith(".tf") and f != name:
                        shutil.copy(os.path.join(context_dir, f), d)
            pathlib.Path(d, name).write_text(text)
            return _tf_validate(d, tf)

    ok, msg = run(content)
    if ok:
        return True, "terraform validate: OK"
    if original is not None:
        base_ok, _ = run(original)
        if not base_ok:
            # The PR's own file does not validate in isolation (e.g. remote modules); don't blame the fix.
            return None, "terraform validate skipped: original file does not validate in isolation either"
    return False, "terraform validate failed: " + msg
