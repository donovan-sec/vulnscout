"""
Cross-session memory.

A single JSON file at ~/.vulnscout/memory.json that remembers, per target:
- which commit / source we last scanned
- fingerprints of confirmed findings

This lets the hunt loop skip targets that haven't changed since the last scan
and avoid re-reporting the same vulnerability across runs. Greppable, no deps.

Schema:
{
  "version": 1,
  "targets": {
    "<target-key>": {
      "last_scanned": "ISO8601",
      "last_commit": "abc123" | null,
      "finding_fingerprints": ["sha1...", ...],
      "scan_count": int
    }
  }
}
"""

import json
import hashlib
import os
from datetime import datetime
from pathlib import Path

MEMORY_DIR = Path(os.path.expanduser("~/.vulnscout"))
MEMORY_FILE = MEMORY_DIR / "memory.json"
SCHEMA_VERSION = 1


def _load():
    if not MEMORY_FILE.exists():
        return {"version": SCHEMA_VERSION, "targets": {}}
    try:
        with open(MEMORY_FILE) as fh:
            data = json.load(fh)
        data.setdefault("version", SCHEMA_VERSION)
        data.setdefault("targets", {})
        return data
    except (json.JSONDecodeError, OSError):
        # Corrupt memory shouldn't break a scan -- start fresh in-memory.
        return {"version": SCHEMA_VERSION, "targets": {}}


def _save(data):
    MEMORY_DIR.mkdir(parents=True, exist_ok=True)
    tmp = MEMORY_FILE.with_suffix(".json.tmp")
    with open(tmp, "w") as fh:
        json.dump(data, fh, indent=2)
    tmp.replace(MEMORY_FILE)  # atomic


def _key(target):
    """Normalize a target (URL or repo) into a stable key."""
    return (target.rstrip("/")
            .replace("https://", "")
            .replace("http://", "")
            .replace("git@", "")
            .lower())


def fingerprint_finding(finding):
    """
    Stable fingerprint of a finding so the same bug across runs collapses to one
    id. Based on the PoC/test + the first line of analysis (the title), which
    stay stable even when Claude's prose around them varies.
    """
    poc = finding.get("poc") or finding.get("test_request") or ""
    title = ""
    for line in finding.get("analysis", "").splitlines():
        s = line.strip().lstrip("#").strip()
        if s and len(s) > 8:
            title = s
            break
    basis = (title + "::" + poc).strip().lower()
    return hashlib.sha1(basis.encode("utf-8", errors="ignore")).hexdigest()


def get_target_record(target):
    data = _load()
    return data["targets"].get(_key(target))


def should_skip(target, current_commit=None):
    """
    True if this target was already scanned at the same commit. If we have no
    commit info (webapp, or commit unknown), we never skip on this basis --
    web targets change without a commit hash.
    """
    record = get_target_record(target)
    if not record:
        return False
    if current_commit and record.get("last_commit") == current_commit:
        return True
    return False


def known_fingerprints(target):
    record = get_target_record(target)
    return set(record.get("finding_fingerprints", [])) if record else set()


def filter_new_findings(target, findings):
    """
    Split findings into (new, already_known) based on stored fingerprints.
    Does NOT mutate memory -- call record_scan() to persist.
    """
    known = known_fingerprints(target)
    new, seen = [], []
    for f in findings:
        fp = fingerprint_finding(f)
        f["_fingerprint"] = fp
        (seen if fp in known else new).append(f)
    return new, seen


def record_scan(target, findings, current_commit=None):
    """Persist this scan: update commit, merge finding fingerprints, bump count."""
    data = _load()
    key = _key(target)
    record = data["targets"].get(key, {
        "last_scanned": None,
        "last_commit": None,
        "finding_fingerprints": [],
        "scan_count": 0,
    })

    fps = set(record.get("finding_fingerprints", []))
    for f in findings:
        fps.add(f.get("_fingerprint") or fingerprint_finding(f))

    record["last_scanned"] = datetime.now().isoformat()
    record["last_commit"] = current_commit or record.get("last_commit")
    record["finding_fingerprints"] = sorted(fps)
    record["scan_count"] = record.get("scan_count", 0) + 1

    data["targets"][key] = record
    _save(data)
    return record


def get_commit(repo_path):
    """Best-effort HEAD commit of a cloned repo. None on any failure."""
    import subprocess
    try:
        out = subprocess.run(
            ["git", "-C", str(repo_path), "rev-parse", "HEAD"],
            capture_output=True, text=True, timeout=10,
        )
        return out.stdout.strip() or None if out.returncode == 0 else None
    except Exception:
        return None
