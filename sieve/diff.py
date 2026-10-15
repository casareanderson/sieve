"""What changed since last time: `--new` on a scan, and `sieve diff OLD.json NEW.json`.

A daily cron job that prints 1,200 findings every morning gets ignored. With --new, sieve keeps the previous run's
findings (a small JSON file next to the cache, one per scan scope) and shows only what is new since then, plus what
has gone (fixed, or the package was removed). The exit code then follows the new findings only, so a box with an old
known-exploited CVE you have already seen stays quiet until something else turns up.

A finding is the same finding while its target, package and advisory id match: a version bump that is still
vulnerable is not "new". A scan with errors or a partial target keeps the old baseline and reports nothing as fixed,
because a missing finding there may only mean sieve could not look.
"""
import hashlib
import json
import os

KEEP = ("id", "package", "target", "installed", "fixed", "severity", "kev", "malicious")


def key(f):
    return (f["target"], f["package"], f["id"])


def scope(args):
    """A stable id for what this command scans, so `host` and `path ~/a` keep separate baselines."""
    parts = [args.cmd, os.path.abspath(getattr(args, "root", None) or "/"), getattr(args, "dest", None) or "",
             *sorted(os.path.abspath(x) for x in (getattr(args, "dirs", None) or [])),
             *sorted(os.path.abspath(x) for x in (getattr(args, "files", None) or [])),
             *sorted(getattr(args, "hosts", None) or []),
             "kernel" if getattr(args, "kernel", False) else ""]
    return hashlib.sha256("\0".join(parts).encode()).hexdigest()[:12]


def state_path(args):
    if getattr(args, "baseline", None):
        return args.baseline
    return os.path.join(os.path.dirname(os.path.abspath(args.cache)), f"last-{args.cmd}-{scope(args)}.json")


def load(path):
    """The saved baseline, or None when there is none (or it can't be read)."""
    try:
        with open(path) as fh:
            d = json.load(fh)
    except (OSError, ValueError):
        return None
    if not isinstance(d, dict) or not isinstance(d.get("findings"), list):
        return None
    return d


def save(path, findings, generated, version):
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w") as fh:
        json.dump({"sieve": version, "generated": generated,
                   "findings": [{k: f.get(k) for k in KEEP} for f in findings]}, fh, indent=1)
    os.replace(tmp, path)


def compare(old, new):
    """old, new: lists of findings → (new findings, gone findings). Order of `new` is kept."""
    before = {key(f) for f in old}
    now = {key(f) for f in new}
    return [f for f in new if key(f) not in before], [f for f in old if key(f) not in now]


def report_findings(path):
    """Findings from a saved `sieve ... --json` report (or a --new baseline file)."""
    with open(path) as fh:
        d = json.load(fh)
    if not isinstance(d, dict) or not isinstance(d.get("findings"), list):
        raise ValueError(f"{path}: not a sieve --json report")
    return d.get("generated"), d["findings"]
