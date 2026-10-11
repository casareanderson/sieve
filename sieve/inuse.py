"""Is the vulnerable code actually loaded? Three honest answers per finding.

  loaded       a file of that package is mapped into a running process right now (/proc/<pid>/maps)
  not loaded   every process was read, the package ships native code (a shared library or an ELF executable),
               and none of it is mapped
  unknown      anything else: not every process could be read (run as root), the package is scripts or a
               pure-Python module (they run inside an interpreter's mapping, so maps can't show them), or it is a
               Go, Rust or npm package (not tracked yet)

`restart` is set when the running copy was replaced on disk by an upgrade: the fix is installed, but the process
is still executing the old, vulnerable code until it restarts.
"""
LOADED, NOT_LOADED, UNKNOWN = "loaded", "not loaded", "unknown"
ORDER = {LOADED: 0, UNKNOWN: 1, NOT_LOADED: 2}
OTHER_ECOS = ("npm", "Go", "crates.io")


def complete(rep):
    return bool(rep) and rep["total"] > 0 and rep["seen"] == rep["total"] and not rep.get("main_only")


def state(rep, kind, name):
    """→ (state, restart) for one package. kind: 'os' or 'py' (anything else is unknown)."""
    if not rep or kind not in ("os", "py"):
        return UNKNOWN, False
    key = f"{kind}:{name}"
    if key in rep["loaded"]:
        return LOADED, bool(rep["loaded"][key])
    if kind == "os" and complete(rep) and name in set(rep["native"]):
        return NOT_LOADED, False
    return UNKNOWN, False


def annotate(findings, target):
    """Set in_use / restart_needed on this target's findings, using target.pkgs (before it is freed) to know which
    report names are OS packages and which are Python packages."""
    kinds = {}
    for e, _, _, rn, _ in target.pkgs:
        kinds.setdefault(rn, "py" if e == "PyPI" else "other" if e in OTHER_ECOS else "os")
    for f in findings:
        f["in_use"], f["restart_needed"] = state(target.inuse, kinds.get(f["package"], "other"), f["package"])


def coverage_note(rep):
    """A target note saying how much of the picture the in-use column is based on, or None when it saw everything."""
    if not rep:
        return None
    if rep.get("main_only"):
        return "in-use: only the container's main process could be read"
    if rep["seen"] < rep["total"]:
        return (f"in-use: read {rep['seen']} of {rep['total']} processes; run as root for the full picture "
                "(until then nothing is reported as not loaded)")
    return None
