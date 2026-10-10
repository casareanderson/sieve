"""Exploit intelligence: CISA KEV (already exploited) and FIRST EPSS (chance of exploitation in the next 30 days).

Both are public files, cached next to the advisory cache for 20 hours. A stale copy beats none, and a scan still
runs (unranked by that signal) if neither can be fetched.
"""
import gzip
import json
import os
import sys
import time

import requests

from .osv import UA

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
# KEV says "already exploited"; EPSS ranks the other 99%, and catches far more of what gets exploited than
# "CVSS >= 9" does (FIRST's own figures).
EPSS_URL = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz"
MAX_AGE = 20 * 3600


def _warn(msg):
    print(f"sieve: {msg}", file=sys.stderr)


def _fresh(path):
    return os.path.exists(path) and time.time() - os.path.getmtime(path) < MAX_AGE


def _save(path, data):
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    with open(path + ".tmp", "wb") as f:
        f.write(data)
    os.replace(path + ".tmp", path)


def load_kev(path):
    with open(path, encoding="utf-8") as f:
        return {v["cveID"] for v in json.load(f)["vulnerabilities"]}


def kev_set(cache_dir, session=None):
    """→ set of CVE ids in CISA's Known Exploited Vulnerabilities catalogue."""
    path = os.path.join(cache_dir, "kev.json")
    try:
        if not _fresh(path):
            r = (session or requests).get(KEV_URL, timeout=60, headers=UA)
            r.raise_for_status()
            json.loads(r.content)["vulnerabilities"]     # validate before replacing a good copy
            _save(path, r.content)
    except Exception as e:  # noqa: BLE001
        _warn(f"KEV refresh failed ({type(e).__name__}); using the cached copy if there is one")
    try:
        return load_kev(path)
    except Exception:  # noqa: BLE001
        _warn("no KEV data: known-exploited findings cannot be flagged")
        return set()


def load_epss(path, wanted):
    """EPSS csv.gz → {cve: (epss, percentile)} for the CVEs in `wanted` (the file has ~300k rows; keep only ours)."""
    out = {}
    with gzip.open(path, "rt") as f:
        for line in f:
            if line.startswith("CVE-"):
                c, e, p = line.rstrip().split(",")[:3]
                if c in wanted:
                    out[c] = (float(e), float(p))
    return out


def epss_scores(cache_dir, wanted, session=None):
    path = os.path.join(cache_dir, "epss.csv.gz")
    try:
        if not _fresh(path):
            r = (session or requests).get(EPSS_URL, timeout=120, headers=UA)
            r.raise_for_status()
            if b"cve,epss" not in gzip.decompress(r.content)[:400]:
                raise ValueError("not an EPSS file")
            _save(path, r.content)
    except Exception as e:  # noqa: BLE001
        _warn(f"EPSS refresh failed ({type(e).__name__}); using the cached copy if there is one")
    if not os.path.exists(path):
        return {}
    try:
        return load_epss(path, wanted)
    except Exception:  # noqa: BLE001
        _warn("EPSS cache unreadable; findings are not scored")
        return {}
