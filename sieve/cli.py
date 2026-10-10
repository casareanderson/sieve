"""sieve command line."""
import argparse
import json
import os
import sys
from datetime import datetime, timezone

from . import __version__, intel, osv, rank, sources

EXIT_OK, EXIT_KEV, EXIT_ERROR = 0, 1, 2


def default_cache():
    base = os.environ.get("XDG_CACHE_HOME") or os.path.join(os.path.expanduser("~"), ".cache")
    return os.path.join(base, "sieve", "sieve.db")


def parser():
    p = argparse.ArgumentParser(
        prog="sieve",
        description="Find the CVEs that matter on a Linux box and its running containers, using OSV.dev, "
                    "CISA KEV and EPSS.")
    p.add_argument("--version", action="version", version=f"sieve {__version__}")
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--json", action="store_true", help="machine-readable output")
    common.add_argument("--min-severity", choices=["low", "medium", "high", "critical"], type=str.lower,
                        help="hide findings below this severity (known-exploited findings are always shown)")
    common.add_argument("--kev-only", action="store_true", help="only known-exploited findings (CISA KEV)")
    common.add_argument("--fixable-only", action="store_true", help="only findings with a fixed version")
    common.add_argument("--cache", default=default_cache(), metavar="PATH",
                        help="advisory cache (default: %(default)s); KEV and EPSS files sit next to it")
    common.add_argument("--no-epss", action="store_true", help="do not download or use EPSS scores")
    common.add_argument("--kernel", action="store_true",
                        help="also check kernel packages (linux-image, linux-libc-dev, ...); skipped by default")
    common.add_argument("--limit", type=int, default=50, metavar="N",
                        help="table rows to print (default 50, 0 = all); the summary always counts everything")
    sub = p.add_subparsers(dest="cmd", required=True, metavar="{host,containers,all,collector}")
    sub.add_parser("host", parents=[common], help="scan this machine's OS and Python packages")
    c = sub.add_parser("containers", parents=[common], help="scan every running Docker container (needs root)")
    c.add_argument("--from-tar", metavar="FILE",
                   help="read a tar written by `sieve collector` on another machine ('-' = stdin) instead")
    sub.add_parser("all", parents=[common], help="host + containers")
    sub.add_parser("collector", help="print the standalone collector script (pipe it to `python3 -` elsewhere)")
    return p


def scan(args, warn):
    """→ (targets, findings, errors)."""
    client = osv.OSV(args.cache)
    targets, findings, errors = [], [], []
    kev = intel.kev_set(os.path.dirname(os.path.abspath(args.cache)))

    def run(t):
        before = client.failed
        try:
            if t.pkgs:
                findings.extend(osv.match(client, t.pkgs, kev, target=t.name))
        except Exception as e:  # noqa: BLE001 — one unreadable target must not stop the rest
            t.status = "error"
            t.notes.append(f"OSV query failed: {type(e).__name__}: {str(e)[:160]}")
        lost = client.failed - before
        if lost and t.status == "ok":
            t.status = "partial"
            t.notes.append(f"{lost} advisories could not be fetched from OSV; counts may be low")
        t.pkgs = []                                     # free the list once matched
        targets.append(t)

    if args.cmd in ("host", "all"):
        run(sources.host(kernel=args.kernel))
    if args.cmd in ("containers", "all"):
        proc = None
        try:
            if getattr(args, "from_tar", None):
                stream = sys.stdin.buffer if args.from_tar == "-" else open(args.from_tar, "rb")
            else:
                proc, stream = sources.run_collector()
            errs = []
            for t in sources.read_collected(stream, errs, kernel=args.kernel):
                run(t)
            errors += [f"collector: {e}" for e in errs]
            if proc:
                rc = proc.wait()
                if rc:
                    tail = proc.stderr.read().decode("utf-8", "replace").strip()[-300:]
                    errors.append(f"collector exited {rc}: {tail}")
        except Exception as e:  # noqa: BLE001
            errors.append(f"containers: {e}")
        if args.cmd == "containers" and not targets and not errors:
            warn("no running containers found")
    if not args.no_epss and findings:
        scores = intel.epss_scores(os.path.dirname(os.path.abspath(args.cache)),
                                   {f["id"] for f in findings if f["id"].startswith("CVE-")})
        for f in findings:
            e = scores.get(f["id"])
            f["epss"], f["epss_percentile"] = e if e else (None, None)
    else:
        for f in findings:
            f["epss"] = f["epss_percentile"] = None
    return targets, findings, errors


def _cut(s, n):
    s = str(s)
    return s if len(s) <= n else s[:n - 1] + "…"


def table(findings, limit):
    rows = [("KEV", "EPSS", "SEVERITY", "ID", "PACKAGE", "INSTALLED → FIXED", "TARGET")]
    shown = findings if not limit else findings[:limit]
    for f in shown:
        epss = f"{f['epss'] * 100:.1f}%" if f.get("epss") is not None else "-"
        fix = f["fixed"] or ("no fix" if f["status"] in ("affected", "fixed") else f["status"])
        rows.append(("⚠" if f["kev"] else "", epss, f["severity"], f["id"], _cut(f["package"], 28),
                     f"{_cut(f['installed'], 26)} → {_cut(fix, 26)}", _cut(f["target"], 32)))
    w = [max(len(r[i]) for r in rows) for i in range(len(rows[0]))]
    lines = ["  ".join(c.ljust(w[i]) for i, c in enumerate(r)).rstrip() for r in rows]
    if limit and len(findings) > limit:
        lines.append(f"… {len(findings) - limit} more (use --limit 0 to show all, or --json)")
    return "\n".join(lines)


def main(argv=None):
    args = parser().parse_args(argv)
    if args.cmd == "collector":
        sys.stdout.write(sources.collector_source())
        return EXIT_OK

    def warn(m):
        print(f"sieve: {m}", file=sys.stderr)
    targets, findings, errors = scan(args, warn)
    total = len(findings)
    findings = rank.rank(rank.apply_filters(findings, args.min_severity, args.kev_only, args.fixable_only))
    s = rank.summary(findings)
    if args.json:
        json.dump({"sieve": __version__, "generated": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                   "targets": [t.as_dict() for t in targets], "errors": errors,
                   "summary": dict(s, unfiltered=total), "findings": findings}, sys.stdout, indent=1)
        sys.stdout.write("\n")
    else:
        for t in targets:
            note = f"  ({'; '.join(t.notes)})" if t.notes else ""
            flag = "" if t.status == "ok" else f" [{t.status}]"
            print(f"# {t.name}: {t.os}, {t.packages} packages{flag}{note}")
        if findings:
            print()
            print(table(findings, args.limit))
        print()
        hidden = f" ({total - len(findings)} hidden by filters)" if total != len(findings) else ""
        print(f"{s['findings']} findings, {s['kev']} actively exploited, {s['fixable']} fixable{hidden}")
    for e in errors:
        warn(e)
    if s["kev"]:
        return EXIT_KEV
    if errors or any(t.status == "error" for t in targets):
        return EXIT_ERROR
    return EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
