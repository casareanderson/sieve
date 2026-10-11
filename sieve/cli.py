"""sieve command line."""
import argparse
import json
import os
import sys
from datetime import datetime, timezone

from . import __version__, inuse, intel, osv, projects, rank, sources

EXIT_OK, EXIT_KEV, EXIT_ERROR = 0, 1, 2          # 1 = known-exploited (KEV) or known-malicious in the output


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
    common.add_argument("--sarif", action="store_true",
                        help="SARIF 2.1.0 output, for GitHub code scanning (upload with codeql-action/upload-sarif)")
    common.add_argument("--min-severity", choices=["low", "medium", "high", "critical"], type=str.lower,
                        help="hide findings below this severity (known-exploited findings are always shown)")
    common.add_argument("--kev-only", action="store_true", help="only known-exploited findings (CISA KEV)")
    common.add_argument("--fixable-only", action="store_true", help="only findings with a fixed version")
    common.add_argument("--in-use-only", action="store_true",
                        help="only findings whose code is loaded in a running process right now")
    common.add_argument("--cache", default=default_cache(), metavar="PATH",
                        help="advisory cache (default: %(default)s); KEV and EPSS files sit next to it")
    common.add_argument("--no-epss", action="store_true", help="do not download or use EPSS scores")
    common.add_argument("--kernel", action="store_true",
                        help="also check kernel packages (linux-image, linux-libc-dev, ...); skipped by default")
    common.add_argument("--limit", type=int, default=50, metavar="N",
                        help="table rows to print (default 50, 0 = all); the summary always counts everything")
    sub = p.add_subparsers(dest="cmd", required=True, metavar="{host,containers,all,path,collector}")
    root = argparse.ArgumentParser(add_help=False)
    root.add_argument("--root", default="/", metavar="PATH",
                      help="read the host's packages from this directory instead of / (e.g. the host's / "
                           "mounted at /host inside a container)")
    sub.add_parser("host", parents=[common, root], help="scan this machine's OS and Python packages")
    c = sub.add_parser("containers", parents=[common], help="scan every running Docker container (needs root)")
    c.add_argument("--from-tar", metavar="FILE",
                   help="read a tar written by `sieve collector` on another machine ('-' = stdin) instead")
    sub.add_parser("all", parents=[common, root], help="host + containers")
    pa = sub.add_parser("path", parents=[common], help="scan project directories: npm/yarn/pnpm lockfiles, "
                        "node_modules, requirements*.txt, poetry.lock, uv.lock, virtualenvs")
    pa.add_argument("dirs", nargs="+", metavar="DIR")
    pa.add_argument("--depth", type=int, default=8, metavar="N", help="how deep to look under each DIR (default 8)")
    sub.add_parser("collector", help="print the standalone collector script (pipe it to `python3 -` elsewhere)")
    return p


def scan(args, warn):
    """→ (targets, findings, errors)."""
    client = osv.OSV(args.cache)
    targets, findings, errors = [], [], []
    kev = intel.kev_set(os.path.dirname(os.path.abspath(args.cache)))

    def run(t):
        before, start = client.failed, len(findings)
        try:
            if t.pkgs:
                findings.extend(osv.match(client, t.pkgs, kev, target=t.name))
                inuse.annotate(findings[start:], t)
        except Exception as e:  # noqa: BLE001 — one unreadable target must not stop the rest
            t.status = "error"
            t.notes.append(f"OSV query failed: {type(e).__name__}: {str(e)[:160]}")
        lost = client.failed - before
        if lost and t.status == "ok":
            t.status = "partial"
            t.notes.append(f"{lost} advisories could not be fetched from OSV; counts may be low")
        note = inuse.coverage_note(t.inuse)
        if note:
            t.notes.append(note)
        t.pkgs = []                                     # free the list once matched
        targets.append(t)

    if args.cmd in ("host", "all"):
        run(sources.host(root=args.root, kernel=args.kernel))
    if args.cmd == "path":
        for d in args.dirs:
            run(projects.scan_path(d, depth=args.depth))
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
    rows = [("ALERT", "EPSS", "SEVERITY", "IN USE", "ID", "PACKAGE", "INSTALLED → FIXED", "TARGET")]
    use = {inuse.LOADED: "yes", inuse.NOT_LOADED: "no", inuse.UNKNOWN: "?"}
    shown = findings if not limit else findings[:limit]
    for f in shown:
        epss = f"{f['epss'] * 100:.1f}%" if f.get("epss") is not None else "-"
        fix = f["fixed"] or ("no fix" if f["status"] in ("affected", "fixed") else f["status"])
        flag = "☠ MALWARE" if f.get("malicious") else "⚠" if f["kev"] else ""
        rows.append((flag, epss, f["severity"],
                     use.get(f.get("in_use"), "?") + (" ↻" if f.get("restart_needed") else ""), f["id"],
                     _cut(f["package"], 28),
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
    findings = rank.rank(rank.apply_filters(findings, args.min_severity, args.kev_only, args.fixable_only,
                                            args.in_use_only))
    s = rank.summary(findings)
    if args.sarif:
        from . import sarif
        json.dump(sarif.build([t.as_dict() for t in targets], findings, errors), sys.stdout, indent=1)
        sys.stdout.write("\n")
    elif args.json:
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
        n = s["malicious"]
        mal = (f"{n} MALICIOUS PACKAGE{'S' if n != 1 else ''} (remove {'them' if n != 1 else 'it'}, rotate secrets), "
               if n else "")
        print(f"{mal}{s['findings']} findings, {s['kev']} actively exploited, {s['fixable']} fixable{hidden}")
        if any(t.inuse for t in targets):
            print(f"{s['in_use']} in code running right now"
                  + (f", {s['restart_needed']} still running an old copy that was upgraded on disk (↻: restart "
                     "it)" if s["restart_needed"] else ""))
    for e in errors:
        warn(e)
    if s["kev"] or s["malicious"]:
        return EXIT_KEV
    if errors or any(t.status == "error" for t in targets):
        return EXIT_ERROR
    return EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
