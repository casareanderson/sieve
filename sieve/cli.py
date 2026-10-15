"""sieve command line."""
import argparse
import json
import os
import re
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
    common.add_argument("--sbom", choices=["cyclonedx", "spdx"], type=str.lower, metavar="{cyclonedx,spdx}",
                        help="print an SBOM of what was read (CycloneDX 1.6 or SPDX 2.3 JSON); no OSV query")
    common.add_argument("--with-vulns", action="store_true",
                        help="with --sbom cyclonedx: scan as usual and add the findings as `vulnerabilities`")
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
    common.add_argument("--new", action="store_true",
                        help="only findings that are new since the last --new run of the same scan; also lists what has "
                             "gone. The exit code follows the new findings only (for quiet daily cron jobs)")
    common.add_argument("--baseline", metavar="FILE",
                        help="with --new: where to keep the last run (default: next to the cache, one file per scan)")
    common.add_argument("--limit", type=int, default=50, metavar="N",
                        help="table rows to print (default 50, 0 = all); the summary always counts everything")
    sub = p.add_subparsers(dest="cmd", required=True, metavar="{host,containers,all,path,sbom,devices,verify,remote,collector}")
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
    sb = sub.add_parser("sbom", parents=[common], help="scan SBOMs made by other tools (CycloneDX or SPDX JSON: syft, "
                        "trivy, cdxgen, GitHub's dependency graph)")
    sb.add_argument("files", nargs="+", metavar="FILE")
    e = sub.add_parser("devices", aliases=["esp"], parents=[common],
                       help="small boards on the network (ESPHome, WLED, Victron Venus OS): advisories for the firmware release, plus "
                       "unencrypted API, web UI without a login, OTA flashing without a password")
    e.add_argument("hosts", nargs="*", metavar="HOST", help="devices to check as well as (or, with --no-discover, "
                   "instead of) the ones found by mDNS")
    e.add_argument("--discover-seconds", type=float, default=3.0, metavar="S",
                   help="how long to listen for mDNS answers (default 3)")
    e.add_argument("--no-discover", action="store_true", help="only the HOSTs given, no mDNS browse")
    v = sub.add_parser("verify", parents=[root], help="has any installed file changed since its package manager put it "
                       "there? (dpkg, apk, rpm and pip checksums already on disk)")
    v.add_argument("--json", action="store_true", help="machine-readable output")
    v.add_argument("--sarif", action="store_true", help="SARIF 2.1.0 output, for GitHub code scanning")
    v.add_argument("--packages", metavar="A,B", help="only these packages (dpkg/apk/rpm names or Python distributions)")
    v.add_argument("--include-config", action="store_true",
                   help="also check dpkg conffiles (expected to differ when you have edited them)")
    v.add_argument("--containers", action="store_true",
                   help="check every running Docker container in place instead of the host (needs root)")
    v.add_argument("--host", action="store_true", help="with --containers: check the host as well")
    v.add_argument("--all-missing", action="store_true",
                   help="also list missing docs, man pages and translations (images trim these; counted otherwise)")
    v.add_argument("--limit", type=int, default=50, metavar="N", help="table rows to print (default 50, 0 = all)")
    r = sub.add_parser("remote", parents=[common],
                       help="scan another machine over ssh (host + its containers); it needs only python3")
    r.add_argument("dest", metavar="user@host", help="ssh destination (key auth: sieve runs ssh in BatchMode)")
    r.add_argument("--port", type=int, help="ssh port")
    r.add_argument("-i", "--identity", metavar="FILE", help="ssh private key")
    r.add_argument("--ssh-opt", action="append", default=[], metavar="OPTION",
                   help="extra ssh -o option, e.g. --ssh-opt ProxyJump=bastion (repeatable)")
    r.add_argument("--sudo", action="store_true",
                   help="run the collector with `sudo -n` (passwordless sudo): containers need root, and so does a "
                        "full in-use picture; package lists alone don't")
    r.add_argument("--no-containers", action="store_true", help="host packages only")
    sub.add_parser("collector", help="print the standalone collector script (pipe it to `python3 -` elsewhere)")
    d = sub.add_parser("diff", help="compare two saved `--json` reports: what is new in the second, what has gone")
    d.add_argument("old_report", metavar="OLD.json")
    d.add_argument("new_report", metavar="NEW.json")
    d.add_argument("--json", action="store_true", help="machine-readable output")
    d.add_argument("--limit", type=int, default=50, metavar="N", help="rows to print per list (default 50, 0 = all)")
    return p


def scan(args, warn):
    """→ (targets, findings, errors). With --sbom (and no --with-vulns) targets keep their package lists and
    nothing is asked of OSV, KEV or EPSS."""
    export = args.sbom and not (args.with_vulns and args.sbom == "cyclonedx")
    targets, findings, errors = [], [], []
    client = kev = None

    def run(t):
        nonlocal client, kev
        if export:
            targets.append(t)
            return
        if client is None:
            client = osv.OSV(args.cache)
            kev = intel.kev_set(os.path.dirname(os.path.abspath(args.cache)))
        before, start = client.failed, len(findings)
        try:
            if t.pkgs:
                found = osv.match(client, t.pkgs, kev, target=t.name)
                if t.kind == "esp":
                    found = esp_firmware_only(found, t)
                findings.extend(found)
                inuse.annotate(findings[start:], t)
        except Exception as e:  # noqa: BLE001 — one unreadable target must not stop the rest
            t.status = "error"
            t.notes.append(f"OSV query failed: {type(e).__name__}: {str(e)[:160]}")
        findings.extend(t.exposures)
        lost = client.failed - before
        if lost and t.status == "ok":
            t.status = "partial"
            t.notes.append(f"{lost} advisories could not be fetched from OSV; counts may be low")
        note = inuse.coverage_note(t.inuse)
        if note:
            t.notes.append(note)
        if not args.sbom:
            t.pkgs, t.osinv = [], None                  # free the lists once matched
        targets.append(t)

    if args.cmd in ("host", "all"):
        run(sources.host(root=args.root, kernel=args.kernel))
    if args.cmd == "sbom":
        from . import sbom
        for f in args.files:
            run(sbom.read_file(f))
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
    if args.cmd == "remote":
        remote(args, run, errors)
    if args.cmd in ("devices", "esp"):
        esp_scan(args, run, errors, warn)
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


def esp_firmware_only(found, t):
    """OSV's PyPI `esphome` advisories cover the dashboard and the compiler too; those don't affect a flashed board."""
    keep = [f for f in found if "dashboard" not in (f.get("summary", "") + " " + f.get("details", "")).lower()]
    if len(keep) < len(found):
        t.notes.append(f"{len(found) - len(keep)} ESPHome dashboard advisories skipped (not in the firmware)")
    return keep


def wled_target(d):
    from . import exposure
    label = d.get("friendly_name") or d.get("name") or ""
    t = sources.Target(f"wled:{label} ({d['ip']})" if label else f"wled:{d['ip']}", "wled")
    t.os = f"WLED {d.get('version') or '(version unknown)'}" + (f" on {d['platform']}" if d.get("platform") else "")
    t.packages = 1 if d.get("version") else 0
    if d.get("web") == "closed":
        t.status = "error"
        t.notes.append("no answer on /json/info")
    else:
        t.notes.append("WLED publishes no security advisories (none on GitHub or OSV): version shown, not matched")
        if d.get("ota_lock") is None:
            t.notes.append("OTA lock state unreadable (a settings PIN hides /json/cfg)")
    t.exposures = exposure.wled_device(d, t.name)
    return t


def venus_target(d):
    from . import exposure
    t = sources.Target(f"venus:{d['ip']}", "venus")
    t.os = "Victron Venus OS"
    t.notes.append(f"remote console {d['gui']}, modbus {'open' if d['modbus'] else 'closed'}, mqtt 1883 "
                   f"{'open' if d['mqtt_plain'] else 'closed'}, ssh {'open' if d['ssh'] else 'closed'}; "
                   "Victron publishes no advisories to OSV, so the firmware version isn't matched")
    t.exposures = exposure.venus_device(d, t.name)
    return t


def esp_target(d):
    from . import exposure
    if d.get("kind") == "wled":
        return wled_target(d)
    if d.get("kind") == "venus":
        return venus_target(d)
    label = d.get("friendly_name") or d.get("name") or d.get("server_info") or ""
    t = sources.Target(f"esp:{label} ({d['ip']})" if label else f"esp:{d['ip']}", "esp")
    ver = d.get("version")
    hw = "/".join(x for x in (d.get("platform"), d.get("board")) if x)
    t.os = f"ESPHome {ver or '(version unknown)'}" + (f" on {hw}" if hw else "")
    if ver:
        t.pkgs = [("PyPI", "esphome", ver, "esphome firmware", ver)]
        t.packages = 1
    else:
        t.notes.append("version unknown: no mDNS answer and no plaintext API, so no advisory check")
        t.status = "partial"
    t.notes.append(f"api {d['api']}, ota {d['ota']}, web {d['web']}"
                   + (" (firmware upload on)" if d.get("web_ota") else ""))
    t.exposures = exposure.esp_device(d, t.name)
    return t


def esp_scan(args, run, errors, warn):
    from . import esp
    import socket
    found = {}
    if not args.no_discover:
        try:
            found = esp.discover(args.discover_seconds)
        except OSError as e:
            errors.append(f"esp: mDNS browse failed: {e}")
    for h in args.hosts:
        try:
            ip = socket.gethostbyname(h)
        except OSError as e:
            errors.append(f"esp: {h}: {e}")
            continue
        found.setdefault(ip, {})
    if not found:
        warn("esp: no ESPHome devices answered mDNS; name them: sieve esp HOST ...")
    for ip in sorted(found, key=lambda x: tuple(int(p) for p in x.split(".")) if x.count(".") == 3 else (999,)):
        info = found[ip]
        if info.get("kind") == "wled" or (not info.get("kind") and esp.is_wled(ip)):
            run(esp_target(esp.probe_wled(ip, info)))
        elif not info.get("kind") and esp.is_venus(ip):
            run(esp_target(esp.probe_venus(ip)))
        else:
            run(esp_target(esp.probe(ip, info)))


DEST = re.compile(r"^[A-Za-z0-9_.@:\[\]%+-]+$")


def remote(args, run, errors):
    """`sieve remote`: the collector in host mode, then (unless --no-containers) in container mode, each piped to the
    remote python3 over ssh. Nothing is installed or written there; only package metadata comes back."""
    if not DEST.match(args.dest) or args.dest.startswith("-"):
        errors.append(f"remote: {args.dest!r} is not an ssh destination (user@host)")
        return
    label = args.dest.rsplit("@", 1)[-1]
    ssh = {"port": args.port, "identity": args.identity, "opts": args.ssh_opt}
    script = sources.collector_source()

    def over_ssh(mode, sudo, read):
        p, stream = sources.run_remote(sources.ssh_command(args.dest, sudo=sudo, mode=mode, **ssh), script)
        failed = None
        try:
            read(stream)
        except Exception as e:  # noqa: BLE001 — usually ssh gave no tar at all; its exit code says why
            failed = e
        rc = p.wait()
        err = p.stderr.read()
        if rc:
            raise RuntimeError(sources.ssh_error(rc, err))
        if failed:
            raise failed

    sudo = args.sudo and not args.dest.startswith("root@")
    host = []
    try:
        over_ssh("host", sudo, lambda s: host.append(sources.read_host(s, label, kernel=args.kernel)))
        run(host[0])
    except Exception as e:  # noqa: BLE001
        errors.append(f"remote host {label}: {e}")
        return
    if args.no_containers:
        return
    errs, n = [], []
    try:
        over_ssh("", sudo,
                 lambda s: n.extend(run(t) for t in sources.read_collected(s, errs, kernel=args.kernel)))
    except Exception as e:  # noqa: BLE001
        errors.append(f"remote containers {label}: {e}")
        return
    errors += [f"remote collector {label}: {e}" for e in errs]
    if not n and not errs:
        host[0].notes.append("no running containers seen (no Docker, none running, or this user can't list them: "
                             "try root@ or --sudo)")


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
        exp = f["status"] == "exposure"
        rows.append((flag, epss, f["severity"],
                     "-" if exp else use.get(f.get("in_use"), "?") + (" ↻" if f.get("restart_needed") else ""),
                     f["id"], _cut(f["package"], 28),
                     f"{_cut(f['installed'], 34 if exp else 26)} → {_cut(fix, 48 if exp else 26)}",
                     _cut(f["target"], 32)))
    w = [max(len(r[i]) for r in rows) for i in range(len(rows[0]))]
    lines = ["  ".join(c.ljust(w[i]) for i, c in enumerate(r)).rstrip() for r in rows]
    if limit and len(findings) > limit:
        lines.append(f"… {len(findings) - limit} more (use --limit 0 to show all, or --json)")
    return "\n".join(lines)


def brief(findings, limit):
    """A short table for findings that may come from a saved report (fewer fields than a live scan)."""
    rows = [("ALERT", "SEVERITY", "ID", "PACKAGE", "INSTALLED → FIXED", "TARGET")]
    shown = findings if not limit else findings[:limit]
    for f in shown:
        flag = "☠ MALWARE" if f.get("malicious") else "⚠" if f.get("kev") else ""
        rows.append((flag, f.get("severity") or "", f["id"], _cut(f["package"], 28),
                     f"{_cut(f.get('installed') or '', 26)} → {_cut(f.get('fixed') or 'no fix', 26)}",
                     _cut(f["target"], 32)))
    w = [max(len(r[i]) for r in rows) for i in range(len(rows[0]))]
    lines = ["  ".join(c.ljust(w[i]) for i, c in enumerate(r)).rstrip() for r in rows]
    if limit and len(findings) > limit:
        lines.append(f"… {len(findings) - limit} more (use --limit 0 to show all, or --json)")
    return "\n".join(lines)


def now_utc():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def new_since(args, targets, findings, errors, warn):
    """--new: → (new findings, gone findings, baseline time or None). Saves this run as the next baseline when the
    scan was complete; an incomplete scan keeps the old baseline and reports nothing as gone."""
    from . import diff
    path = diff.state_path(args)
    base = diff.load(path)
    complete = not errors and all(t.status == "ok" for t in targets)
    if base is None:
        new, gone = findings, []
        warn(f"--new: no earlier run of this scan, so everything counts as new; baseline saved to {path}" if complete
             else "--new: no earlier run of this scan, and this one was incomplete, so no baseline was saved yet")
    else:
        new, gone = diff.compare(base["findings"], findings)
        if not complete:
            warn("--new: this scan was incomplete, so the baseline is kept and nothing is reported as gone")
            gone = []
    if complete:
        diff.save(path, findings, now_utc(), __version__)
    return new, gone, (base or {}).get("generated")


def diff_main(args):
    from . import diff
    try:
        old_at, old = diff.report_findings(args.old_report)
        new_at, new = diff.report_findings(args.new_report)
    except (OSError, ValueError) as e:
        print(f"sieve: {e}", file=sys.stderr)
        return EXIT_ERROR
    added, gone = diff.compare(old, new)
    if args.json:
        json.dump({"sieve": __version__, "old": old_at, "new": new_at, "new_findings": added, "gone": gone},
                  sys.stdout, indent=1)
        sys.stdout.write("\n")
    else:
        print(f"# {args.old_report} ({old_at or '?'}) → {args.new_report} ({new_at or '?'})")
        for title, rows in ((f"{len(added)} new", added), (f"{len(gone)} gone (fixed or removed)", gone)):
            print(f"\n{title}")
            if rows:
                print(brief(rows, args.limit))
    return EXIT_KEV if any(f.get("kev") or f.get("malicious") for f in added) else EXIT_OK


def main(argv=None):
    args = parser().parse_args(argv)
    if args.cmd == "diff":
        return diff_main(args)
    if args.cmd == "collector":
        sys.stdout.write(sources.collector_source())
        return EXIT_OK
    if args.cmd == "verify":
        from . import verify
        return verify.main(args)

    def warn(m):
        print(f"sieve: {m}", file=sys.stderr)
    targets, findings, errors = scan(args, warn)
    gone, since = [], None
    if args.new:
        if args.sbom and not args.with_vulns:
            warn("--new: an SBOM export has no findings to compare; ignored")
            args.new = False
        else:
            findings, gone, since = new_since(args, targets, findings, errors, warn)
    total = len(findings)
    findings = rank.rank(rank.apply_filters(findings, args.min_severity, args.kev_only, args.fixable_only,
                                            args.in_use_only))
    s = rank.summary(findings)
    if args.sbom:
        from . import sbom
        if args.with_vulns and args.sbom == "spdx":
            warn("--with-vulns needs --sbom cyclonedx (SPDX 2.3 has no place for vulnerabilities); not added")
        vulns = findings if args.with_vulns and args.sbom == "cyclonedx" else None
        json.dump(sbom.build(args.sbom, targets, vulns), sys.stdout, indent=1)
        sys.stdout.write("\n")
    elif args.sarif:
        from . import sarif
        json.dump(sarif.build([t.as_dict() for t in targets], findings, errors), sys.stdout, indent=1)
        sys.stdout.write("\n")
    elif args.json:
        out = {"sieve": __version__, "generated": now_utc(),
               "targets": [t.as_dict() for t in targets], "errors": errors,
               "summary": dict(s, unfiltered=total), "findings": findings}
        if args.new:
            out["new_since"] = {"baseline": since, "gone": gone}
        json.dump(out, sys.stdout, indent=1)
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
        what = (f"new findings since {since}" if since else "findings (first --new run: all new)") if args.new \
            else "findings"
        print(f"{mal}{s['findings']} {what}, {s['kev']} actively exploited, {s['fixable']} fixable{hidden}")
        if gone:
            print(f"\n{len(gone)} gone since {since} (fixed or removed):")
            print(brief(gone, args.limit))
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
