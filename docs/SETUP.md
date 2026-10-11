# Setting up sieve

This takes about five minutes on a normal Linux box. Every block marked as tested below is run on a fresh
Ubuntu runner every week by [`setup-check`](../.github/workflows/setup-check.yml), so if a step here stops
working, that check goes red before you find out the hard way.


![What a passing run looks like on a fresh machine (excerpt from `setup-check` on 11 October 2026). Secrets in the output are masked](setup-run.png)

*What a passing run looks like on a fresh machine (excerpt from `setup-check` on 11 October 2026). Secrets in the output are masked.*

## What you need

- Linux. sieve reads Debian/Ubuntu (`dpkg`) and Alpine (`apk`) package databases for OS packages. On other
  distros (Fedora, RHEL, Arch) it still checks Python and container language packages, not the OS ones.
- Python 3.10 or newer.
- Outbound HTTPS to `api.osv.dev`, `secdb.alpinelinux.org`, `www.cisa.gov` and `epss.empiricalsecurity.com`.
  Package names and versions go to OSV.dev; nothing else about the machine does.
- Root only if you want to scan running Docker containers (their filesystems under `/proc/<pid>/root` are
  root-only). Host scans don't need it.

No database to download, no server to run, no API key.

## Install

The easy way is [pipx](https://pipx.pypa.io/), which keeps sieve in its own environment:

```sh setup-check
sudo apt-get update -qq && sudo apt-get install -y -qq pipx
pipx install git+https://github.com/casareanderson/sieve
export PATH="$HOME/.local/bin:$PATH"
sieve --version
```

If `sieve: command not found` comes back after installing, `~/.local/bin` isn't on your `PATH` yet.
Run `pipx ensurepath` and open a new terminal.

No pipx? It runs straight from a checkout too, and its only dependency is `requests`:

```
git clone https://github.com/casareanderson/sieve
cd sieve
python3 -m sieve host
```

## First run

Scan the machine you're on:

```sh setup-check
sieve host --limit 10 || [ $? -eq 1 ]
```

The first run is the slow one: it downloads the CISA KEV list and the EPSS scores, and asks OSV.dev about every
package. After that the advisories are cached and only refetched when OSV says they changed, so later runs are
much quicker.

You get one line per target, a ranked table, and a summary at the bottom:

```
# host: debian 13, 811 packages

KEV  EPSS   SEVERITY  ID              PACKAGE              INSTALLED → FIXED                          TARGET
     73.3%  UNKNOWN   CVE-2011-3389   gnutls-bin           3.8.9-3+deb13u4 → no fix                   host
...
1965 findings, 0 actively exploited, 0 fixable
```

A big number with "0 fixable" is normal on a patched box. Most of what any scanner reports is "affected, no
fix released yet". The rows that matter are at the top: a `⚠` in the KEV column means someone is exploiting it
in the wild right now.

## Check it worked

The exit code tells you, which is what you want for cron and CI:

| exit code | meaning |
|---|---|
| `0` | nothing known-exploited in the output |
| `1` | at least one known-exploited (KEV) finding |
| `2` | part of the scan failed (read the `sieve:` lines on stderr) |

That's why the tested step above is `sieve host ... || [ $? -eq 1 ]`: a KEV finding on the runner is a real
result, not a broken install. Only exit code 2 means sieve itself didn't work.

For something a script can read, use `--json`:

```sh setup-check
sieve host --json --limit 0 > report.json || [ $? -eq 1 ]
python3 -c "import json; d = json.load(open('report.json')); print(d['summary']); assert d['targets']"
```

## Scan your running containers

This needs root and Docker on the same box. The collector is a single standard-library script that sieve
prints; you pipe it into `python3` as root, it reads each running container's package lists and writes a tar,
and sieve scans the tar. It doesn't install or write anything inside the containers.

```sh setup-check
docker run -d --rm --name sieve-demo debian:12 sleep 300
sieve collector | sudo python3 - > packages.tgz
sieve containers --from-tar packages.tgz --min-severity high --limit 10 || [ $? -eq 1 ]
docker stop sieve-demo
```

Or let sieve run the collector itself:

```
sudo "$(command -v sieve)" containers
sudo "$(command -v sieve)" all          # host and containers in one go
```

Only images with a running container are scanned. If you see `sieve: no running containers found`, that's what
it means.

The same collector works for a Docker host somewhere else, with nothing installed there except `python3`:

```
sieve collector | ssh root@dockerhost python3 - > packages.tgz
sieve containers --from-tar packages.tgz
```

## Or use the Docker image

The image only needs to read the host's filesystem, so mount it read-only and point `--root` at it:

```sh setup-check
docker run --rm ghcr.io/casareanderson/sieve --version
docker run --rm -v /:/host:ro ghcr.io/casareanderson/sieve host --root /host --limit 5 || [ $? -eq 1 ]
```

Add `-v sieve-cache:/home/sieve/.cache` to keep the advisory cache between runs, or every run is a first run.

## Configure

There's no config file. Everything is a command-line option:

| option | default | what it does |
|---|---|---|
| `--min-severity low\|medium\|high\|critical` | all | hide findings below this severity (known-exploited ones are always shown) |
| `--kev-only` | off | only findings in CISA's known-exploited list |
| `--fixable-only` | off | only findings with a fixed version available |
| `--cache PATH` | `~/.cache/sieve/sieve.db` | advisory cache; KEV and EPSS files are kept next to it |
| `--no-epss` | off | don't download or use EPSS scores |
| `--kernel` | off | also check kernel packages |
| `--root PATH` | `/` | `host` and `all`: read packages from this directory instead of `/` |
| `--limit N` | `50` | table rows to print, `0` for all |
| `--json` | off | machine-readable output |

The cache lives under `$XDG_CACHE_HOME/sieve` if `XDG_CACHE_HOME` is set, otherwise `~/.cache/sieve`. That's the
only environment variable sieve reads.

A good cron line, which only shouts about things you can actually fix:

```
0 7 * * 1  sieve all --fixable-only --min-severity high
```

## Run it in GitHub Actions

sieve is also a GitHub Action. It scans the runner, writes the table to the job summary and fails the job on a
known-exploited finding:

```yaml
- uses: casareanderson/sieve@v1
  with:
    command: host            # host, containers or all
    args: --fixable-only
```

The full list of inputs and outputs is in the [README](../README.md#use-it-in-ci).

## Common problems

| you see | what it means | what to do |
|---|---|---|
| `OSV query failed: ...` on a target, exit code 2 | OSV.dev couldn't be reached or timed out | check outbound HTTPS to `api.osv.dev`; run it again |
| `N advisories could not be fetched from OSV; counts may be low` | some advisory downloads failed | run it again; the cache keeps what it did get |
| `KEV refresh failed (...); using the cached copy if there is one` | couldn't reach `www.cisa.gov` | fine for a while; the last copy is used |
| `no KEV data: known-exploited findings cannot be flagged` | no KEV copy at all yet | fix the network, then run again |
| `EPSS refresh failed` / `EPSS cache unreadable` | couldn't get EPSS scores | use `--no-epss`, or delete the cache folder |
| `<os>: OSV has no advisory feed for this OS; OS packages not checked` | Fedora, RHEL, Arch and friends | only language packages are checked on these |
| `no dpkg or apk package database found` | wrong `--root`, or a distro sieve doesn't read | point `--root` at the real `/` |
| `N kernel packages skipped` | normal; containers run the host kernel | add `--kernel` on a real host if you want them |
| `sieve: no running containers found` | no containers running, or not run as root | start them, or run with `sudo` |
| `collector exited 1: ...` | the collector couldn't read Docker | run it as root on the Docker host |

## Update

```
pipx upgrade sieve
```

pipx installed it from git, so if `upgrade` says it's already up to date, `pipx reinstall sieve` pulls the latest
from `main`. The Docker image: `docker pull ghcr.io/casareanderson/sieve`.

## Uninstall

```
pipx uninstall sieve
rm -rf ~/.cache/sieve
```

sieve doesn't write anywhere else, and it never changes anything on the machine it scans.
