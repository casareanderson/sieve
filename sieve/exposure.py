"""Exposure findings: things that let someone in without any CVE at all.

They go in the same list as advisories (same fields, so ranking, filters, --new, SARIF and diff all work), with an
id starting `SIEVE-`, `status: "exposure"`, the current state as `installed` and the fix as `fixed`.

  accounts(report, target)   from collect.accounts_report(): empty passwords, a usable root password, root
                             password logins over ssh, weak hash schemes
  esp_device(dev, target)    from esp.probe(): ESPHome native API without encryption, web UI without a login,
                             OTA flashing without a password, web-UI firmware upload open to the LAN
  secrets(report, target)    from collect.secrets_report(): credentials in plain-text files, shell histories, AI
                             agent chats and configs, and private keys without a passphrase
  container_env(entries, t)  from collect.containers_env(): credentials in a running container's environment
"""
URL = "https://github.com/casareanderson/sieve/blob/main/docs/EXPOSURES.md#"
WEAK = {"des": "DES crypt (8-character limit, cracked in seconds)", "md5": "MD5 crypt ($1$)",
        "sun-md5": "Sun MD5 crypt", "sha1": "SHA-1 crypt", "unknown": "an unrecognised scheme"}


def row(fid, package, installed, fix, severity, summary, target, details=""):
    return {"id": fid, "package": package, "installed": installed, "fixed": fix, "severity": severity,
            "summary": summary[:200], "kev": False, "malicious": False, "status": "exposure", "target": target,
            "details": details[:1200], "url": URL + fid.lower()}


def ssh_allows_root_password(sshd):
    """sshd options → True / False. `without-password` is the old spelling of `prohibit-password`."""
    if not sshd:
        return False
    if sshd.get("permitrootlogin") not in ("yes",):
        return False
    return sshd.get("passwordauthentication") == "yes" or (
        sshd.get("kbdinteractiveauthentication") == "yes" and sshd.get("usepam") == "yes")


def accounts(rep, target):
    """→ (findings, note or "")."""
    if not rep or not rep.get("checked"):
        return [], (rep or {}).get("note") or ""
    out, sshd = [], rep.get("sshd")
    over_ssh = ssh_allows_root_password(sshd)
    src = f" (sshd settings from {sshd['source']})" if sshd else ""
    for a in rep.get("accounts", []):
        user, state = a["user"], a["state"]
        login = a.get("shell", "") not in ("", "/usr/sbin/nologin", "/sbin/nologin", "/bin/false", "/usr/bin/false")
        if state == "empty":
            sev = "CRITICAL" if user == "root" or login else "HIGH"
            out.append(row("SIEVE-EMPTY-PASSWORD", f"account:{user}", "empty password", f"passwd -l {user}", sev,
                           f"{user} has an EMPTY password: anyone at a console (or over ssh if PermitEmptyPasswords "
                           "is on) logs in with no password", target))
            continue
        if state != "usable":
            continue
        if a.get("default_of"):
            ssh = " and sshd takes passwords" if user != "root" and sshd and sshd.get("passwordauthentication") \
                == "yes" else ""
            out.append(row("SIEVE-DEFAULT-PASSWORD", f"account:{user}", f"default password ({a['default_of']})",
                           f"passwd {user}", "CRITICAL",
                           f"{user} still has the {a['default_of']} default password{ssh}: it is on every "
                           "scanner's first-guess list", target))
        if a["scheme"] in WEAK:
            out.append(row("SIEVE-WEAK-PASSWORD-HASH", f"account:{user}", f"{a['scheme']} hash",
                           f"passwd {user} (re-hashes with the system default)", "MEDIUM",
                           f"{user}'s password is stored with {WEAK[a['scheme']]}: a copied /etc/shadow gives "
                           "the password up quickly", target))
        if user == "root":
            if over_ssh:
                out.append(row("SIEVE-ROOT-SSH-PASSWORD", "account:root", "root password + ssh password login",
                               "PermitRootLogin prohibit-password (keys only), or passwd -l root", "HIGH",
                               "root has a password AND sshd lets root log in with it: one guessed or reused "
                               "password is a root shell for anyone who can reach port 22" + src, target))
            else:
                out.append(row("SIEVE-ROOT-PASSWORD", "account:root", "root password set (not locked)",
                               "passwd -l root if you log in with sudo or keys", "LOW",
                               "root has a usable password; ssh does not accept it" + src + ", but a console, "
                               "su, or a web UI that uses PAM (Proxmox, Cockpit, Webmin) still does", target,
                               "Leave it if something needs it (the Proxmox web UI logs in as root@pam). Otherwise "
                               "lock it: `passwd -l root`. Locking keeps key-based root logins working."))
    if sshd and sshd.get("permitemptypasswords") == "yes":
        out.append(row("SIEVE-SSH-EMPTY-PASSWORDS", "sshd", "PermitEmptyPasswords yes", "PermitEmptyPasswords no",
                       "HIGH", "sshd accepts logins to accounts that have no password" + src, target))
    return out, ""


def esp_device(dev, target):
    """dev: esp.probe() result → findings."""
    out, name = [], "esphome firmware"
    if dev.get("api") == "plaintext":
        out.append(row("SIEVE-ESPHOME-API-PLAINTEXT", name, "native API without encryption",
                       "api: encryption: key: <32-byte base64> (then re-adopt in Home Assistant)", "MEDIUM",
                       "the native API (port 6053) has no encryption key: anyone on the network can read every "
                       "sensor and switch every output, and see the traffic in clear", target))
    if dev.get("ota") == "open":
        out.append(row("SIEVE-ESPHOME-OTA-NO-PASSWORD", name, "OTA flashing without a password",
                       "ota: - platform: esphome  password: <long random>", "HIGH",
                       "anyone on the network can flash new firmware over OTA (port 3232): the board, its "
                       "Wi-Fi password and its API key are theirs", target))
    if dev.get("web") == "open":
        upload = dev.get("web_ota")
        out.append(row("SIEVE-ESPHOME-WEB-OTA" if upload else "SIEVE-ESPHOME-WEB-NO-AUTH", name,
                       "web UI without a login" + (" + firmware upload" if upload else ""),
                       "web_server: auth: {username: …, password: …}" + ("  and  ota: false" if upload else ""),
                       "HIGH" if upload else "MEDIUM",
                       ("the web UI on port 80 has no login AND accepts firmware uploads: anyone on the network "
                        "can flash it from a browser") if upload else
                       ("the web UI on port 80 has no login: anyone on the network can switch its outputs and "
                        "read its log (which can include hostnames and IPs)"), target))
    return out


def wled_device(dev, target):
    """dev: esp.probe_wled() result → findings."""
    if dev.get("ota_lock") is False:
        extra = (" ArduinoOTA is on too (port 3232, default password `wledota` unless changed)."
                 if dev.get("arduino_ota") else "")
        return [row("SIEVE-WLED-OTA-UNLOCKED", "wled firmware", "OTA not locked",
                    "Config → Security & Updates: set a settings PIN, tick OTA lock (+ password), untick ArduinoOTA",
                    "HIGH", "anyone on the network can flash new firmware from a browser at /update" + extra,
                    target, "WLED's own advice: lock OTA once set up. A flashed board joins your Wi-Fi with "
                    "whatever firmware the attacker chose.")]
    return []


def venus_device(dev, target):
    """dev: esp.probe_venus() result → findings."""
    out, name = [], "venus os"
    if dev.get("gui") == "open":
        out.append(row("SIEVE-VENUS-NO-LOGIN", name, "Remote Console without a password",
                       "Settings → General → Security profile: Secured (sets a password)", "HIGH",
                       "the Remote Console opens without a login: anyone on the network can change charger, "
                       "inverter and battery settings", target))
    if dev.get("modbus"):
        out.append(row("SIEVE-VENUS-MODBUS-OPEN", name, "Modbus TCP on (port 502, no auth)",
                       "Settings → Integrations → Modbus TCP server: off", "MEDIUM",
                       "Modbus TCP has no authentication: anyone on the network can read and WRITE registers "
                       "(charge limits, ESS setpoints)", target))
    if dev.get("mqtt_plain"):
        out.append(row("SIEVE-VENUS-MQTT-PLAINTEXT", name, "MQTT on LAN, plaintext (port 1883)",
                       "Security profile: Secured (MQTT over TLS on 8883 with a password)", "MEDIUM",
                       "plaintext MQTT on 1883 lets anyone on the network read every value and send W/ writes "
                       "to settings", target))
    return out


# ── plain-text secrets (collect.secrets_report, collect.containers_env) ───────
SECRET_BASE = {"file": ("SIEVE-SECRET-IN-FILE", "LOW"), "history": ("SIEVE-SECRET-IN-HISTORY", "MEDIUM"),
               "agent-chat": ("SIEVE-SECRET-IN-AGENT-CHAT", "MEDIUM"),
               "agent-config": ("SIEVE-SECRET-IN-AGENT-CONFIG", "LOW"), "key": ("SIEVE-SECRET-PRIVATE-KEY", "LOW")}
ORDER = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]


def _at_least(sev, floor):
    return sev if ORDER.index(sev) >= ORDER.index(floor) else floor


def _secret_fix(f):
    p, where, reach = f["path"], f["where"], f["reach"]
    chmod = f"chmod 600 {p}; " if reach != "owner" else ""
    if where == "key":
        name = p.rsplit("/", 1)[-1]
        if name.startswith("id_") or name.endswith(".ppk"):
            return f"{chmod}ssh-keygen -p -f {p} (add a passphrase; ssh-agent saves retyping it)"
        return f"{chmod or 'chmod 600 ' + p + '; '}keep it readable only by the service that uses it"
    if where == "history":
        return f"rotate it, then delete the line from {p} (HISTCONTROL=ignorespace: a leading space keeps a command out)"
    if where == "agent-chat":
        return f"{chmod}rotate it (it was sent to the model provider too), then delete the session or the line"
    if where == "agent-config":
        return f"{chmod}read it from the environment or a secret manager instead of writing it into the config"
    return f"{chmod}load it from a secret manager (pass, Vault, Infisical, systemd credentials) or keep it 0600"


def secrets(rep, target):
    """→ (findings, note). One row per file, however many secrets it holds."""
    if not rep or not rep.get("checked"):
        return [], (rep or {}).get("note") or ""
    out = []
    for f in rep.get("files", []):
        fid, sev = SECRET_BASE.get(f["where"], SECRET_BASE["file"])
        reach = f["reach"]
        if reach == "world":
            sev = "HIGH"
        elif reach.startswith("group:"):
            sev = _at_least(sev, "MEDIUM")
        who = {"world": "readable by every user on the machine", "owner": f"readable by {f['owner']} only"}.get(
            reach, f"readable by group {reach[6:]}")
        kinds = ", ".join(f["kinds"])
        n = f["count"]
        at = f" line {f['line']}" if f.get("line") else ""
        what = (f"unencrypted private key, {f['mode']}" if f["where"] == "key" else
                f"{n} secret{'s' if n != 1 else ''} ({kinds}){at}, {f['mode']}")
        agent = f"{f['agent']} " if f.get("agent") else ""
        summary = {"key": f"private key with no passphrase, {who}: a copy of the file is the key",
                   "history": f"{kinds} typed on a command line and kept in the shell history, {who}",
                   "agent-chat": f"{kinds} in an {agent}chat transcript, {who}: it is in the model provider's "
                                 "logs too, and transcripts get synced, shared and backed up",
                   "agent-config": f"{kinds} written into {agent}config{' (its login store)' if f.get('login_store') else ''}, {who}",
                   }.get(f["where"], f"{kinds} in plain text, {who}")
        details = (f"{f['path']}{at}; mode {f['mode']}, owner {f['owner']}, {who}. "
                   + (f"fingerprint {f['fp']} (the same secret gives the same fingerprint on this machine). "
                      if f.get("fp") else "") + "sieve never prints or sends the secret itself.")
        out.append(row(fid, f["path"], what + (f", fp {f['fp']}" if f.get("fp") else ""), _secret_fix(f), sev,
                       summary, target, details))
    return out, rep.get("note") or ""


def container_env(entries, target):
    """collect.containers_env() entries for one image → one row per container."""
    out = []
    for c in entries or []:
        names = ", ".join(v["var"] for v in c["vars"])
        kinds = ", ".join(sorted({k for v in c["vars"] for k in v["kinds"]}))
        out.append(row("SIEVE-SECRET-IN-CONTAINER-ENV", f"container:{c['container']}",
                       f"{len(c['vars'])} in env ({names})" + (f", fp {c['fp']}" if c.get("fp") else ""),
                       "pass it as a file (Docker/compose secrets, or a *_FILE variable) instead of an env var",
                       "LOW", f"{kinds} in the container's environment ({names}): `docker inspect`, /proc/<pid>/"
                       "environ, crash dumps and anything that logs the environment all show it", target,
                       f"variables: {names}. Values the image sets itself are not counted. sieve never prints or "
                       "sends the value."))
    return out
