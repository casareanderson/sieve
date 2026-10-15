"""Exposure findings: things that let someone in without any CVE at all.

They go in the same list as advisories (same fields, so ranking, filters, --new, SARIF and diff all work), with an
id starting `SIEVE-`, `status: "exposure"`, the current state as `installed` and the fix as `fixed`.

  accounts(report, target)   from collect.accounts_report(): empty passwords, a usable root password, root
                             password logins over ssh, weak hash schemes
  esp_device(dev, target)    from esp.probe(): ESPHome native API without encryption, web UI without a login,
                             OTA flashing without a password, web-UI firmware upload open to the LAN
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
