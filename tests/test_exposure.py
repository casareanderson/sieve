"""Exposure checks: accounts and sshd (collect.accounts_report → exposure.accounts), small boards (esp.py:
ESPHome and WLED), and the raspbian mapping. No network: sockets are local, HTTP is faked."""
import json
import socket
import struct
import threading

from sieve import cli, collect, esp, exposure, osv, sources

YESCRYPT_SETTING = "$y$j9T$F5Jx5fExrKuPp53xLKQ..1$"


def make_root(tmp_path, shadow, passwd=None, sshd=None, model=None):
    (tmp_path / "etc").mkdir(exist_ok=True)
    (tmp_path / "etc/shadow").write_text(shadow)
    (tmp_path / "etc/passwd").write_text(passwd or "root:x:0:0:root:/root:/bin/bash\n"
                                                   "pi:x:1000:1000::/home/pi:/bin/bash\n"
                                                   "daemon:x:1:1::/:/usr/sbin/nologin\n")
    if sshd is not None:
        (tmp_path / "etc/ssh/sshd_config.d").mkdir(parents=True, exist_ok=True)
        (tmp_path / "etc/ssh/sshd_config").write_text(sshd)
    if model:
        (tmp_path / "proc/device-tree").mkdir(parents=True)
        (tmp_path / "proc/device-tree/model").write_bytes(model.encode() + b"\0")
    return str(tmp_path)


def ids(findings):
    return sorted((f["id"], f["package"], f["severity"]) for f in findings)


# ── accounts ─────────────────────────────────────────────────────────────────
def test_pw_state():
    assert collect.pw_state("") == ("empty", "")
    assert collect.pw_state("!") == ("locked", "")
    assert collect.pw_state("!$6$x$y") == ("locked", "")
    assert collect.pw_state("*") == ("locked", "")
    assert collect.pw_state("$y$j9T$a$b") == ("usable", "yescrypt")
    assert collect.pw_state("$6$a$b") == ("usable", "sha512")
    assert collect.pw_state("$1$a$b") == ("usable", "md5")
    assert collect.pw_state("abcdefghijklm") == ("usable", "des")


def test_sshd_config_first_value_wins_include_and_match(tmp_path):
    root = make_root(tmp_path, "root:!:1::::::\n",
                     sshd="Include /etc/ssh/sshd_config.d/*.conf\nPermitRootLogin no\n"
                          "Match User backup\n  PasswordAuthentication no\n")
    (tmp_path / "etc/ssh/sshd_config.d/10-local.conf").write_text("PermitRootLogin yes  # set by a guide\n")
    s = collect.sshd_settings(root)
    assert s["permitrootlogin"] == "yes"                    # the Include comes first, so it wins
    assert s["passwordauthentication"] == "yes"             # default; the Match block is not applied
    assert "Match" in s["source"]
    assert collect.sshd_settings(str(tmp_path / "nowhere")) is None


def test_root_password_with_ssh_password_login_is_high(tmp_path):
    root = make_root(tmp_path, "root:$6$a$b:1::::::\npi:!:1::::::\ndaemon:*:1::::::\n",
                     sshd="PermitRootLogin yes\nPasswordAuthentication yes\n")
    rep = collect.accounts_report(root)
    assert rep["checked"] and rep["locked"] == 2 and [a["user"] for a in rep["accounts"]] == ["root"]
    assert "$6$" not in json.dumps(rep)                      # no hash ever leaves accounts_report
    found, note = exposure.accounts(rep, "host")
    assert ids(found) == [("SIEVE-ROOT-SSH-PASSWORD", "account:root", "HIGH")] and note == ""


def test_root_password_keys_only_ssh_is_low(tmp_path):
    root = make_root(tmp_path, "root:$y$j9T$a$b:1::::::\n", sshd="PermitRootLogin prohibit-password\n")
    found, _ = exposure.accounts(collect.accounts_report(root), "host")
    assert ids(found) == [("SIEVE-ROOT-PASSWORD", "account:root", "LOW")]


def test_empty_and_weak_and_locked_root(tmp_path):
    root = make_root(tmp_path, "root:!:1::::::\npi::1::::::\ndaemon:abcdefghijklm:1::::::\n",
                     sshd="PermitEmptyPasswords yes\n")
    found, _ = exposure.accounts(collect.accounts_report(root), "h")
    assert ids(found) == [("SIEVE-EMPTY-PASSWORD", "account:pi", "CRITICAL"),
                          ("SIEVE-SSH-EMPTY-PASSWORDS", "sshd", "HIGH"),
                          ("SIEVE-WEAK-PASSWORD-HASH", "account:daemon", "MEDIUM")]


def test_board_default_password_found_without_leaking_it(tmp_path):
    crypt = collect._crypt_fn()
    if crypt is None:
        import pytest
        pytest.skip("no libcrypt here")
    pi = crypt("raspberry", YESCRYPT_SETTING)
    other = crypt("correct horse", YESCRYPT_SETTING)
    root = make_root(tmp_path, f"root:!:1::::::\npi:{pi}:1::::::\n",
                     sshd="PasswordAuthentication yes\n", model="Raspberry Pi 4 Model B Rev 1.4")
    rep = collect.accounts_report(root)
    assert rep["board"] == "Raspberry Pi 4 Model B Rev 1.4"
    assert "raspberry" not in json.dumps(rep) and pi not in json.dumps(rep)
    found, _ = exposure.accounts(rep, "pi4")
    assert ids(found) == [("SIEVE-DEFAULT-PASSWORD", "account:pi", "CRITICAL")]
    assert "Raspberry Pi OS" in found[0]["installed"]
    assert collect.default_password("pi", other) == ""
    assert collect.default_password("someone", pi) == ""     # only the users an image ships


def test_shadow_unreadable_is_a_note(tmp_path):
    found, note = exposure.accounts({"checked": False, "note": "passwords not checked: /etc/shadow needs root"}, "h")
    assert found == [] and "needs root" in note


def test_remote_host_tar_carries_accounts(tmp_path, monkeypatch):
    from test_remote import host_mode_tar
    root = make_root(tmp_path, "root:$6$a$b:1::::::\n", sshd="PermitRootLogin yes\n")
    (tmp_path / "etc/os-release").write_text('ID=raspbian\nVERSION_ID="12"\n')
    t = sources.read_host(__import__("io").BytesIO(host_mode_tar(monkeypatch, root)), "pi")
    assert ids(t.exposures) == [("SIEVE-ROOT-SSH-PASSWORD", "account:root", "HIGH")]
    assert t.os.startswith("raspbian 12")


def test_raspbian_maps_to_debian():
    assert osv.ecosystem({"ID": "raspbian", "ID_LIKE": "debian", "VERSION_ID": "12"})[0] == "Debian:12"
    assert osv.ecosystem({"ID": "raspbian", "VERSION_ID": ""})[0] is None


# ── mDNS ─────────────────────────────────────────────────────────────────────
def _labels(name):
    return b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\0"


def _rr(name, typ, rdata):
    return _labels(name) + struct.pack("!HHIH", typ, 0x8001, 120, len(rdata)) + rdata


def mdns_answer():
    inst = "garden-bt-proxy._esphomelib._tcp.local"
    txt = b"".join(bytes([len(x)]) + x for x in (b"version=2026.8.2", b"friendly_name=Garden BT", b"platform=ESP32"))
    recs = [_rr("_esphomelib._tcp.local", 12, _labels(inst)), _rr(inst, 16, txt),
            _rr(inst, 33, struct.pack("!HHH", 0, 0, 6053) + _labels("garden-bt-proxy.local")),
            _rr("garden-bt-proxy.local", 1, socket.inet_aton("10.0.0.7"))]
    return struct.pack("!6H", 0, 0x8400, 0, 1, 0, 3) + b"".join(recs)


def test_parse_dns_and_discover():
    recs = esp.parse_dns(mdns_answer())
    assert ("garden-bt-proxy._esphomelib._tcp.local", 16,
            {"version": "2026.8.2", "friendly_name": "Garden BT", "platform": "ESP32"}) in recs

    class Sock:
        def __init__(self):
            self.sent, self.replies = [], [(mdns_answer(), ("10.0.0.99", 5353))]

        def settimeout(self, _):
            pass

        def setsockopt(self, *a):
            pass

        def sendto(self, data, addr):
            self.sent.append((data, addr))

        def recvfrom(self, _):
            if self.replies:
                return self.replies.pop()
            raise TimeoutError
    s = Sock()
    found = esp.discover(0.5, sock=s)
    assert found == {"10.0.0.7": {"name": "garden-bt-proxy", "kind": "esphome", "version": "2026.8.2",
                                  "friendly_name": "Garden BT", "platform": "ESP32"}}
    assert {a for _, a in s.sent} == {esp.MDNS} and len(s.sent) == len(esp.SERVICES)


# ── device probes against local sockets ──────────────────────────────────────
def serve(handler):
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)

    def run():
        c, _ = srv.accept()
        with c:
            handler(c)
        srv.close()
    threading.Thread(target=run, daemon=True).start()
    return srv.getsockname()[1]


def ota_handler(auth):
    def h(c):
        assert c.recv(5) == esp.OTA_MAGIC
        c.sendall(bytes([0x00, 0x02]))
        c.recv(1)
        c.sendall(bytes([esp.OTA_HEADER_OK, auth]))
    return h


def test_ota_probe_stops_at_auth():
    assert esp.probe_ota("127.0.0.1", serve(ota_handler(esp.OTA_AUTH_OK))) == "open"
    assert esp.probe_ota("127.0.0.1", serve(ota_handler(esp.OTA_AUTH_SHA256))) == "password"


def test_api_probe_plaintext_and_encrypted():
    def plain(c):
        c.recv(64)
        body = b"\x08\x01\x10\x0a\x1a\x1bHomelab (esphome v2026.9.1)\x22\x07homelab"
        c.sendall(b"\x00" + esp._varint(len(body)) + esp._varint(2) + body)
    assert esp.probe_api("127.0.0.1", serve(plain)) == ("plaintext", "Homelab (esphome v2026.9.1)")

    def noise(c):
        c.recv(64)
        c.sendall(b"\x01\x00\x12Bad indicator byte")
    assert esp.probe_api("127.0.0.1", serve(noise)) == ("encrypted", "")
    closed = socket.socket()
    closed.bind(("127.0.0.1", 0))
    port = closed.getsockname()[1]
    closed.close()
    assert esp.probe_api("127.0.0.1", port)[0] == "closed"


class Http:
    def __init__(self, pages):
        self.pages = pages

    def get(self, url, timeout=None, allow_redirects=True, stream=False, verify=True):
        page = self.pages.get(url.split("://", 1)[1].split("/", 1)[1], (404, ""))
        r = HttpResp(*page[:2])
        r.headers = page[2] if len(page) > 2 else {}
        return r


class HttpResp:
    def __init__(self, status, body):
        self.status_code, self.text = status, body if isinstance(body, str) else json.dumps(body)

    def json(self):
        return json.loads(self.text)

    def iter_lines(self, decode_unicode=False):
        return iter(self.text.splitlines())

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def test_web_probe():
    open_ui = Http({"": (200, "<esp-app></esp-app>"),
                    "events": (200, 'event: ping\ndata: {"title":"Watchdog","ota":true}\n')})
    assert esp.probe_web("x", session=open_ui) == ("open", True, "Watchdog")
    assert esp.probe_web("x", session=Http({"": (401, "")})) == ("auth", None, "")
    assert esp.probe_web("x", session=Http({"": (200, "<h1>router</h1>")}))[0] == "other"


def test_esphome_findings_and_dashboard_advisories_dropped():
    d = {"ip": "10.0.0.7", "friendly_name": "Garden", "version": "2024.2.0", "api": "plaintext", "ota": "open",
         "web": "open", "web_ota": True}
    t = cli.esp_target(d)
    assert t.pkgs == [("PyPI", "esphome", "2024.2.0", "esphome firmware", "2024.2.0")]
    assert ids(t.exposures) == [("SIEVE-ESPHOME-API-PLAINTEXT", "esphome firmware", "MEDIUM"),
                                ("SIEVE-ESPHOME-OTA-NO-PASSWORD", "esphome firmware", "HIGH"),
                                ("SIEVE-ESPHOME-WEB-OTA", "esphome firmware", "HIGH")]
    found = [{"summary": "ESPHome vulnerable to remote code execution via arbitrary file write",
              "details": "... the dashboard's edit API ..."},
             {"summary": "ESP-IDF web_server basic auth bypass", "details": ""}]
    assert cli.esp_firmware_only(found, t) == found[1:]
    assert any("dashboard advisories skipped" in n for n in t.notes)
    quiet = cli.esp_target({"ip": "10.0.0.8", "api": "encrypted", "ota": "password", "web": "auth"})
    assert quiet.exposures == [] and quiet.status == "partial" and quiet.pkgs == []


def test_wled():
    http = Http({"json/info": (200, {"ver": "16.0.1", "name": "Kitchen", "arch": "esp32", "brand": "WLED"}),
                 "json/cfg": (200, {"ota": {"lock": False, "aota": True}})})
    d = esp.probe_wled("10.0.0.9", session=http)
    assert esp.is_wled("10.0.0.9", session=http)
    t = cli.esp_target(d)
    assert t.name == "wled:Kitchen (10.0.0.9)" and t.os == "WLED 16.0.1 on esp32"
    assert ids(t.exposures) == [("SIEVE-WLED-OTA-UNLOCKED", "wled firmware", "HIGH")]
    assert "wledota" in t.exposures[0]["summary"]
    locked = esp.probe_wled("10.0.0.9", session=Http({"json/info": (200, {"ver": "16.0.1"}),
                                                       "json/cfg": (200, {"ota": {"lock": True}})}))
    assert cli.esp_target(locked).exposures == []


def test_devices_cli_offline(monkeypatch, capsys):
    monkeypatch.setattr(esp, "discover", lambda s: {"10.0.0.9": {"kind": "wled"}})
    monkeypatch.setattr(esp, "probe_wled", lambda ip, info: {"ip": ip, "kind": "wled", "version": "16.0.1",
                                                             "web": "open", "ota_lock": False})
    rc = cli.main(["devices", "--no-epss", "--cache", "/nonexistent/sieve.db"])
    out = capsys.readouterr().out
    assert rc == cli.EXIT_OK and "SIEVE-WLED-OTA-UNLOCKED" in out and "wled:10.0.0.9" in out


def test_venus():
    secured = Http({"": (200, "<title>Venus GX - SSL certifcate note</title>"),
                    "gui-v2/": (302, "", {"Location": "https://x/auth/login.php?page=/gui-v2/"})})
    assert esp.is_venus("x", session=secured)
    d = esp.probe_venus("x", session=secured, port_open=lambda ip, p: False)
    assert d["gui"] == "login" and cli.esp_target(d).exposures == []
    loose = esp.probe_venus("x", session=Http({"gui-v2/": (200, "<app>")}), port_open=lambda ip, p: p in (502, 1883))
    assert ids(cli.esp_target(loose).exposures) == [("SIEVE-VENUS-MODBUS-OPEN", "venus os", "MEDIUM"),
                                                    ("SIEVE-VENUS-MQTT-PLAINTEXT", "venus os", "MEDIUM"),
                                                    ("SIEVE-VENUS-NO-LOGIN", "venus os", "HIGH")]
