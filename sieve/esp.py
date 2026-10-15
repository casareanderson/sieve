"""`sieve esp`: ESPHome devices (ESP32, ESP8266, RP2040, ...) on the network.

A flashed board has no package list to read, but it does say which ESPHome release built it: in its mDNS TXT
record (`version=2026.8.2`) and, when the native API is unencrypted, in the API hello. That release is matched
against OSV's PyPI `esphome` advisories, which cover both the firmware and the dashboard; the dashboard ones don't
apply to a flashed board and are dropped.

Then four read-only probes, each a few bytes and then a hang-up:

  api   port 6053: a plaintext HelloRequest. A plaintext reply = no encryption key (and gives the version);
        an encrypted-frame reply = encrypted.
  ota   port 3232: the OTA handshake up to the point where the board says whether it wants a password, then
        disconnect. Nothing is uploaded; the board logs an aborted OTA.
  web   port 80: GET /. 401 = has a login; the ESPHome page without one = open. When open, the first event on
        /events says whether the page accepts firmware uploads.

ESP-IDF's own advisories (Bluetooth, Wi-Fi, TEE) are not checked: a board doesn't announce its ESP-IDF version.
"""
import json
import re
import socket
import struct
import time

import requests

SERVICE = "_esphomelib._tcp.local"
SERVICES = {"_esphomelib._tcp.local": "esphome", "_wled._tcp.local": "wled"}
MDNS = ("224.0.0.251", 5353)
OTA_MAGIC = bytes([0x6C, 0x26, 0xF7, 0x5C, 0x45])
OTA_AUTH_OK, OTA_AUTH_MD5, OTA_AUTH_SHA256 = 0x41, 0x01, 0x02
OTA_HEADER_OK, OTA_COMPRESSION, OTA_FEATURE_FLAGS = 0x40, 0x46, 0x48
OTA_ENCRYPTION_REQUIRED = 0x94
VERSION = re.compile(r"esphome v?(\d{4}\.\d+\.\d+\S*)", re.IGNORECASE)


# ── mDNS ─────────────────────────────────────────────────────────────────────
def _name(data, i, depth=0):
    labels = []
    while i < len(data):
        n = data[i]
        if n == 0:
            return ".".join(labels), i + 1
        if n & 0xC0 == 0xC0:
            if depth > 10 or i + 1 >= len(data):
                break
            rest, _ = _name(data, ((n & 0x3F) << 8) | data[i + 1], depth + 1)
            return ".".join(labels + ([rest] if rest else [])), i + 2
        labels.append(data[i + 1:i + 1 + n].decode("utf-8", "replace"))
        i += 1 + n
    raise ValueError("bad DNS name")


def parse_dns(data):
    """A DNS message → [(name, type, rdata)] for every answer/authority/additional record. rdata: PTR/SRV target
    name, TXT {key: value}, A dotted quad; others raw bytes."""
    if len(data) < 12:
        return []
    qd, an, ns, ar = struct.unpack("!4H", data[4:12])
    i = 12
    for _ in range(qd):
        _, i = _name(data, i)
        i += 4
    out = []
    for _ in range(an + ns + ar):
        name, i = _name(data, i)
        if i + 10 > len(data):
            break
        typ, _cls, _ttl, ln = struct.unpack("!HHIH", data[i:i + 10])
        i += 10
        rd = data[i:i + ln]
        if typ == 12:
            val = _name(data, i)[0]
        elif typ == 33:
            val = _name(data, i + 6)[0]
        elif typ == 16:
            val, j = {}, 0
            while j < len(rd):
                s = rd[j + 1:j + 1 + rd[j]].decode("utf-8", "replace")
                j += 1 + rd[j]
                k, _, v = s.partition("=")
                if k:
                    val[k.lower()] = v
        elif typ == 1 and ln == 4:
            val = socket.inet_ntoa(rd)
        else:
            val = rd
        out.append((name.lower(), typ, val))
        i += ln
    return out


def _query(service):
    q = b"".join(bytes([len(p)]) + p.encode() for p in service.split(".")) + b"\x00"
    return struct.pack("!6H", 0, 0, 1, 0, 0, 0) + q + struct.pack("!HH", 12, 0x8001)   # PTR, QU bit


def discover(seconds=3.0, sock=None, services=SERVICES):
    """→ {ip: {"kind", "name", "friendly_name", "version", "platform", "board", "api_encryption", ...}} for every
    ESPHome or WLED device that answers an mDNS browse within `seconds`."""
    s = sock or socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    found = {}
    try:
        s.settimeout(0.3)
        s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 1)
        start = time.monotonic()
        end, sends = start + seconds, [start + k for k in range(max(1, int(seconds)))]   # Wi-Fi boards miss some
        while time.monotonic() < end:
            if sends and time.monotonic() >= sends[0]:
                sends.pop(0)
                for svc in services:
                    s.sendto(_query(svc), MDNS)
            try:
                data, (src, _) = s.recvfrom(9000)
            except TimeoutError:
                continue
            except OSError:
                break
            try:
                recs = parse_dns(data)
            except (ValueError, IndexError, struct.error):
                continue
            for svc, kind in services.items():
                insts = {v for n, t, v in recs if t == 12 and n == svc} or \
                        {n for n, t, v in recs if t in (16, 33) and n.endswith("." + svc)}
                for inst in insts:
                    txt = next((v for n, t, v in recs if t == 16 and n == inst), {})
                    host = next((v for n, t, v in recs if t == 33 and n == inst), "")
                    ip = next((v for n, t, v in recs if t == 1 and n == host.lower()), src)
                    d = found.setdefault(ip, {"name": inst[:-len(svc) - 1], "kind": kind})
                    d.update({k: v for k, v in txt.items() if k != "kind"})
    finally:
        if sock is None:
            s.close()
    return found


# ── probes ───────────────────────────────────────────────────────────────────
def _varint(n):
    out = b""
    while True:
        b = n & 0x7F
        n >>= 7
        out += bytes([b | (0x80 if n else 0)])
        if not n:
            return out


def _read_varint(buf, i):
    n = shift = 0
    while i < len(buf):
        b = buf[i]
        n |= (b & 0x7F) << shift
        i += 1
        if not b & 0x80:
            return n, i
        shift += 7
    raise ValueError("short varint")


def _fields(buf):
    """Protobuf → {field number: value} for varint and length-delimited fields."""
    out, i = {}, 0
    while i < len(buf):
        key, i = _read_varint(buf, i)
        f, wt = key >> 3, key & 7
        if wt == 0:
            out[f], i = _read_varint(buf, i)
        elif wt == 2:
            n, i = _read_varint(buf, i)
            out[f] = buf[i:i + n]
            i += n
        else:
            break
    return out


def hello_request():
    body = b"\x0a" + _varint(5) + b"sieve" + b"\x10\x01" + b"\x18\x0a"    # client_info, api 1.10
    return b"\x00" + _varint(len(body)) + _varint(1) + body


def parse_hello(data):
    """The first bytes back from port 6053 → ("plaintext", server_info) | ("encrypted", "") | (None, "")."""
    if not data:
        return None, ""
    if data[0] == 0x01:
        return "encrypted", ""
    if data[0] != 0x00:
        return None, ""
    try:
        n, i = _read_varint(data, 1)
        typ, i = _read_varint(data, i)
        f = _fields(data[i:i + n]) if typ == 2 else {}
    except ValueError:
        return "plaintext", ""
    info = f.get(3, b"")
    return "plaintext", info.decode("utf-8", "replace") if isinstance(info, bytes) else ""


def _recv(s, n, deadline):
    buf = b""
    while len(buf) < n and time.monotonic() < deadline:
        try:
            chunk = s.recv(n - len(buf))
        except TimeoutError:
            continue
        if not chunk:
            break
        buf += chunk
    return buf


def probe_api(ip, port=6053, timeout=3.0):
    try:
        with socket.create_connection((ip, port), timeout=timeout) as s:
            s.sendall(hello_request())
            deadline = time.monotonic() + timeout
            data = b""
            while time.monotonic() < deadline and len(data) < 512:
                try:
                    chunk = s.recv(512)
                except TimeoutError:
                    break
                if not chunk:
                    break
                data += chunk
                if data[:1] == b"\x01" or (data[:1] == b"\x00" and len(data) > 8):
                    break
            return parse_hello(data)
    except OSError:
        return "closed", ""


def probe_ota(ip, port=3232, timeout=3.0):
    """→ "open" (no password) | "password" | "encrypted" | "closed" | "unknown". Stops before any upload."""
    try:
        with socket.create_connection((ip, port), timeout=timeout) as s:
            deadline = time.monotonic() + timeout
            s.sendall(OTA_MAGIC)
            ok = _recv(s, 2, deadline)
            if len(ok) < 2 or ok[0] != 0x00:
                return "unknown"
            s.sendall(bytes([0x02]))                     # client features: SHA-256 auth, nothing else
            feat = _recv(s, 1, deadline)
            if not feat:
                return "unknown"
            if feat[0] == OTA_ENCRYPTION_REQUIRED:
                return "encrypted"
            if feat[0] == OTA_FEATURE_FLAGS:
                _recv(s, 1, deadline)
            elif feat[0] not in (OTA_HEADER_OK, OTA_COMPRESSION):
                return "unknown"
            auth = _recv(s, 1, deadline)
            if not auth:
                return "unknown"
            if auth[0] == OTA_AUTH_OK:
                return "open"
            if auth[0] in (OTA_AUTH_MD5, OTA_AUTH_SHA256):
                return "password"
            return "encrypted" if auth[0] == OTA_ENCRYPTION_REQUIRED else "unknown"
    except OSError:
        return "closed"


def probe_web(ip, port=80, timeout=3.0, session=None):
    """→ (state, web_ota, title): state "open" | "auth" | "closed" | "other"; web_ota True/False/None; title is
    the device's friendly name from the first /events ping ("" if not seen)."""
    http = session or requests
    base = f"http://{ip}" + ("" if port == 80 else f":{port}")
    try:
        r = http.get(base + "/", timeout=timeout, allow_redirects=False)
    except requests.RequestException:
        return "closed", None, ""
    if r.status_code == 401:
        return "auth", None, ""
    if r.status_code != 200 or not re.search(r"esp-app|esphome", r.text or "", re.IGNORECASE):
        return "other", None, ""
    web_ota, title = None, ""
    try:
        with http.get(base + "/events", timeout=timeout, stream=True) as ev:
            seen, deadline = 0, time.monotonic() + timeout
            for line in ev.iter_lines(decode_unicode=True):
                seen += 1
                if line and line.startswith("data:") and '"ota"' in line:
                    ping = json.loads(line[5:])
                    web_ota, title = bool(ping.get("ota")), str(ping.get("title") or "")[:64]
                    break
                if seen > 40 or time.monotonic() > deadline:
                    break
    except (requests.RequestException, ValueError):
        pass
    return "open", web_ota, title


def probe_wled(ip, info=None, timeout=3.0, session=None):
    """WLED: /json/info (version, name, chip) and the `ota` block of /json/cfg (is flashing locked?)."""
    http = session or requests
    d = dict(info or {})
    d.update(ip=ip, kind="wled")
    try:
        i = http.get(f"http://{ip}/json/info", timeout=timeout).json()
        d["version"], d["friendly_name"], d["platform"] = str(i.get("ver") or ""), i.get("name") or "", i.get("arch") or ""
    except (requests.RequestException, ValueError, AttributeError):
        d["web"] = "closed"
        return d
    try:
        r = http.get(f"http://{ip}/json/cfg", timeout=timeout)
        ota = r.json().get("ota") if r.status_code == 200 else None
    except (requests.RequestException, ValueError, AttributeError):
        ota = None
    d["web"] = "open"
    if isinstance(ota, dict):
        d["ota_lock"], d["arduino_ota"] = bool(ota.get("lock")), bool(ota.get("aota"))
    return d


def is_wled(ip, timeout=3.0, session=None):
    try:
        i = (session or requests).get(f"http://{ip}/json/info", timeout=timeout).json()
        return isinstance(i, dict) and i.get("brand") == "WLED"
    except (requests.RequestException, ValueError):
        return False


def _open(ip, port, timeout=2.0):
    try:
        socket.create_connection((ip, port), timeout=timeout).close()
        return True
    except OSError:
        return False


def is_venus(ip, timeout=3.0, session=None):
    """Victron Venus OS (Cerbo GX, or a Raspberry Pi running it): its landing page title."""
    try:
        r = (session or requests).get(f"http://{ip}/", timeout=timeout)
        return "Venus GX" in (r.text or "")
    except requests.RequestException:
        return False


def probe_venus(ip, timeout=3.0, session=None, port_open=None):
    """Venus OS: does the Remote Console (gui-v2) ask for a login, and are Modbus TCP (502) or plaintext MQTT
    (1883, no auth) reachable? Both are off in the default 'Secured' security profile."""
    import warnings
    http, port_open = session or requests, port_open or _open
    d = {"ip": ip, "kind": "venus"}
    try:
        with warnings.catch_warnings():                 # its certificate is self-signed by design
            warnings.simplefilter("ignore")
            r = http.get(f"https://{ip}/gui-v2/", timeout=timeout, allow_redirects=False, verify=False)
        loc = r.headers.get("Location", "") if hasattr(r, "headers") else ""
        d["gui"] = "login" if r.status_code in (301, 302) and "login" in loc else \
            "open" if r.status_code == 200 else "other"
    except requests.RequestException:
        d["gui"] = "closed"
    d["modbus"], d["mqtt_plain"], d["ssh"] = port_open(ip, 502), port_open(ip, 1883), port_open(ip, 22)
    return d


def probe(ip, info=None, ports=None):
    """mDNS info (may be empty) + the three probes → one device dict."""
    ports = ports or {}
    d = dict(info or {})
    d["ip"] = ip
    d["api"], server_info = probe_api(ip, ports.get("api", 6053))
    if not d.get("version"):
        m = VERSION.search(server_info)
        if m:
            d["version"] = m.group(1)
    if server_info and not d.get("friendly_name"):
        d["server_info"] = server_info
    d["ota"] = probe_ota(ip, ports.get("ota", 3232))
    d["web"], d["web_ota"], title = probe_web(ip, ports.get("web", 80))
    if title and not d.get("friendly_name"):
        d["friendly_name"] = title
    return d
