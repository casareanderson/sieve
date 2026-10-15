# Exposure findings

Rows with an id starting `SIEVE-` are not advisories: they are ways in that need no CVE. Each one below says what
sieve saw and how to close it. sieve never prints or sends a password or a password hash.

## sieve-default-password
An account still has the default password of the image it came from (for example `pi` / `raspberry` on Raspberry
Pi OS before April 2022, `root` / `dietpi`, `root` / `1234` on Armbian's first boot). These are the first guesses
of every ssh scanner on the internet. Fix: `passwd <user>`, or `passwd -l <user>` if nobody logs in as it.

## sieve-empty-password
The account has no password at all. Fix: `passwd -l <user>` (lock) or set one.

## sieve-root-ssh-password
root has a usable password **and** sshd accepts it (`PermitRootLogin yes` with password or keyboard-interactive
logins on). Fix: `PermitRootLogin prohibit-password` in `/etc/ssh/sshd_config` (or a file in `sshd_config.d/`,
which is read first), then `systemctl reload ssh`. Make sure your key works first.

## sieve-ssh-empty-passwords
`PermitEmptyPasswords yes`: sshd lets anyone into an account that has no password. Fix: remove the line.

## sieve-weak-password-hash
The password is stored as DES or MD5 crypt, which a stolen `/etc/shadow` gives up in seconds to minutes. Fix:
`passwd <user>`; the new hash uses the system default (yescrypt or SHA-512).

## sieve-root-password
root's password works, though not over ssh. Fine if something needs it (the Proxmox web UI logs in as `root@pam`);
otherwise `passwd -l root` locks it and key-based root logins keep working.

## sieve-esphome-api-plaintext
The ESPHome native API (port 6053) has no encryption key: anyone on the network can read and switch everything.
Fix: add `api: encryption: key: <base64>` (generate one on esphome.io), flash, then re-adopt in Home Assistant.

## sieve-esphome-ota-no-password
Port 3232 accepts new firmware without a password. Fix: `ota: - platform: esphome` with `password:` (or ESPHome's
OTA encryption), then flash.

## sieve-esphome-web-no-auth
The `web_server` page has no login. Fix: `web_server: auth: {username: …, password: …}`, or drop `web_server`.

## sieve-esphome-web-ota
The web page has no login **and** accepts firmware uploads. Fix: add `auth:` and remove the `web_server` OTA
platform.

## sieve-wled-ota-unlocked
WLED's OTA is not locked: anyone on the network can flash it at `http://<ip>/update`, and ArduinoOTA (if on)
uses the default password `wledota`. Fix: Config → Security & Updates: set a settings PIN, tick "OTA lock" with a
password, untick ArduinoOTA.

## sieve-venus-no-login
Victron's Remote Console opens without a password. Fix: Settings → General → Security profile → Secured.

## sieve-venus-modbus-open
Modbus TCP (502) has no authentication and allows writes. Fix: turn the Modbus TCP server off unless something
needs it, and then firewall it to that one client.

## sieve-venus-mqtt-plaintext
MQTT on 1883 without TLS or a password ("Weak"/"Unsecured" profile). Fix: Security profile → Secured (MQTT moves
to TLS on 8883 with the GX password).
