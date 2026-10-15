# Exposure findings

Rows with an id starting `SIEVE-` are not advisories: they are ways in that need no CVE. Each one below says what
sieve saw and how to close it. sieve never prints or sends a password, a password hash or any secret it finds.

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

## sieve-secret-in-file
A credential in a plain-text file: an `.env` or compose file, `.netrc`, `.git-credentials`, `.pgpass`, `.npmrc`,
`~/.aws/credentials`, `~/.docker/config.json` without a credential helper, a kubeconfig, or a `password=` line in a
config. Fix: if anyone other than the owner can read it, `chmod 600` first. Then load it from a secret manager (pass,
Vault, Infisical, systemd `LoadCredential=`), or use the tool's credential helper.

## sieve-secret-in-history
A password or token typed on a command line and saved in a shell history (`curl -u user:…`, `mysql -p…`,
`export GH_TOKEN=…`). Fix: rotate it, then delete the line. `HISTCONTROL=ignorespace` (bash) keeps any command that
starts with a space out of the history.

## sieve-secret-in-agent-chat
A secret in an AI coding agent's transcript: it was pasted in, or a tool printed it (`cat .env`, `env`, a config
dump). It was sent to the model provider along with the rest of the chat, and transcripts get synced, shared and
backed up. Fix: rotate it; deleting the transcript alone doesn't take it back.

## sieve-secret-in-agent-config
A token written straight into an agent or MCP server config (`.mcp.json`, `~/.claude.json`, Cursor's or Claude
Desktop's config, Codex's `config.toml`). Configs get copied into repos and shared. Fix: have the MCP server read it
from the environment, or point at a secret manager. An agent's own login store is only reported when someone other
than its owner can read it.

## sieve-secret-private-key
A private key with no passphrase in a home directory (or anywhere, if everyone can read it): a copy of the file is
the key. Fix: `ssh-keygen -p -f <key>` adds a passphrase; `ssh-agent` saves typing it.

## sieve-secret-in-container-env
A credential in a running container's environment. `docker inspect`, `/proc/<pid>/environ`, crash reports and any
library that logs its environment all show it. Fix: Docker or compose secrets (mounted as files), or the image's
`*_FILE` variables (`POSTGRES_PASSWORD_FILE=/run/secrets/db`). Values the image sets itself are not counted.
