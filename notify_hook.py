#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
    notify_hook.py - Binary Tripwire

    Original: @JusticeRage
    Updated:  @moscovium-mc

    Symlink this script over any binary you want to "booby-trap". When an
    intruder runs it (e.g. `id`, `whoami`, `gcc`), notify_hook sends you a
    silent alert and then transparently executes the real binary so nothing
    looks suspicious.

    Example:
      ln -s /path/to/notify_hook.py /usr/local/bin/id

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
"""

import os
import re
import shutil
import subprocess
import sys
from typing import Optional

# ---------------------------------------------------------------------------
# Whitelist
# Processes listed here will NOT trigger an alert. Regex allowed.
# ---------------------------------------------------------------------------

CALLER_WHITELIST: list[str] = [
    # r"cron",
    # r"nagios",
    # r"/usr/lib/update-notifier/",
]

# ---------------------------------------------------------------------------
# Notification backends
# Choose one (or write your own notify_callback below).
# ---------------------------------------------------------------------------

# --- Signal (via signal-cli) ------------------------------------------------
SIGNAL_CLI        = "/usr/local/bin/signal-cli"
SIGNAL_CLI_CONFIG = "/opt/signal-cli/.config"
SIGNAL_SENDER     = "+1XXXXXXXXXX"   # Your registered Signal number
SIGNAL_RECIPIENT  = "+1XXXXXXXXXX"   # Where to send alerts

# --- Slack webhook ----------------------------------------------------------
SLACK_WEBHOOK_URL = ""               # e.g. https://hooks.slack.com/services/…

# --- Discord webhook --------------------------------------------------------
DISCORD_WEBHOOK_URL = ""             # e.g. https://discord.com/api/webhooks/…

# --- Generic HTTP POST webhook ----------------------------------------------
GENERIC_WEBHOOK_URL = ""             # Any URL; payload = {"text": "…"}

# ---------------------------------------------------------------------------
# EDIT HERE: pick your delivery method
# ---------------------------------------------------------------------------

def notify_callback(message: str) -> None:
    """Send the alert. Edit/replace this with your preferred backend."""

    # --- Signal ---
    if shutil.which("signal-cli") and SIGNAL_SENDER and SIGNAL_RECIPIENT:
        subprocess.Popen(
            ["signal-cli", "--config", SIGNAL_CLI_CONFIG,
             "-u", SIGNAL_SENDER, "send", SIGNAL_RECIPIENT, "-m", message],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        ).communicate()
        return

    # --- Slack ---
    if SLACK_WEBHOOK_URL:
        _http_post(SLACK_WEBHOOK_URL, {"text": message})
        return

    # --- Discord ---
    if DISCORD_WEBHOOK_URL:
        _http_post(DISCORD_WEBHOOK_URL, {"content": message})
        return

    # --- Generic webhook ---
    if GENERIC_WEBHOOK_URL:
        _http_post(GENERIC_WEBHOOK_URL, {"text": message})
        return

    # --- Fallback: write to syslog ---
    try:
        import syslog
        syslog.syslog(syslog.LOG_WARNING, f"notify_hook: {message}")
    except ImportError:
        pass


def _http_post(url: str, payload: dict) -> None:
    """Best-effort HTTP POST using whatever's available."""
    import json as _json
    data = _json.dumps(payload).encode()
    headers = "Content-Type: application/json"

    if shutil.which("curl"):
        subprocess.Popen(
            ["curl", "-s", "-X", "POST", url,
             "-H", headers, "-d", data.decode()],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        ).communicate()
    elif shutil.which("wget"):
        subprocess.Popen(
            ["wget", "-q", "--method=POST", url,
             f"--header={headers}", f"--body-data={data.decode()}"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        ).communicate()

# ---------------------------------------------------------------------------
# Internals – no need to touch below here
# ---------------------------------------------------------------------------

INTERPRETERS = frozenset([
    "/bin/sh", "/bin/bash", "/usr/bin/bash",
    "/usr/bin/perl", "/usr/bin/python3", "/usr/bin/python",
])


def get_caller() -> Optional[str]:
    """Return the name/path of the process that invoked us."""
    pid = os.getppid()
    cmdline_path = f"/proc/{pid}/cmdline"
    try:
        with open(cmdline_path, "r") as fh:
            parts = fh.read().split("\x00")
        # If called via an interpreter, return the script name instead
        if parts and parts[0] in INTERPRETERS and len(parts) > 1:
            for candidate in parts[1:]:
                if candidate and os.path.exists(candidate):
                    return candidate
        return parts[0] if parts else None
    except OSError:
        return None


def get_ssh_origin() -> Optional[str]:
    """Return the source IP if this session came in over SSH."""
    ssh_conn = os.environ.get("SSH_CONNECTION", "")
    parts = ssh_conn.split()
    return parts[0] if parts else None


def get_hostname() -> Optional[str]:
    try:
        return open("/etc/hostname").read().strip()
    except OSError:
        return None


def find_real_binary(name: str) -> Optional[str]:
    """
    Search PATH for the real binary, skipping /usr/local/bin (where symlinks
    typically live) so we don't create an infinite loop.
    """
    for directory in os.environ.get("PATH", "").split(":"):
        if "/local/" in directory:
            continue
        candidate = os.path.join(directory, name)
        if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            return candidate

    # Nothing found – print a realistic-looking error and bail
    print(f"-bash: {name}: command not found", file=sys.stderr)
    return None


def daemonize_and_notify(message: str) -> None:
    """
    Fork a daemon to send the notification in the background so the user
    sees no latency when running the hooked binary.
    """
    sys.stdout.flush()
    sys.stderr.flush()

    try:
        pid = os.fork()
        if pid > 0:
            return   # parent: go run the real binary
    except OSError as exc:
        # Non-fatal – we still run the real binary
        print(f"fork error: {exc}", file=sys.stderr)
        return

    os.chdir("/")
    os.setsid()
    os.umask(0)

    try:
        pid2 = os.fork()
        if pid2 > 0:
            sys.exit(0)
    except OSError as exc:
        print(f"fork2 error: {exc}", file=sys.stderr)
        sys.exit(1)

    notify_callback(message)
    sys.exit(0)


def build_alert_message(program: str, caller: Optional[str]) -> str:
    hostname = get_hostname()
    origin   = get_ssh_origin()
    user     = os.environ.get("USER", os.environ.get("LOGNAME", "unknown"))

    parts = [f"⚠ Tripwire: {program!r} invoked"]
    if hostname:
        parts.append(f"on {hostname}")
    parts.append(f"by {user!r}")
    if origin:
        parts.append(f"from {origin}")
    if caller:
        parts.append(f"(via {caller})")
    return " ".join(parts)


def main() -> None:
    program = os.path.basename(sys.argv[0])

    # Check whitelist
    caller = get_caller()
    should_notify = True
    if caller:
        for pattern in CALLER_WHITELIST:
            if re.search(pattern, caller):
                should_notify = False
                break

    if should_notify:
        daemonize_and_notify(build_alert_message(program, caller))

    # Find and execute the real binary transparently
    real = find_real_binary(program)
    if real and os.path.exists(real):
        args = [real] + sys.argv[1:]
        # Use execv so we replace ourselves – no extra process in ps output
        os.execv(real, args)
    # execv only returns on error; fall through to sys.exit
    sys.exit(1)


if __name__ == "__main__":
    main()
