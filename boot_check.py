#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
    boot_check.py - Anti Evil-Maid Attack Monitor

    Original: @JusticeRage
    Updated:  @moscovium-mc

    Detects whether your hard drive was powered on without the OS booting –
    the classic signature of an evil-maid attack (drive duplication, cold-boot,
    interrupted FDE prompt, etc.).

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.

    ---------------------------------------------------------------------------
    Installation (systemd):
      1. cp boot_check.service /etc/systemd/system/
         (update the ExecStart path inside it)
      2. systemctl enable boot_check.service
      3. apt install smartmontools dialog
      4. ./boot_check.py    ← run once to initialise the baseline
    ---------------------------------------------------------------------------
"""

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Optional

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

BOOT_COUNT_FILE = Path("/root/.boot_check")
SERVICE_NAME    = "boot_check.service"

# ---------------------------------------------------------------------------
# Colour helpers
# ---------------------------------------------------------------------------

RED   = "\033[0;31m"
GREEN = "\033[0;32m"
CYAN  = "\033[0;36m"
END   = "\033[0m"

def _c(colour: str, text: str) -> str: return f"{colour}{text}{END}"
def red(t):   return _c(RED,   t)
def green(t): return _c(GREEN, t)
def cyan(t):  return _c(CYAN,  t)

def info(t):    print(f"[ ] {t}")
def success(t): print(f"[{green('*')}] {green(t)}")
def error(t):   print(f"[{red('!')}] {red(t)}", file=sys.stderr)
def warn(t):    print(f"[{red('!')}] {red(t)}")

# ---------------------------------------------------------------------------
# Prerequisite checks
# ---------------------------------------------------------------------------

def check_prerequisites() -> None:
    """Exit with a descriptive message if the environment isn't suitable."""
    if os.geteuid() != 0:
        error("This script must be run as root.")
        sys.exit(1)

    for tool, pkg in [("smartctl", "smartmontools"), ("lsblk", "util-linux"), ("dialog", "dialog")]:
        if shutil.which(tool) is None:
            error(f"{tool!r} is not installed. Run: apt install {pkg}")
            sys.exit(1)

# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    check_prerequisites()

    if not BOOT_COUNT_FILE.exists():
        initialise()
    else:
        check_boot_count()

# ---------------------------------------------------------------------------
# Initialisation
# ---------------------------------------------------------------------------

def initialise() -> None:
    """Create the baseline power-cycle file."""
    result = subprocess.run(
        ["systemctl", "--quiet", "is-enabled", SERVICE_NAME],
        capture_output=True,
    )
    if result.returncode != 0:
        warn(f"Boot Check is NOT enabled in systemd!\n"
             f"    Run: systemctl enable {SERVICE_NAME}")
        return

    init_data: dict[str, int] = {}
    for device in get_hard_drives():
        count = get_power_cycle_count(device)
        if count is not None:
            init_data[device] = count
        else:
            warn(f"Could not read power cycle count for {device} – skipping.")

    BOOT_COUNT_FILE.write_text(json.dumps(init_data, indent=2))
    BOOT_COUNT_FILE.chmod(0o600)
    success("Boot Check initialised. Baseline saved.")

# ---------------------------------------------------------------------------
# Check
# ---------------------------------------------------------------------------

def check_boot_count() -> None:
    """Compare current power-cycle counts against the stored baseline."""
    try:
        state: dict[str, int] = json.loads(BOOT_COUNT_FILE.read_text())
    except (json.JSONDecodeError, OSError) as exc:
        error(f"Could not read state file: {exc}")
        sys.exit(1)

    for device in get_hard_drives():
        if device not in state:
            show_dialog(
                f"WARNING: No baseline data for {device}.\n"
                f"Delete {BOOT_COUNT_FILE} and re-run this script to reinitialise."
            )
            continue

        current = get_power_cycle_count(device)
        if current is None:
            warn(f"Could not read power cycle count for {device}.")
            continue

        # -1 because the current boot doesn't count
        suspicious_boots = current - state[device] - 1

        if suspicious_boots <= 0:
            state[device] = current
        else:
            model = get_drive_model(device) or f"/dev/{device}"
            plural = "s" if suspicious_boots != 1 else ""
            show_dialog(
                f"⚠ EVIL MAID ALERT ⚠\n\n"
                f"{model} was powered on {suspicious_boots} extra time{plural} "
                f"since the last verified boot.\n\n"
                f"Someone may have tampered with your drive."
            )
            state[device] = current

    BOOT_COUNT_FILE.write_text(json.dumps(state, indent=2))

# ---------------------------------------------------------------------------
# Hardware helpers
# ---------------------------------------------------------------------------

def get_hard_drives() -> list[str]:
    """Return device names (e.g. ['sda', 'nvme0n1']) for all physical disks."""
    result = subprocess.run(
        ["lsblk", "-d", "-J"],
        capture_output=True,
        text=True,
        timeout=10,
    )
    try:
        data = json.loads(result.stdout)
        return [
            d["name"]
            for d in data.get("blockdevices", [])
            if d.get("type") == "disk"
        ]
    except (json.JSONDecodeError, KeyError):
        warn("Could not parse lsblk output.")
        return []


def get_drive_model(device: str) -> Optional[str]:
    """Return the human-readable model string for a device, or None."""
    result = subprocess.run(
        ["lsblk", "-S", "-J"],
        capture_output=True,
        text=True,
        timeout=10,
    )
    try:
        data = json.loads(result.stdout)
        for d in data.get("blockdevices", []):
            if d.get("name") == device:
                return d.get("model")
    except (json.JSONDecodeError, KeyError):
        pass
    return None


def get_power_cycle_count(device: str) -> Optional[int]:
    """
    Query SMART data for the Power_Cycle_Count attribute.
    Returns None if it can't be determined.
    """
    result = subprocess.run(
        ["smartctl", "-A", f"/dev/{device}"],
        capture_output=True,
        text=True,
        timeout=15,
    )
    for line in result.stdout.splitlines():
        if "power_cycle_count" in line.lower():
            parts = line.split()
            if parts:
                try:
                    return int(parts[-1])
                except ValueError:
                    pass
    return None

# ---------------------------------------------------------------------------
# Display
# ---------------------------------------------------------------------------

def show_dialog(text: str, width: int = 60) -> None:
    """
    Display a scary full-screen alert on TTY2 at boot, then restore TTY7.
    Uses the dialog --msgbox trick with a red background injected via stdin.
    """
    if not text:
        return

    # Sleep briefly so the display manager doesn't grab TTY2 back immediately
    subprocess.run(["sh", "-c", "sleep 5; chvt 2"], check=False)

    lines_needed = 6 + len(text) // (width - 4)

    dialog_proc = subprocess.Popen(
        "OLDDIALOGRC=$DIALOGRC; "
        "export DIALOGRC=/dev/stdin; "
        f'dialog --clear --msgbox "{text}" {lines_needed} {width}; '
        "export DIALOGRC=$OLDDIALOGRC",
        shell=True,
        stdin=subprocess.PIPE,
    )
    dialog_proc.communicate(input=b"screen_color = (CYAN,RED,ON)\n")

    print(f"[{red('!')}] Press [{red('CTRL+ALT+F7')}] to return to the desktop.")
    subprocess.run(["chvt", "7"], check=False)


# ---------------------------------------------------------------------------

if __name__ == "__main__":
    main()
