#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
    listurl.py

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
"""

import argparse
import os
import queue
import re
import sys
import threading
from urllib.parse import urlparse, urljoin

# ---------------------------------------------------------------------------
# Optional third-party imports
# ---------------------------------------------------------------------------

try:
    from bs4 import BeautifulSoup
except ImportError:
    print(
        "[\033[91m!\033[0m] BeautifulSoup4 is not installed!\n"
        "       Run: \033[93mpip install beautifulsoup4\033[0m"
    )
    sys.exit(1)

try:
    import requests
    from requests.adapters import HTTPAdapter
    from urllib3.util.retry import Retry
except ImportError:
    print(
        "[\033[91m!\033[0m] Requests is not installed!\n"
        "       Run: \033[93mpip install requests\033[0m"
    )
    sys.exit(1)

# ---------------------------------------------------------------------------
# Globals (populated after argument parsing)
# ---------------------------------------------------------------------------

ARGS = None
COOKIES = None
PRINT_QUEUE: "queue.Queue[str | None]" = queue.Queue()

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

IGNORED_EXTENSIONS = frozenset(
    [".pdf", ".jpg", ".jpeg", ".png", ".gif", ".svg",
     ".doc", ".docx", ".eps", ".wav", ".mp3", ".mp4",
     ".zip", ".tar", ".gz", ".bz2", ".7z", ".exe",
     ".dmg", ".pkg", ".deb", ".rpm", ".iso", ".bin"]
)

USER_AGENT = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/124.0.0.0 Safari/537.36"
    )
}

# ---------------------------------------------------------------------------
# Colour helpers
# ---------------------------------------------------------------------------

GREEN  = "\033[92m"
ORANGE = "\033[93m"
RED    = "\033[91m"
END    = "\033[0m"

def red(t):    return RED + t + END
def orange(t): return ORANGE + t + END
def green(t):  return GREEN + t + END
def error(t):  return f"[{red('!')}] {red('Error: ' + t)}"
def warning(t):return f"[{orange('*')}] Warning: {t}"
def success(t):return f"[{green('*')}] {green(t)}"
def info(t):   return f"[ ] {t}"

# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------

def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Map a website by recursively grabbing all its URLs.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--max-depth", "-m", default=3, type=int,
                        help="Maximum crawl depth (default: 3).")
    parser.add_argument("--threads", "-t", default=10, type=int,
                        help="Number of worker threads (default: 10).")
    parser.add_argument("--url", "-u", required=True,
                        help="Starting URL.")
    parser.add_argument("--external", "-e", action="store_true", default=False,
                        help="Follow external links.")
    parser.add_argument("--subdomains", "-d", action="store_true", default=False,
                        help="Include subdomains in scope.")
    parser.add_argument("-c", "--cookie", action="append",
                        help='Cookie to include. Example: -c "session=abc123". '
                             'May be specified multiple times.')
    parser.add_argument("--exclude-regexp", "-r",
                        help="Regexp matching URLs to ignore (partial match).")
    parser.add_argument("--show-regexp", "-s",
                        help="Only display URLs matching this regexp (partial match).")
    parser.add_argument("--no-certificate-check", "-n",
                        action="store_false", dest="verify_ssl", default=True,
                        help="Disable SSL certificate verification.")
    parser.add_argument("--output-file", "-o",
                        help="Write discovered URLs to this file instead of stdout.")
    parser.add_argument("--timeout", default=10, type=int,
                        help="Per-request timeout in seconds (default: 10).")
    parser.add_argument("--verbose", "-v", action="count", default=0,
                        help="Increase verbosity. May be specified multiple times.")

    args = parser.parse_args()

    # Normalise the URL
    if not args.url.startswith(("http://", "https://")):
        args.url = "https://" + args.url

    # Parse cookies
    if args.cookie:
        global COOKIES
        cookie_dict = {}
        for c in args.cookie:
            if c.count("=") < 1:
                print(error(f"Cookie must be key=value, got: {c!r}"))
                sys.exit(1)
            k, v = c.split("=", 1)
            cookie_dict[k.strip()] = v.strip()
        COOKIES = requests.utils.cookiejar_from_dict(cookie_dict)

    if args.output_file and os.path.exists(args.output_file):
        print(error(f"{args.output_file} already exists. Aborting to avoid overwrite."))
        sys.exit(1)

    return args


# ---------------------------------------------------------------------------
# Printer thread – single writer to stdout
# ---------------------------------------------------------------------------

class PrinterThread(threading.Thread):
    def __init__(self, q: queue.Queue) -> None:
        super().__init__(daemon=True)
        self.q = q
        self.alive = True

    def run(self) -> None:
        while True:
            try:
                msg = self.q.get(timeout=1)
                if msg is None:           # sentinel
                    return
                if msg.endswith("\r"):
                    print(msg, end="", flush=True)
                else:
                    print(msg)
                self.q.task_done()
            except queue.Empty:
                if not self.alive:
                    return

    def stop(self) -> None:
        self.alive = False
        self.q.put(None)


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

class InputParameter:
    """Represents a discovered HTML form field."""

    def __init__(self, name: str, value: str, param_type: str) -> None:
        self.name = name
        self.value = value
        self.type = param_type.upper()

    def __str__(self) -> str:
        return f"{self.name} ({self.type})"

    def __eq__(self, other: object) -> bool:
        return isinstance(other, InputParameter) and self.name == other.name

    def __hash__(self) -> int:
        return hash(self.name)


class GrabbedURL:
    """An URL discovered during crawling."""

    def __init__(self, url: str, method: str = "GET") -> None:
        if url is None:
            raise ValueError("URL cannot be None")
        self.url = url
        self.method = method.upper()
        self.parameters: "list[InputParameter] | None" = None

    def __str__(self) -> str:
        pad = " " if self.method == "GET" else ""
        base = f"[{self.method}]{pad} {self.url}"
        if self.parameters:
            base += f" (params: {', '.join(str(p) for p in self.parameters)})"
        return base

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, GrabbedURL):
            return False
        return self.url == other.url and self.method == other.method

    def __hash__(self) -> int:
        return hash((self.url, self.method))


# ---------------------------------------------------------------------------
# HTTP session factory
# ---------------------------------------------------------------------------

def create_session() -> requests.Session:
    session = requests.Session()
    session.headers.update(USER_AGENT)
    session.verify = ARGS.verify_ssl

    # Retry on transient errors
    retry = Retry(
        total=3,
        backoff_factor=0.5,
        status_forcelist=[429, 500, 502, 503, 504],
        allowed_methods=["GET", "POST"],
    )
    adapter = HTTPAdapter(max_retries=retry)
    session.mount("http://",  adapter)
    session.mount("https://", adapter)

    if COOKIES:
        session.cookies = COOKIES

    return session


# ---------------------------------------------------------------------------
# URL processing helpers
# ---------------------------------------------------------------------------

def process_url(url: str, parent_url: str) -> "str | None":
    """
    Normalise `url` relative to `parent_url`. Returns None if the URL should
    be skipped (external, wrong scheme, excluded extension, user regexp).
    """
    parent = urlparse(parent_url)

    # Resolve relative URLs
    if not url.startswith(("http://", "https://", "//")):
        url = urljoin(f"{parent.scheme}://{parent.netloc}", url)

    parsed = urlparse(url)

    # Only HTTP(S)
    if parsed.scheme not in ("http", "https"):
        return None

    # Strip fragment
    url = url.split("#")[0].rstrip("?")

    # Skip ignored extensions
    path = parsed.path
    if "." in path:
        ext = path[path.rfind("."):].lower().split("?")[0]
        if ext in IGNORED_EXTENSIONS:
            if ARGS.verbose > 1:
                PRINT_QUEUE.put(info(f"Skipping static resource: {url}"))
            return None

    # Scope check
    same_host = parsed.netloc == parent.netloc
    is_subdomain = parsed.netloc.endswith("." + parent.netloc) or \
                   parsed.netloc.endswith(parent.netloc)

    if not same_host:
        if ARGS.external:
            pass  # allowed explicitly
        elif ARGS.subdomains and is_subdomain:
            pass  # subdomains allowed
        else:
            if ARGS.verbose > 1:
                PRINT_QUEUE.put(info(f"Out-of-scope: {parsed.netloc}"))
            return None

    # User exclusion regexp
    if ARGS.exclude_regexp and re.search(ARGS.exclude_regexp, url):
        if ARGS.verbose > 1:
            PRINT_QUEUE.put(info(f"Excluded by regexp: {url}"))
        return None

    return url or None


# ---------------------------------------------------------------------------
# HTML extraction
# ---------------------------------------------------------------------------

def extract_urls(html: str, page_url: str) -> "set[GrabbedURL]":
    soup = BeautifulSoup(html, "html.parser")
    urls: set[GrabbedURL] = set()

    # <a href="…">
    for tag in soup.find_all("a", href=True):
        href = tag["href"].strip()
        if not href or href.startswith(("javascript:", "mailto:", "tel:")):
            continue
        normalized = process_url(href, page_url)
        if normalized:
            try:
                urls.add(GrabbedURL(normalized))
            except ValueError:
                pass

    # <form action="…" method="…">
    for form in soup.find_all("form"):
        action = form.get("action", page_url).strip()
        method = form.get("method", "GET").strip()
        if action.startswith(("javascript:", "mailto:")):
            continue
        normalized = process_url(action, page_url)
        if normalized:
            try:
                grabbed = GrabbedURL(normalized, method)
                params = [
                    InputParameter(
                        inp["name"],
                        inp.get("value", ""),
                        inp.get("type", "text"),
                    )
                    for inp in form.find_all("input")
                    if inp.get("name")
                ]
                if params:
                    grabbed.parameters = params
                urls.add(grabbed)
            except ValueError:
                pass

    return urls


# ---------------------------------------------------------------------------
# Worker thread
# ---------------------------------------------------------------------------

class RequesterThread(threading.Thread):
    def __init__(
        self,
        in_q: queue.Queue,
        out_q: queue.Queue,
    ) -> None:
        super().__init__(daemon=True)
        self.session = create_session()
        self.iq = in_q
        self.oq = out_q

    def run(self) -> None:
        while True:
            try:
                grabbed: GrabbedURL = self.iq.get(block=False)
            except queue.Empty:
                return

            try:
                if ARGS.verbose > 0:
                    PRINT_QUEUE.put(info(f"→ {grabbed.url}"))

                if grabbed.method == "GET":
                    r = self.session.get(grabbed.url, timeout=ARGS.timeout)
                else:
                    r = self.session.post(grabbed.url, timeout=ARGS.timeout)

                if r.status_code != 200:
                    if ARGS.verbose > 0:
                        PRINT_QUEUE.put(
                            warning(f"HTTP {r.status_code} for {grabbed.url}")
                        )
                    self.iq.task_done()
                    continue

                for found in extract_urls(r.text, grabbed.url):
                    self.oq.put(found)

            except requests.exceptions.SSLError as exc:
                PRINT_QUEUE.put(
                    error(f"SSL error on {grabbed.url}: {exc}. "
                          f"Try --no-certificate-check")
                )
            except requests.exceptions.ConnectionError as exc:
                if ARGS.verbose > 0:
                    PRINT_QUEUE.put(warning(f"Connection error: {exc}"))
            except requests.exceptions.Timeout:
                if ARGS.verbose > 0:
                    PRINT_QUEUE.put(warning(f"Timeout: {grabbed.url}"))
            except requests.RequestException as exc:
                PRINT_QUEUE.put(warning(f"Request failed: {exc}"))
            finally:
                self.iq.task_done()


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    global ARGS, PRINT_QUEUE
    ARGS = parse_arguments()

    in_q:    queue.Queue = queue.Queue()
    out_q:   queue.Queue = queue.Queue()
    PRINT_QUEUE           = queue.Queue()

    printer = PrinterThread(PRINT_QUEUE)
    printer.start()

    # Seed with the root URL
    root = GrabbedURL(ARGS.url)
    in_q.put(root)
    seed = RequesterThread(in_q, out_q)
    seed.run()   # synchronous for the first fetch

    found: set[GrabbedURL] = {root}

    try:
        for depth in range(ARGS.max_depth):
            PRINT_QUEUE.put(success(f"Started crawling at depth {depth + 1}."))

            # Drain the output queue from the previous round
            round_urls: set[GrabbedURL] = set()
            while True:
                try:
                    round_urls.add(out_q.get_nowait())
                    out_q.task_done()
                except queue.Empty:
                    break

            new_urls = round_urls - found
            if not new_urls:
                PRINT_QUEUE.put(info("No new URLs this round. Done crawling."))
                break

            for u in new_urls:
                in_q.put(u)
            found |= new_urls

            total = in_q.qsize()
            workers = [
                RequesterThread(in_q, out_q)
                for _ in range(min(ARGS.threads, total or 1))
            ]
            for w in workers:
                w.start()
            for w in workers:
                while w.is_alive():
                    w.join(timeout=0.5)
                    if ARGS.verbose == 0:
                        done = total - in_q.qsize()
                        PRINT_QUEUE.put(
                            f"  {done}/{total} requests this round…\r"
                        )

    except KeyboardInterrupt:
        PRINT_QUEUE.put(
            warning("\rInterrupt! Draining queues, please wait…")
        )
        # Drain to unblock workers
        while not in_q.empty():
            try:
                in_q.get_nowait()
                in_q.task_done()
            except queue.Empty:
                break
        while not out_q.empty():
            try:
                found.add(out_q.get_nowait())
                out_q.task_done()
            except queue.Empty:
                break

    # Output results
    visible = sorted(
        (u for u in found if not ARGS.show_regexp or re.search(ARGS.show_regexp, u.url)),
        key=lambda u: u.url,
    )

    if len(visible) <= 1:
        PRINT_QUEUE.put(error("No URLs discovered beyond the start page."))
    elif ARGS.output_file:
        with open(ARGS.output_file, "w") as fh:
            for u in visible:
                fh.write(str(u) + os.linesep)
        PRINT_QUEUE.put(success(f"URLs written to {ARGS.output_file}"))
    else:
        PRINT_QUEUE.put(success(f"URLs discovered ({len(visible)}):"))
        for u in visible:
            PRINT_QUEUE.put(str(u))

    printer.stop()
    printer.join(timeout=3)


if __name__ == "__main__":
    main()
