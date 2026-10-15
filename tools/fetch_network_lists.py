"""Refresh the public network lists the server reads (DESIGN.md 81).

    python3 tools/fetch_network_lists.py [--dir data/network_lists]

Downloads the X4BNet VPN and data-centre lists (MIT licence) and the Tor
Project's exit list, checks that each still looks like one -- enough lines,
nearly all of them IPv4 networks -- and replaces each file atomically. A file
that fails the check is left as it was, so a broken download never empties a
list. The server re-reads a changed file within a minute. DevOps runs it
daily (cron or a systemd timer) on a host with outbound HTTPS; the server
itself never fetches anything. Python 3.9, standard library only.
"""
import argparse
import ipaddress
import os
import sys
import tempfile
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_DIR = os.path.join(HERE, "..", "data", "network_lists")
SOURCES = {
    # file: (URL, the fewest lines a sound copy has)
    "x4bnet_vpn_ipv4.txt":
        ("https://raw.githubusercontent.com/X4BNet/lists_vpn/main/output/vpn/ipv4.txt", 1000),
    "x4bnet_datacenter_ipv4.txt":
        ("https://raw.githubusercontent.com/X4BNet/lists_vpn/main/output/datacenter/ipv4.txt",
         5000),
    "tor_exits.txt": ("https://check.torproject.org/torbulkexitlist", 100),
}


def check(text, minimum):
    """The reason `text` is not a sound list, or None."""
    lines = [line.split("#", 1)[0].strip() for line in text.splitlines()]
    lines = [line for line in lines if line]
    valid = 0
    for line in lines:
        try:
            ipaddress.IPv4Network(line, strict=False)
            valid += 1
        except ValueError:
            pass
    if valid < minimum:
        return "%d networks, fewer than %d" % (valid, minimum)
    if valid * 100 < len(lines) * 95:
        return "%d of %d lines are IPv4 networks" % (valid, len(lines))
    return None


def fetch(url):
    request = urllib.request.Request(url, headers={"User-Agent": "device-trust-network-lists/1"})
    with urllib.request.urlopen(request, timeout=60) as response:
        return response.read().decode("utf-8")


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--dir", default=DEFAULT_DIR)
    arguments = parser.parse_args()
    os.makedirs(arguments.dir, exist_ok=True)
    failed = 0
    for name, (url, minimum) in SOURCES.items():
        try:
            text = fetch(url)
        except Exception as error:  # noqa: BLE001 - report and keep the old file
            print("KEPT %s: %s" % (name, error))
            failed += 1
            continue
        problem = check(text, minimum)
        if problem:
            print("KEPT %s: %s" % (name, problem))
            failed += 1
            continue
        handle, temporary = tempfile.mkstemp(dir=arguments.dir, prefix=".fetch-")
        with os.fdopen(handle, "w", encoding="utf-8") as out:
            out.write(text)
        os.chmod(temporary, 0o644)
        os.replace(temporary, os.path.join(arguments.dir, name))
        print("WROTE %s" % name)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
