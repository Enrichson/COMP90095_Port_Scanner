#!/usr/bin/env python3
"""
Assessment 3 - Port Scanner and Banner Grabber

Scans a target host for a selection of well-known TCP ports, reports which
ones are open, grabs the first 100 bytes of each service's banner/response,
and saves a summary report to a text file.

ETHICAL USE ONLY: scan only hosts you own or have permission to scan:
    - localhost (127.0.0.1)
    - comp90095.cis.unimelb.edu.au
    - scanme.nmap.org

GitHub repository: https://github.com/Enrichson/COMP90095_Port_Scanner.git
"""

import socket
import sys
from datetime import datetime

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

# Well-known ports to scan, mapped to the service usually found there.
COMMON_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    8080: "HTTP-Alt",
    9929: "Nping-Echo",   # open on scanme.nmap.org
    31337: "Elite",       # open on scanme.nmap.org
}

TIMEOUT = 1.0                          # seconds to wait for connect/recv
BANNER_BYTES = 100                     # how much of the response to keep
PROBE = b"HEAD / HTTP/1.0\r\n\r\n"     # small message to elicit a response


# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------

def resolve_host(hostname):
    """Convert a hostname to an IPv4 address. Returns None if it can't be resolved."""
    try:
        return socket.gethostbyname(hostname)
    except socket.gaierror:
        return None


def grab_banner(sock):
    """
    Read up to BANNER_BYTES from an open socket.

    Some services (SSH, FTP, SMTP) send a banner as soon as you connect, so we
    listen first. If nothing arrives, the service is probably waiting for the
    client to speak (e.g. HTTP), so we send the PROBE and listen again.
    """
    data = b""

    # 1. Listen briefly in case the service talks first.
    try:
        data = sock.recv(BANNER_BYTES)
    except socket.timeout:
        pass                      # nothing sent yet - that's fine
    except OSError:
        pass                      # e.g. connection reset; we'll try the probe

    # 2. If no banner yet, send the probe and listen again.
    if not data:
        try:
            sock.sendall(PROBE)
            data = sock.recv(BANNER_BYTES)
        except socket.timeout:
            return "(no response - timed out)"
        except OSError as err:
            return f"(error reading response: {err})"

    if not data:
        return "(connection closed with no data)"

    # Decode bytes to text; replace any non-text bytes instead of crashing.
    return data.decode("utf-8", errors="replace").strip()


def one_line(text):
    """Collapse a multi-line banner into one line for neat printing."""
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    return " | ".join(lines)


def identify_service(port, banner):
    """Guess the running service from banner keywords, falling back to the port number."""
    lower = banner.lower()

    if banner.startswith("SSH-"):
        return f"SSH ({banner.splitlines()[0]})"
    if banner.startswith("HTTP/"):
        for line in banner.splitlines():
            if line.lower().startswith("server:"):
                return f"HTTP ({line.split(':', 1)[1].strip()})"
        return "HTTP"
    if banner.startswith("220") and "ftp" in lower:
        return "FTP"
    if banner.startswith("220") and "smtp" in lower:
        return "SMTP"
    if banner.startswith("+OK"):
        return "POP3"
    if banner.startswith("* OK"):
        return "IMAP"
    if "mysql" in lower:
        return "MySQL"

    return f"{COMMON_PORTS.get(port, 'Unknown')} (guessed from port number)"


def scan_port(ip, port):
    """
    Try a TCP connection to ip:port.
    Returns the banner string if the port is open, or None if closed/filtered.
    """
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(TIMEOUT)
        result = sock.connect_ex((ip, port))   # 0 means the connection succeeded
        if result != 0:
            return None
        return grab_banner(sock)


def build_report(hostname, ip, start, duration, results):
    """Create the summary report as a single string."""
    lines = [
        "=" * 60,
        "PORT SCAN SUMMARY REPORT",
        "=" * 60,
        f"Target host : {hostname} ({ip})",
        f"Scan started: {start.strftime('%Y-%m-%d %H:%M:%S')}",
        f"Duration    : {duration:.2f} seconds",
        f"Ports tested: {', '.join(str(p) for p in COMMON_PORTS)}",
        f"Open ports  : {len(results)}",
        "-" * 60,
    ]
    if results:
        for port, service, banner in results:
            lines.append(f"Port {port}/tcp  OPEN  ->  {service}")
            lines.append(f"    Banner: {one_line(banner)}")
    else:
        lines.append("No open ports found among those tested.")
    lines.append("=" * 60)
    return "\n".join(lines)


def save_report(report, hostname, start):
    """Write the report to a timestamped text file. Returns the filename or None."""
    filename = f"scan_report_{hostname}_{start.strftime('%Y%m%d_%H%M%S')}.txt"
    try:
        with open(filename, "w", encoding="utf-8") as f:
            f.write(report + "\n")
        return filename
    except OSError as err:
        print(f"[!] Could not save report: {err}")
        return None


# ---------------------------------------------------------------------------
# Main program
# ---------------------------------------------------------------------------

def main():
    print("Simple Port Scanner & Banner Grabber")
    print("Only scan hosts you own or have permission to scan.\n")

    hostname = input("Enter hostname to scan [localhost]: ").strip() or "localhost"

    ip = resolve_host(hostname)
    if ip is None:
        print(f"[!] Could not resolve hostname '{hostname}'. Check the spelling and your connection.")
        sys.exit(1)

    print(f"\nScanning {hostname} ({ip}) ...\n")
    start = datetime.now()
    results = []

    for port, name in COMMON_PORTS.items():
        print(f"Port {port:<5} ({name:<10}) ... ", end="", flush=True)
        try:
            banner = scan_port(ip, port)
        except OSError as err:
            print(f"error: {err}")
            continue

        if banner is None:
            print("closed/filtered")
        else:
            service = identify_service(port, banner)
            print("OPEN")
            print(f"    Banner : {one_line(banner)}")
            print(f"    Service: {service}")
            results.append((port, service, banner))

    duration = (datetime.now() - start).total_seconds()
    report = build_report(hostname, ip, start, duration, results)

    print("\n" + report)

    filename = save_report(report, hostname, start)
    if filename:
        print(f"\nReport saved to {filename}")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] Scan cancelled by user.")
        sys.exit(0)