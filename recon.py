import argparse
import json
import socket
from datetime import datetime, timezone


RECORD_TYPES = ["A", "AAAA", "MX", "NS", "CNAME"]


def unique(values):
    seen = []
    for value in values:
        if value not in seen:
            seen.append(value)
    return seen


def resolve_with_getaddrinfo(domain, family):
    results = []
    try:
        infos = socket.getaddrinfo(domain, None, family, socket.SOCK_STREAM)
    except socket.gaierror:
        return results

    for info in infos:
        address = info[4][0]
        results.append(address)
    return unique(results)


def resolve_reverse(ip_address):
    try:
        return socket.gethostbyaddr(ip_address)[0]
    except (socket.herror, socket.gaierror, OSError):
        return None


def collect_dns(domain):
    a_records = resolve_with_getaddrinfo(domain, socket.AF_INET)
    aaaa_records = resolve_with_getaddrinfo(domain, socket.AF_INET6)

    return {
        "A": a_records,
        "AAAA": aaaa_records,
        "MX": [],
        "NS": [],
        "CNAME": [],
    }


def build_report(domain):
    records = collect_dns(domain)
    reverse_dns = {}

    for ip_address in records["A"] + records["AAAA"]:
        hostname = resolve_reverse(ip_address)
        if hostname:
            reverse_dns[ip_address] = hostname

    return {
        "target": domain,
        "scanned_at": datetime.now(timezone.utc).isoformat(),
        "record_types_checked": RECORD_TYPES,
        "records": records,
        "reverse_dns": reverse_dns,
        "notes": [
            "MX, NS, and CNAME are left as placeholders in this offline-safe implementation.",
            "The tool demonstrates structured reconnaissance and report output."
        ],
    }


def main():
    parser = argparse.ArgumentParser(description="Collect basic DNS reconnaissance data.")
    parser.add_argument("domain", help="Target domain to analyze")
    parser.add_argument("--output", help="Optional output file path")
    args = parser.parse_args()

    report = build_report(args.domain)
    serialized = json.dumps(report, indent=2)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as handle:
            handle.write(serialized + "\n")
        print(f"Saved report to {args.output}")
        return

    print(serialized)


if __name__ == "__main__":
    main()
