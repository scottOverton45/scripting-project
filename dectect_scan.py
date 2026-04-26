import re
from collections import defaultdict

# --- CONFIG ---
ACCESS_LOG = "Scripts/access.log"
THRESHOLD = 1000  # flag IPs with more than this many requests

def run():
    ip_counts = defaultdict(int)

    with open(ACCESS_LOG, "r") as f:
        for line in f:
            match = re.match(r"([\d.]+)", line)
            if match:
                ip_counts[match.group(1)] += 1

    # Only return IPs exceeding the threshold
    findings = [
        {"ip": ip, "count": count}
        for ip, count in ip_counts.items()
        if count > THRESHOLD
    ]

    # Sort highest first
    findings.sort(key=lambda x: x["count"], reverse=True)
    return findings

def report(findings):
    lines = []
    lines.append("=" * 50)
    lines.append("DETECTION: High Request Rate / Scanning")
    lines.append(f"Threshold: >{THRESHOLD} requests per IP")
    lines.append("=" * 50)

    if not findings:
        lines.append("No high-rate IPs detected.")
    else:
        lines.append(f"Found {len(findings)} suspicious IP(s):\n")
        for f in findings:
            lines.append(f"  IP: {f['ip']:<20} Requests: {f['count']}")

    return "\n".join(lines)

if __name__ == "__main__":
    findings = run()
    print(report(findings))
