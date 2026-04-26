import re
from collections import Counter
 
log_file = "Scripts/auth.log"
ip_pattern = r'(?:\d{1,3}\.){3}\d{1,3}'
 
def run():
    failed_attempts = 0
    ip_counter = Counter()
 
    with open(log_file, "r") as f:
        for line in f:
            if "authentication failure" in line.lower():
                failed_attempts += 1
                for ip in re.findall(ip_pattern, line):
                    ip_counter[ip] += 1
 
    return {"total": failed_attempts, "top_ips": ip_counter.most_common(3)}
 
def report(findings):
    lines = []
    lines.append("=" * 50)
    lines.append("DETECTION 3: Sudo Privilege Escalation")
    lines.append("=" * 50)
    lines.append(f"Total failed sudo/auth attempts: {findings['total']}\n")
    if findings["top_ips"]:
        lines.append("Top 3 suspicious IPs:")
        for ip, count in findings["top_ips"]:
            lines.append(f"  {ip} -> {count} failed attempts")
    else:
        lines.append("No suspicious IPs found.")
    return "\n".join(lines)
 
if __name__ == "__main__":
    print(report(run()))