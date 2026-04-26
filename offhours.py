import re
from datetime import datetime
 
# --- CONFIG ---
AUTH_LOG = "Scripts/access.log"
BUSINESS_START = 9   # 9am
BUSINESS_END   = 17  # 5pm
 
def run():
    findings = []
 
    with open(AUTH_LOG, "r") as f:
        for line in f:
            # Only look at successful SSH logins
            if "Accepted" not in line:
                continue
 
            # Parse timestamp: e.g. "Mar 27 13:08:09"
            match = re.match(r"(\w{3}\s+\d+\s+\d+:\d+:\d+)", line)
            if not match:
                continue
 
            timestamp_str = match.group(1)
            try:
                dt = datetime.strptime(timestamp_str, "%b %d %H:%M:%S")
            except ValueError:
                continue
 
            hour = dt.hour
 
            # Flag if outside business hours
            if hour < BUSINESS_START or hour >= BUSINESS_END:
                # Extract user and IP
                user_match = re.search(r"for (\S+) from ([\d.]+)", line)
                user = user_match.group(1) if user_match else "unknown"
                ip   = user_match.group(2) if user_match else "unknown"
 
                findings.append({
                    "timestamp": timestamp_str,
                    "user": user,
                    "ip": ip,
                    "hour": hour
                })
 
    return findings
 
def report(findings):
    lines = []
    lines.append("=" * 50)
    lines.append("DETECTION: Off-Hours Login Activity")
    lines.append(f"Business hours: {BUSINESS_START:02d}:00 - {BUSINESS_END:02d}:00")
    lines.append("=" * 50)
 
    if not findings:
        lines.append("No off-hours logins detected.")
    else:
        lines.append(f"Found {len(findings)} off-hours login(s):\n")
        for f in findings:
            lines.append(f"  [{f['timestamp']}] User: {f['user']} | IP: {f['ip']} | Hour: {f['hour']:02d}:xx")
 
    return "\n".join(lines)
 
if __name__ == "__main__":
    findings = run()
    print(report(findings))
 