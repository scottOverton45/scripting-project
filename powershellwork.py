log_file = "Scripts/powershell_log.txt"
 
suspicious_patterns = [
    "encodedcommand",
    "executionpolicy bypass",
    "invoke-webrequest http://",
    "upload",
    "compress-archive"
]
 
def run():
    suspicious_lines = []
    with open(log_file, "r") as f:
        for line in f:
            lower_line = line.lower()
            for pattern in suspicious_patterns:
                if pattern in lower_line:
                    suspicious_lines.append(line.strip())
                    break
    return suspicious_lines
 
def report(findings):
    lines = []
    lines.append("=" * 50)
    lines.append("DETECTION 4: Suspicious PowerShell Patterns")
    lines.append("=" * 50)
    lines.append(f"Total suspicious events: {len(findings)}\n")
    if findings:
        for entry in findings:
            lines.append(f"  [!] {entry}")
    else:
        lines.append("No suspicious PowerShell activity found.")
    return "\n".join(lines)
 
if __name__ == "__main__":
    print(report(run()))