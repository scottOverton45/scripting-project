from datetime import datetime


import Scripts.offhours as offhours
import Scripts.dectect_scan as dectect_scan
import Scripts.escalation as escalation
import Scripts.powershellwork as powershellwork

OUTPUT_FILE = "report.txt"

if __name__ == "__main__":
    print("[*] Running the files")
    report_sections = [
        "MALICIOUS ACTIVITY SCAN REPORT",
        f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        "=" * 30,
        "",
        offhours.report(offhours.run()),
        "",
        dectect_scan.report(dectect_scan.run()),
        "",
        escalation.report(escalation.run()),
        "",
        powershellwork.report(powershellwork.run()),
        "",
        "=" * 30,
        "END OF REPORT",
    ]

    full_report = "\n".join(report_sections)

    print(full_report)

    with open(OUTPUT_FILE, "w") as f:
        f.write(full_report)

    print(f"\n[*] Report saved to {OUTPUT_FILE}")