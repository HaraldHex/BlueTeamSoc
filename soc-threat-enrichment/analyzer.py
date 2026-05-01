import re
from threat_intel import THREAT_DB
from collections import defaultdict

def classify_ip(ip):
    return THREAT_DB.get(ip, "unknown")

def analyze_log(file_path):
    ip_counts = defaultdict(int)
    results = []

    with open(file_path, "r") as file:
        for line in file:
            ips = re.findall(r'\d+\.\d+\.\d+\.\d+', line)

            for ip in ips:
                ip_counts[ip] += 1
                risk = classify_ip(ip)

                results.append((ip, risk, line.strip()))

    print("\n=== SOC THREAT REPORT ===\n")

    for ip, count in ip_counts.items():
        risk = classify_ip(ip)

        if risk == "malicious":
            print(f"🔴 {ip} -> MALICIOUS ({count} events)")
        elif risk == "suspicious":
            print(f"🟡 {ip} -> SUSPICIOUS ({count} events)")
        elif risk == "safe":
            print(f"🟢 {ip} -> SAFE ({count} events)")
        else:
            print(f"⚪ {ip} -> UNKNOWN ({count} events)")


if __name__ == "__main__":
    analyze_log("sample.log")
