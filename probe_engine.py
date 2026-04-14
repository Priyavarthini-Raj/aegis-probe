# probe_engine.py
# This file investigates suspicious IPs using threat intelligence APIs

import requests
import json
import streamlit as st
ABUSEIPDB_API_KEY = st.secrets.get("ABUSEIPDB_KEY", "")
VIRUSTOTAL_API_KEY = st.secrets.get("VIRUSTOTAL_KEY", "")

def check_abuseipdb(ip):
    """
    Checks if the IP is known for malicious activity on AbuseIPDB
    """
    print(f"\n[*] Checking {ip} on AbuseIPDB...")

    try:
        response = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers={
                "Key": ABUSEIPDB_API_KEY,
                "Accept": "application/json"
            },
            params={
                "ipAddress": ip,
                "maxAgeInDays": 90
            },
            timeout=10
        )

        if response.status_code == 200:
            data = response.json()["data"]
            result = {
                "ip": ip,
                "abuse_confidence_score": data["abuseConfidenceScore"],
                "country": data["countryCode"],
                "total_reports": data["totalReports"],
                "last_reported": data["lastReportedAt"],
                "is_malicious": data["abuseConfidenceScore"] > 50
            }
            print(f"[+] Abuse Score: {result['abuse_confidence_score']}%")
            print(f"[+] Country: {result['country']}")
            print(f"[+] Total Reports: {result['total_reports']}")
            print(f"[+] Malicious: {result['is_malicious']}")
            return result
        else:
            print(f"[!] AbuseIPDB Error: {response.status_code}")
            return None

    except Exception as e:
        print(f"[!] AbuseIPDB connection failed: {e}")
        return None


def check_virustotal(ip):
    """
    Checks IP reputation on VirusTotal
    """
    print(f"\n[*] Checking {ip} on VirusTotal...")

    try:
        response = requests.get(
            f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
            headers={
                "x-apikey": VIRUSTOTAL_API_KEY
            },
            timeout=10
        )

        if response.status_code == 200:
            data = response.json()["data"]["attributes"]
            stats = data["last_analysis_stats"]
            result = {
                "ip": ip,
                "malicious_count": stats["malicious"],
                "suspicious_count": stats["suspicious"],
                "harmless_count": stats["harmless"],
                "country": data.get("country", "Unknown"),
                "is_malicious": stats["malicious"] > 3
            }
            print(f"[+] Malicious Engines: {result['malicious_count']}")
            print(f"[+] Suspicious Engines: {result['suspicious_count']}")
            print(f"[+] Country: {result['country']}")
            print(f"[+] Malicious: {result['is_malicious']}")
            return result
        else:
            print(f"[!] VirusTotal Error: {response.status_code}")
            return None

    except Exception as e:
        print(f"[!] VirusTotal connection failed: {e}")
        return None


def run_probes(parsed_alert):
    """
    Runs all probes on every IP found in the alert
    """
    print("\n[*] Starting Probe Engine...")
    probe_results = []

    if not parsed_alert["ips"]:
        print("[!] No IPs found in alert to probe.")
        return probe_results

    for ip in parsed_alert["ips"]:
        print(f"\n{'='*40}")
        print(f"[*] Probing IP: {ip}")
        print(f"{'='*40}")

        ip_result = {
            "ip": ip,
            "abuseipdb": check_abuseipdb(ip),
            "virustotal": check_virustotal(ip)
        }

        # Overall verdict
        is_dangerous = False
        if ip_result["abuseipdb"] and ip_result["abuseipdb"]["is_malicious"]:
            is_dangerous = True
        if ip_result["virustotal"] and ip_result["virustotal"]["is_malicious"]:
            is_dangerous = True

        ip_result["verdict"] = "🔴 DANGEROUS" if is_dangerous else "🟡 SUSPICIOUS - MONITOR"
        print(f"\n[!] VERDICT: {ip_result['verdict']}")

        probe_results.append(ip_result)

    return probe_results


# Test it
if __name__ == "__main__":
    test_parsed = {
        "raw_alert": "Failed SSH login attempts: 500 tries in 2 mins from IP 192.168.1.105",
        "keywords": ["failed", "login", "ssh"],
        "ips": ["192.168.1.105"]
    }

    results = run_probes(test_parsed)
    print("\n========== PROBE RESULTS ==========")
    print(json.dumps(results, indent=2, default=str))
    print("===================================")