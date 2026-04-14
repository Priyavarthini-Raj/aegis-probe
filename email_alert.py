# email_alert.py
# Sends automatic email alerts when dangerous threats are detected

import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime
import streamlit as st

SENDER_EMAIL = st.secrets.get("SENDER_EMAIL", "")
SENDER_PASSWORD = st.secrets.get("SENDER_PASSWORD", "")
RECEIVER_EMAIL = st.secrets.get("RECEIVER_EMAIL", "")


def send_danger_alert(case_id, parsed_alert, probe_results, analysis):
    """
    Sends an email alert when a DANGEROUS threat is detected
    """
    print("\n[*] Sending email alert...")

    # Build email subject
    subject = f"🚨 AEGIS PROBE ALERT — DANGEROUS Threat Detected! Case #{case_id}"

    # Find dangerous IPs
    dangerous_ips = []
    for probe in probe_results:
        if "DANGEROUS" in probe.get("verdict", ""):
            dangerous_ips.append(probe)

    if not dangerous_ips:
        print("[!] No dangerous IPs found — skipping email")
        return False

    # Build HTML email body
    ip_rows = ""
    for probe in dangerous_ips:
        ab = probe.get("abuseipdb", {}) or {}
        vt = probe.get("virustotal", {}) or {}
        ip_rows += f"""
        <tr>
            <td style='padding:8px; border:1px solid #ddd; font-family:monospace;'>{probe['ip']}</td>
            <td style='padding:8px; border:1px solid #ddd; color:red; font-weight:bold;'>{ab.get('abuse_confidence_score', 'N/A')}%</td>
            <td style='padding:8px; border:1px solid #ddd; color:red; font-weight:bold;'>{vt.get('malicious_count', 'N/A')}</td>
            <td style='padding:8px; border:1px solid #ddd;'>{ab.get('country') or 'Unknown'}</td>
            <td style='padding:8px; border:1px solid #ddd; color:red; font-weight:bold;'>DANGEROUS</td>
        </tr>
        """

    html_body = f"""
    <html>
    <body style='font-family: Arial, sans-serif; background-color: #f4f4f4; padding: 20px;'>

        <div style='max-width: 700px; margin: auto; background: white; border-radius: 10px; overflow: hidden; box-shadow: 0 2px 10px rgba(0,0,0,0.1);'>

            <!-- Header -->
            <div style='background: #0d1117; padding: 20px 30px;'>
                <h1 style='color: #58a6ff; margin:0; font-size:22px;'>🛡️ Aegis Probe</h1>
                <p style='color: #8b949e; margin:4px 0 0 0; font-size:13px;'>Defensive SOC Bot — Automated Alert</p>
            </div>

            <!-- Danger Banner -->
            <div style='background: #6b0000; padding: 16px 30px;'>
                <h2 style='color: #ffa198; margin:0; font-size:18px;'>🚨 DANGEROUS Threat Detected!</h2>
                <p style='color: #ffa198; margin:4px 0 0 0; font-size:13px;'>Immediate action required — Case #{case_id}</p>
            </div>

            <!-- Body -->
            <div style='padding: 24px 30px;'>

                <!-- Case Info -->
                <table style='width:100%; margin-bottom:20px;'>
                    <tr>
                        <td style='color:#666; font-size:13px;'>Case ID</td>
                        <td style='font-weight:bold; font-size:13px;'>#{case_id}</td>
                    </tr>
                    <tr>
                        <td style='color:#666; font-size:13px;'>Timestamp</td>
                        <td style='font-weight:bold; font-size:13px;'>{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</td>
                    </tr>
                    <tr>
                        <td style='color:#666; font-size:13px;'>Keywords</td>
                        <td style='font-weight:bold; font-size:13px;'>{', '.join(parsed_alert.get('keywords', []))}</td>
                    </tr>
                </table>

                <!-- Alert Text -->
                <div style='background:#f8f8f8; border-left:4px solid #f85149; padding:12px 16px; border-radius:4px; margin-bottom:20px;'>
                    <p style='margin:0; font-size:13px; color:#333;'><strong>Alert:</strong> {parsed_alert.get('raw_alert', '')}</p>
                </div>

                <!-- IP Table -->
                <h3 style='color:#333; font-size:15px; margin-bottom:10px;'>🔬 Dangerous IPs Detected</h3>
                <table style='width:100%; border-collapse:collapse; margin-bottom:20px;'>
                    <thead>
                        <tr style='background:#f85149;'>
                            <th style='padding:8px; border:1px solid #ddd; color:white; text-align:left;'>IP Address</th>
                            <th style='padding:8px; border:1px solid #ddd; color:white; text-align:left;'>Abuse Score</th>
                            <th style='padding:8px; border:1px solid #ddd; color:white; text-align:left;'>VT Engines</th>
                            <th style='padding:8px; border:1px solid #ddd; color:white; text-align:left;'>Country</th>
                            <th style='padding:8px; border:1px solid #ddd; color:white; text-align:left;'>Verdict</th>
                        </tr>
                    </thead>
                    <tbody>
                        {ip_rows}
                    </tbody>
                </table>

                <!-- AI Analysis -->
                <h3 style='color:#333; font-size:15px; margin-bottom:10px;'>🤖 Mistral AI Analysis</h3>
                <div style='background:#f8f8f8; padding:12px 16px; border-radius:4px; font-size:13px; color:#333; margin-bottom:20px;'>
                    <pre style='margin:0; white-space:pre-wrap; font-family:Arial;'>{analysis if analysis else 'Analysis not available'}</pre>
                </div>

                <!-- Recommended Actions -->
                <h3 style='color:#333; font-size:15px; margin-bottom:10px;'>⚡ Immediate Actions Required</h3>
                <ol style='color:#333; font-size:13px; line-height:1.8;'>
                    <li>Isolate affected hosts from the network immediately</li>
                    <li>Block all flagged IPs at the firewall</li>
                    <li>Collect and preserve logs for forensic analysis</li>
                    <li>Notify the incident response team</li>
                    <li>Run full malware scan on affected systems</li>
                </ol>
            </div>

            <!-- Footer -->
            <div style='background:#f4f4f4; padding:12px 30px; text-align:center;'>
                <p style='color:#999; font-size:11px; margin:0;'>
                    Generated by Aegis Probe SOC Bot | {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
                </p>
            </div>
        </div>

    </body>
    </html>
    """

    try:
        # Create email
        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"] = SENDER_EMAIL
        msg["To"] = RECEIVER_EMAIL
        msg.attach(MIMEText(html_body, "html"))

        # Send via Gmail SMTP
        with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
            server.login(SENDER_EMAIL, SENDER_PASSWORD)
            server.sendmail(SENDER_EMAIL, RECEIVER_EMAIL, msg.as_string())

        print(f"[+] Email alert sent to {RECEIVER_EMAIL}!")
        return True

    except Exception as e:
        print(f"[!] Email failed: {e}")
        return False


# Test it
if __name__ == "__main__":
    test_parsed = {
        "raw_alert": "Malware detected on host 10.0.0.5, beacon.exe connecting to IP 185.220.101.45",
        "keywords": ["malware", "suspicious"],
        "ips": ["10.0.0.5", "185.220.101.45"]
    }
    test_probes = [{
        "ip": "185.220.101.45",
        "abuseipdb": {"abuse_confidence_score": 100, "total_reports": 96, "country": "DE"},
        "virustotal": {"malicious_count": 16, "suspicious_count": 3, "harmless_count": 59},
        "verdict": "🔴 DANGEROUS"
    }]
    test_analysis = "1. ATTACK TYPE: RAT / C2\n2. SEVERITY: High\n3. HYPOTHESIS 1: Malware C2 connection"

    send_danger_alert(8, test_parsed, test_probes, test_analysis)