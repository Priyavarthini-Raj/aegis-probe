# app.py — Aegis Probe v2.0 — Ultimate SOC Dashboard

from log_analyzer import render_log_analyzer
import streamlit as st
from alert_parser import parse_alert
from hypothesis_engine import generate_hypotheses
from probe_engine import run_probes
from evidence_ledger import init_database, save_investigation, get_all_investigations
from pdf_report import generate_pdf_report
from email_alert import send_danger_alert
from stats_dashboard import render_stats
from geo_map import render_map
from threat_intel import render_threat_intel

st.set_page_config(
    page_title="Aegis Probe - SOC Bot",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

st.markdown("""
<style>
[data-testid="stAppViewContainer"] { background-color: #080d14; }
[data-testid="stSidebar"] {
    background-color: #0a0f1a !important;
    border-right: 1px solid #1a2332 !important;
}
[data-testid="stSidebar"] * { color: #c9d1d9 !important; }
.stApp { background-color: #080d14; color: #c9d1d9; }

h1,h2,h3,h4 { color: #85b7eb !important; }
p, li, label { color: #8b949e !important; }

.stTextArea textarea {
    background-color: #0d1520 !important;
    color: #c9d1d9 !important;
    border: 1px solid #1a2332 !important;
    border-radius: 8px !important;
    font-size: 13px !important;
}
.stSelectbox > div > div {
    background-color: #0d1520 !important;
    color: #c9d1d9 !important;
    border: 1px solid #1a2332 !important;
    border-radius: 8px !important;
}
.stButton > button {
    background-color: #1a4a2a !important;
    color: #97c459 !important;
    border: 1px solid #2a7a3a !important;
    border-radius: 8px !important;
    font-size: 15px !important;
    font-weight: 700 !important;
    letter-spacing: 2px !important;
    padding: 14px !important;
    transition: all 0.2s !important;
}
.stButton > button:hover {
    background-color: #1f5a30 !important;
    border-color: #3a9a4a !important;
}
.stDownloadButton > button {
    background-color: #0c2a4a !important;
    color: #85b7eb !important;
    border: 1px solid #1a5a8a !important;
    border-radius: 8px !important;
    font-weight: 700 !important;
}
.stMetric {
    background-color: #0a0f1a !important;
    border: 1px solid #1a2332 !important;
    border-radius: 10px !important;
    padding: 16px !important;
}
.stMetricLabel { color: #4a7090 !important; font-size: 11px !important; }
.stMetricValue { color: #85b7eb !important; }
div[data-testid="stExpander"] {
    background-color: #0a0f1a !important;
    border: 1px solid #1a2332 !important;
    border-radius: 8px !important;
}
.stProgress > div > div {
    background: linear-gradient(90deg, #1a4a2a, #85b7eb) !important;
    border-radius: 4px !important;
}
hr { border-color: #1a2332 !important; }
code {
    background-color: #0d1520 !important;
    color: #85b7eb !important;
    padding: 2px 8px !important;
    border-radius: 4px !important;
    border: 1px solid #1a2332 !important;
}

/* Custom Classes */
.aegis-header {
    background: #0a0f1a;
    border: 1px solid #1a2332;
    border-radius: 12px;
    padding: 20px 24px;
    margin-bottom: 4px;
    display: flex;
    align-items: center;
    justify-content: space-between;
}
.verdict-danger {
    background: #120404;
    border: 1px solid #7a1515;
    border-left: 4px solid #e24b4a;
    border-radius: 10px;
    padding: 16px 20px;
    color: #e24b4a !important;
    font-size: 18px;
    font-weight: 700;
    letter-spacing: 1px;
}
.verdict-warn {
    background: #120c02;
    border: 1px solid #6b4a10;
    border-left: 4px solid #ef9f27;
    border-radius: 10px;
    padding: 16px 20px;
    color: #ef9f27 !important;
    font-size: 18px;
    font-weight: 700;
    letter-spacing: 1px;
}
.section-card {
    background: #0a0f1a;
    border: 1px solid #1a2332;
    border-left: 3px solid #85b7eb;
    border-radius: 0 10px 10px 0;
    padding: 16px 20px;
    margin-bottom: 8px;
    font-size: 13px;
    line-height: 1.8;
    color: #8b949e !important;
}
.ip-card-danger {
    background: #120404;
    border: 1px solid #5a1010;
    border-radius: 8px;
    padding: 12px;
    margin-bottom: 8px;
}
.ip-card-warn {
    background: #120c02;
    border: 1px solid #4a3008;
    border-radius: 8px;
    padding: 12px;
    margin-bottom: 8px;
}
.step-badge {
    display: inline-block;
    background: #0d1520;
    border: 1px solid #1a2332;
    border-radius: 6px;
    padding: 6px 10px;
    font-size: 12px;
    color: #6a9ab0;
    margin-bottom: 4px;
    width: 100%;
}
.tor-banner {
    background: #1a0505;
    border: 1px solid #7a1515;
    border-radius: 8px;
    padding: 10px 14px;
    color: #e24b4a !important;
    font-size: 13px;
    font-weight: 500;
    margin-bottom: 8px;
}
</style>
""", unsafe_allow_html=True)

init_database()

# ── Sidebar ──
with st.sidebar:
    st.markdown("""
    <div style='display:flex;align-items:center;gap:10px;
                padding-bottom:14px;border-bottom:1px solid #1a2332;
                margin-bottom:14px;'>
        <div style='width:34px;height:34px;background:#1a3a5c;
                    border:1px solid #2a5a8c;border-radius:8px;
                    display:flex;align-items:center;justify-content:center;
                    font-size:18px;'>🛡</div>
        <div>
            <div style='font-size:14px;font-weight:600;color:#e6f1fb;'>
                Aegis Probe
            </div>
            <div style='font-size:11px;color:#4a7090;'>
                SOC Bot v2.0
            </div>
        </div>
    </div>
    """, unsafe_allow_html=True)

    rows = get_all_investigations()
    total = len(rows)
    dangerous = sum(1 for r in rows if "DANGEROUS" in str(r[7]))
    suspicious = total - dangerous

    st.markdown("### 📊 Stats")
    c1, c2 = st.columns(2)
    with c1:
        st.metric("Total", total)
        st.metric("🔴 Danger", dangerous)
    with c2:
        st.metric("🟡 Suspect", suspicious)
        st.metric("✅ Clean", max(0, total - dangerous - suspicious))

    st.divider()
    st.markdown("### 📋 Recent Cases")
    if rows:
        for row in rows[:8]:
            icon = "🔴" if "DANGEROUS" in str(row[7]) else "🟡"
            with st.expander(f"{icon} Case #{row[0]} — {row[1][:10]}"):
                st.markdown(f"**Alert:** {str(row[2])[:80]}...")
                st.markdown(f"**Verdict:** {row[7]}")
    else:
        st.info("No investigations yet.")

# ── Tabs ──
tab1, tab2, tab3 = st.tabs([
    "🔍 Investigate",
    "📊 Statistics",
    "📁 Log Analyzer"
])

# ════════════════════════════════
# TAB 1 — INVESTIGATE
# ════════════════════════════════
with tab1:

    # ── Header ──
    st.markdown("""
    <div style='background:#0a0f1a;border:1px solid #1a2332;
                border-radius:12px;padding:20px 24px;margin-bottom:16px;
                display:flex;align-items:center;justify-content:space-between;'>
        <div>
            <div style='font-size:28px;font-weight:700;color:#85b7eb;
                        letter-spacing:2px;'>🛡️ AEGIS PROBE</div>
            <div style='font-size:12px;color:#4a7090;margin-top:4px;
                        letter-spacing:1px;'>
                DEFENSIVE SOC BOT v2.0 — PHI3 MINI + NMAP + ABUSEIPDB + VIRUSTOTAL
            </div>
        </div>
        <div style='background:#0d2010;border:1px solid #2a5a10;
                    border-radius:99px;padding:6px 14px;font-size:12px;
                    color:#97c459;display:flex;align-items:center;gap:6px;'>
            <div style='width:7px;height:7px;background:#97c459;
                        border-radius:50%;'></div>
            AI Online
        </div>
    </div>
    """, unsafe_allow_html=True)

    # ── Metrics ──
    m1, m2, m3, m4 = st.columns(4)
    with m1: st.metric("🔵 Total Cases", total, "All time")
    with m2: st.metric("🔴 Dangerous", dangerous, "Act immediately")
    with m3: st.metric("🟡 Suspicious", suspicious, "Monitor closely")
    with m4: st.metric("⚡ Model", "Phi3 Mini", "Local & Private")
    st.divider()

    # ── Input ──
    col1, col2 = st.columns([2, 1])

    with col1:
        st.markdown("### 🚨 Enter Security Alert")
        sample_alerts = {
            "Select a sample alert...": "",
            "SSH Brute Force": "Failed SSH login attempts: 500 tries in 2 mins from IP 89.248.167.131",
            "Port Scan": "Port scan detected from IP 45.155.205.233 scanning ports 22,80,443,3389",
            "DDoS Attack": "DDoS attack detected! Traffic spike of 95Gbps from IPs 185.156.73.54, 194.165.16.11 targeting web server on port 80",
            "Malware Detection": "Malware detected on host 10.0.0.5, suspicious process beacon.exe connecting to IP 185.220.101.45",
            "Ransomware": "Ransomware activity detected! Files being encrypted on host 10.0.0.20. Process cryptolocker.exe communicating with IP 91.195.240.94",
            "Cryptomining": "Cryptomining malware detected! Process xmrig.exe consuming 98% CPU connecting to mining pool at IP 194.165.16.76 port 3333",
            "SQL Injection": "SQL injection attempt detected from IP 45.155.205.233 on login page. Payload: OR 1=1 in username field",
            "Phishing Email": "Phishing email detected from IP 193.32.162.95. Malicious link to fake-bank-login.ru clicked by john.doe@company.com",
            "Unauthorized Access": "Unauthorized access attempt detected from IP 89.248.167.131 on admin panel /wp-admin",
            "Data Exfiltration": "Large data transfer! 15GB uploaded from host 10.0.1.55 to external IP 185.220.101.34 via FTP port 21",
            "Privilege Escalation": "Privilege escalation on host 10.0.0.10. User guest ran sudo and accessed /etc/shadow. Traffic from IP 45.33.32.156",
            "Lateral Movement": "Lateral movement detected! Host 10.0.0.15 attempting SMB connections to internal hosts using stolen credentials from IP 46.161.27.151",
        }

        selected = st.selectbox("⚡ Quick test:", list(sample_alerts.keys()))
        alert_input = st.text_area(
            "Alert text:",
            value=sample_alerts[selected] if selected != "Select a sample alert..." else "",
            placeholder="Paste your security alert here...",
            height=120
        )

    with col2:
        st.markdown("### ⚡ Investigation Pipeline")
        pipeline = [
            ("1", "Parse alert", "Extract IPs & keywords"),
            ("2", "Phi3 Mini AI", "Generate hypotheses"),
            ("3", "AbuseIPDB + VT", "Probe IP reputation"),
            ("4", "Nmap scan", "Detect open ports"),
            ("5", "Geo map", "Locate attacker"),
            ("6", "PDF + Email", "Report & notify"),
        ]
        for num, title, desc in pipeline:
            st.markdown(
                f'<div class="step-badge">'
                f'<span style="color:#85b7eb;font-weight:600;">{num}.</span> '
                f'<span style="color:#c9d1d9;">{title}</span> — '
                f'<span style="color:#4a7090;">{desc}</span>'
                f'</div>',
                unsafe_allow_html=True
            )

    st.divider()

    # ── Investigate Button ──
    if st.button(
        "🔍   INVESTIGATE NOW",
        type="primary",
        use_container_width=True
    ):
        if not alert_input.strip():
            st.error("⚠️ Please enter a security alert first!")
        else:
            prog = st.progress(0, text="🚀 Launching Aegis Probe v2.0...")

            prog.progress(15, text="🔍 Step 1 — Parsing alert...")
            parsed = parse_alert(alert_input)

            prog.progress(35, text="🤖 Step 2 — Phi3 Mini AI analyzing...")
            analysis = generate_hypotheses(parsed)

            prog.progress(55, text="🌐 Step 3 — Probing IPs on AbuseIPDB + VirusTotal...")
            probes = run_probes(parsed)

            prog.progress(75, text="💾 Step 4 — Saving to Evidence Ledger...")
            inv_id = save_investigation(parsed, analysis, probes)

            # Auto Email
            final_check = any(
                "DANGEROUS" in p.get("verdict", "") for p in probes
            )
            if final_check:
                try:
                    send_danger_alert(inv_id, parsed, probes, analysis)
                    st.toast("📧 Danger alert email sent!", icon="✅")
                except Exception as e:
                    st.toast(f"Email failed: {e}", icon="⚠️")

            prog.progress(100, text="✅ Investigation complete!")

            final = (
                "🔴 DANGEROUS"
                if any("DANGEROUS" in p.get("verdict", "") for p in probes)
                else "🟡 SUSPICIOUS - MONITOR"
            )

            st.divider()

            # ── Verdict ──
            if "DANGEROUS" in final:
                st.markdown(
                    f'<div class="verdict-danger">'
                    f'🚨 FINAL VERDICT: {final} — CASE #{inv_id}'
                    f'</div>',
                    unsafe_allow_html=True
                )
            else:
                st.markdown(
                    f'<div class="verdict-warn">'
                    f'⚠️ FINAL VERDICT: {final} — CASE #{inv_id}'
                    f'</div>',
                    unsafe_allow_html=True
                )

            st.markdown("")

            # ── Keywords + IPs ──
            r1, r2 = st.columns(2)
            with r1:
                st.markdown("#### 🔑 Keywords Detected")
                if parsed["keywords"]:
                    chips = " ".join([
                        f"`{k}`" for k in parsed["keywords"]
                    ])
                    st.markdown(chips)
                else:
                    st.info("No keywords found")

            with r2:
                st.markdown("#### 🌐 IPs Extracted")
                if parsed["ips"]:
                    for ip in parsed["ips"]:
                        st.code(ip)
                else:
                    st.info("No IPs found")

            st.divider()

            # ── AI Analysis ──
            st.markdown("#### 🤖 Phi3 Mini AI Analysis")
            if (analysis and
                    "timed out" not in str(analysis).lower() and
                    analysis != "None"):
                st.markdown(
                    f'<div class="section-card">{analysis}</div>',
                    unsafe_allow_html=True
                )
            else:
                st.warning("⚠️ AI timed out — click Investigate again!")

            st.divider()

            # ── Probe Results ──
            st.markdown("#### 🔬 Threat Intelligence — AbuseIPDB + VirusTotal")
            for probe in probes:
                is_dangerous = "DANGEROUS" in probe.get("verdict", "")
                card_class = "ip-card-danger" if is_dangerous else "ip-card-warn"

                st.markdown(
                    f'<div class="{card_class}">',
                    unsafe_allow_html=True
                )

                pc1, pc2, pc3 = st.columns(3)
                with pc1:
                    st.markdown(f"**IP:** `{probe['ip']}`")
                    if probe.get("abuseipdb"):
                        ab = probe["abuseipdb"]
                        st.metric(
                            "Abuse Score",
                            f"{ab['abuse_confidence_score']}%"
                        )
                        st.caption(
                            f"Reports: {ab['total_reports']} | "
                            f"Country: {ab.get('country') or 'Unknown'}"
                        )
                with pc2:
                    st.markdown("**VirusTotal**")
                    if probe.get("virustotal"):
                        vt = probe["virustotal"]
                        st.metric(
                            "Malicious Engines",
                            vt["malicious_count"]
                        )
                        st.caption(
                            f"Suspicious: {vt['suspicious_count']} | "
                            f"Harmless: {vt['harmless_count']}"
                        )
                with pc3:
                    st.markdown("**Verdict**")
                    v = probe.get("verdict", "")
                    if "DANGEROUS" in v:
                        st.error("🔴 DANGEROUS")
                    else:
                        st.warning("🟡 SUSPICIOUS")

                st.markdown('</div>', unsafe_allow_html=True)
                st.divider()

            # ── Geo Map ──
            render_map(st, probes)
            st.divider()

            # ── Nmap Intel ──
            render_threat_intel(st, parsed["ips"])
            st.divider()

            # ── PDF Download ──
            st.markdown("#### 📄 Download Investigation Report")
            try:
                pdf_path = generate_pdf_report(
                    inv_id, parsed, analysis, probes, final
                )
                with open(pdf_path, "rb") as f:
                    st.download_button(
                        label="📥 Download Full PDF Report",
                        data=f,
                        file_name=f"AegisProbe_Case_{inv_id}_Report.pdf",
                        mime="application/pdf",
                        use_container_width=True
                    )
            except Exception as e:
                st.error(f"PDF error: {e}")

            st.success(f"✅ Case #{inv_id} saved to Evidence Ledger!")

# ════════════════════════════════
# TAB 2 — STATISTICS
# ════════════════════════════════
with tab2:
    render_stats(st)

# ════════════════════════════════
# TAB 3 — LOG ANALYZER
# ════════════════════════════════
with tab3:
    render_log_analyzer(st)