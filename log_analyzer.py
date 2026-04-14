# log_analyzer.py
# Analyzes security log files and extracts threats

import re
import requests
from collections import Counter


def parse_log_file(content):
    """
    Parses raw log content and extracts key security info
    """
    lines = content.strip().split("\n")
    total_lines = len(lines)

    # Extract IPs
    ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
    all_ips = re.findall(ip_pattern, content)

    # Filter out private IPs
    private_ranges = ["192.168.", "10.", "172.16.", "127.", "0."]
    public_ips = [
        ip for ip in all_ips
        if not any(ip.startswith(p) for p in private_ranges)
    ]

    # Count IP frequency
    ip_counts = Counter(all_ips)
    public_ip_counts = Counter(public_ips)

    # Detect keywords
    security_keywords = {
        "failed": "Authentication Failure",
        "error": "Error Event",
        "block": "Firewall Block",
        "denied": "Access Denied",
        "attack": "Attack Detected",
        "malware": "Malware Activity",
        "sql": "SQL Injection",
        "admin": "Admin Access",
        "root": "Root Access Attempt",
        "passwd": "Password File Access",
        "shadow": "Shadow File Access",
        "unauthorized": "Unauthorized Access",
        "exploit": "Exploit Attempt",
        "shell": "Shell Access Attempt",
    }

    found_keywords = {}
    content_lower = content.lower()
    for kw, description in security_keywords.items():
        count = content_lower.count(kw)
        if count > 0:
            found_keywords[description] = count

    # Detect log type
    log_type = "Unknown"
    if "sshd" in content or "Failed password" in content:
        log_type = "SSH Log"
    elif "HTTP" in content or "GET" in content or "POST" in content:
        log_type = "Web Server Log"
    elif "FIREWALL" in content or "BLOCK" in content or "dport" in content:
        log_type = "Firewall Log"

    return {
        "total_lines": total_lines,
        "log_type": log_type,
        "all_ip_counts": dict(ip_counts.most_common(10)),
        "public_ip_counts": dict(public_ip_counts.most_common(5)),
        "top_ip": ip_counts.most_common(1)[0] if ip_counts else ("None", 0),
        "unique_ips": len(set(all_ips)),
        "found_keywords": found_keywords,
        "sample_lines": lines[:5]
    }


def analyze_with_ai(log_summary):
    """
    Sends log summary to Phi3 Mini for intelligent analysis
    """
    print("\n[*] Sending log summary to Phi3 Mini...")

    prompt = f"""You are Aegis Probe, an expert SOC analyst analyzing security logs.

LOG ANALYSIS SUMMARY:
- Log Type: {log_summary['log_type']}
- Total Lines: {log_summary['total_lines']}
- Unique IPs Found: {log_summary['unique_ips']}
- Top IP: {log_summary['top_ip'][0]} ({log_summary['top_ip'][1]} occurrences)
- Public IPs: {list(log_summary['public_ip_counts'].keys())}
- Security Events Found: {log_summary['found_keywords']}

Analyze this and respond in exactly this format, stop after point 5:

1. LOG TYPE: What kind of log is this?
2. THREAT LEVEL: Low / Medium / High / Critical
3. MAIN THREAT: What is the primary threat detected?
4. SUSPICIOUS IPS: Which IPs are most suspicious and why?
5. RECOMMENDED ACTION: What should the SOC analyst do immediately?"""

    try:
        response = requests.post(
            "http://localhost:11434/api/generate",
            json={
                "model": "phi3:mini",
                "prompt": prompt,
                "stream": False,
                "options": {
                    "temperature": 0.3,
                    "stop": ["6.", "Note:", "Additional", "---"]
                }
            },
            timeout=300
        )

        if response.status_code == 200:
            result = response.json()
            analysis = result.get("response", "").strip()

            # Clean extra lines
            lines = analysis.split("\n")
            clean = []
            for line in lines:
                line = line.strip()
                if not line:
                    continue
                if any(line.startswith(x) for x in ["6.", "7.", "Note:", "---"]):
                    break
                clean.append(line)

            print("[+] Log Analysis Complete!")
            return "\n".join(clean)
        else:
            return f"AI error: {response.status_code}"

    except Exception as e:
        return f"Connection error: {str(e)}"


def render_log_analyzer(st):
    """
    Renders the log analyzer UI in Streamlit
    """
    st.markdown("""
    <div style='text-align:center; padding:10px 0 20px 0;'>
      <h1 style='font-size:28px; color:#58a6ff !important;'>📁 LOG FILE ANALYZER</h1>
      <p style='color:#8b949e; font-size:13px;'>Upload security logs for AI-powered threat analysis</p>
    </div>
    """, unsafe_allow_html=True)

    # ── Generate Sample Logs Button ──
    st.markdown("### 🛠️ Generate Sample Logs")
    st.markdown("Don't have logs? Generate realistic sample logs for testing!")

    if st.button("⚡ Generate Sample Log Files", use_container_width=True):
        try:
            from log_generator import generate_all_logs
            generate_all_logs()
            st.success("✅ Sample logs generated in D:\\aegis_probe\\logs\\")
            st.info("📁 Files created: ssh_attack.log, web_attack.log, firewall.log")
        except Exception as e:
            st.error(f"Error: {e}")

    st.divider()

    # ── Upload Log File ──
    st.markdown("### 📂 Upload Log File")
    uploaded_file = st.file_uploader(
        "Upload a .log or .txt security log file",
        type=["log", "txt"],
        help="Supports SSH logs, web server logs, firewall logs"
    )

    if uploaded_file:
        content = uploaded_file.read().decode("utf-8", errors="ignore")

        # Show file info
        c1, c2, c3 = st.columns(3)
        with c1:
            st.metric("File Name", uploaded_file.name)
        with c2:
            st.metric("File Size", f"{len(content)} bytes")
        with c3:
            st.metric("Total Lines", len(content.split("\n")))

        st.divider()

        # Parse log
        with st.spinner("🔍 Parsing log file..."):
            summary = parse_log_file(content)

        # Show parsed summary
        st.markdown("### 📊 Log Summary")

        s1, s2, s3, s4 = st.columns(4)
        with s1: st.metric("Log Type", summary["log_type"])
        with s2: st.metric("Total Lines", summary["total_lines"])
        with s3: st.metric("Unique IPs", summary["unique_ips"])
        with s4: st.metric("Top IP Hits", summary["top_ip"][1])

        st.divider()

        # Show top IPs
        col1, col2 = st.columns(2)

        with col1:
            st.markdown("#### 🌐 Top IPs by Frequency")
            for ip, count in summary["all_ip_counts"].items():
                private = any(ip.startswith(p) for p in
                            ["192.168.", "10.", "172.", "127."])
                label = "🔒 Private" if private else "🌐 Public"
                st.markdown(f"`{ip}` — **{count}** hits {label}")

        with col2:
            st.markdown("#### 🚨 Security Events Detected")
            if summary["found_keywords"]:
                for event, count in summary["found_keywords"].items():
                    st.markdown(f"⚠️ **{event}** — {count} occurrences")
            else:
                st.success("✅ No suspicious keywords found")

        st.divider()

        # Sample lines preview
        st.markdown("#### 👁️ Sample Log Lines")
        for line in summary["sample_lines"]:
            st.code(line)

        st.divider()

        # AI Analysis
        st.markdown("### 🤖 Phi3 Mini AI Analysis")
        if st.button("🔍 Analyze with AI", type="primary",
                     use_container_width=True):
            with st.spinner("🤖 Phi3 Mini analyzing logs..."):
                ai_result = analyze_with_ai(summary)

            st.markdown(f"""
            <div style='background:#161b22; border:1px solid #30363d;
                        border-radius:12px; padding:20px;'>
                {ai_result}
            </div>
            """, unsafe_allow_html=True)

            # Probe top public IPs
            if summary["public_ip_counts"]:
                st.divider()
                st.markdown("### 🔬 Probing Top Suspicious IPs")
                from probe_engine import run_probes
                from geo_map import render_map

                top_public_ips = list(
                    summary["public_ip_counts"].keys()
                )[:3]

                fake_parsed = {
                    "raw_alert": f"Suspicious activity in {summary['log_type']}",
                    "keywords": list(summary["found_keywords"].keys())[:3],
                    "ips": top_public_ips
                }

                with st.spinner("🌐 Checking IPs on threat intel..."):
                    probes = run_probes(fake_parsed)

                for probe in probes:
                    pc1, pc2, pc3 = st.columns(3)
                    with pc1:
                        st.markdown(f"**IP:** `{probe['ip']}`")
                        if probe.get("abuseipdb"):
                            ab = probe["abuseipdb"]
                            st.metric("Abuse Score",
                                      f"{ab['abuse_confidence_score']}%")
                    with pc2:
                        if probe.get("virustotal"):
                            vt = probe["virustotal"]
                            st.metric("VT Engines",
                                      vt["malicious_count"])
                    with pc3:
                        v = probe.get("verdict", "")
                        if "DANGEROUS" in v:
                            st.error("🔴 DANGEROUS")
                        else:
                            st.warning("🟡 SUSPICIOUS")

                st.divider()
                render_map(st, probes)