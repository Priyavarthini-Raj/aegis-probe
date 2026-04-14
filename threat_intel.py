# threat_intel.py
# Cloud-safe Nmap threat intelligence
# Works on local machine AND Streamlit Cloud

import socket
import requests
import streamlit as st

# ── Try to import nmap safely ──
# On Streamlit Cloud, nmap may not be available
# So we wrap it in try/except
try:
    import nmap
    NMAP_AVAILABLE = True
except ImportError:
    NMAP_AVAILABLE = False

# ── Dangerous ports reference ──
DANGEROUS_PORTS = {
    21:   "FTP — File Transfer (data theft risk)",
    22:   "SSH — Secure Shell (brute force target)",
    23:   "Telnet — Unencrypted remote access",
    25:   "SMTP — Mail server (spam/phishing)",
    80:   "HTTP — Web server",
    443:  "HTTPS — Encrypted web",
    445:  "SMB — File sharing (ransomware spread)",
    1433: "MSSQL — Database (SQL injection risk)",
    1723: "PPTP VPN — Tunneling",
    3306: "MySQL — Database exposed",
    3389: "RDP — Remote Desktop (takeover risk)",
    4444: "Metasploit default — Likely backdoor!",
    5900: "VNC — Remote control",
    6379: "Redis — Database exposed",
    8080: "HTTP Alternate — Web proxy",
    8443: "HTTPS Alternate — Suspicious web",
    8888: "Jupyter/Custom — Code execution risk",
    9200: "Elasticsearch — Data exposure",
}

HIGH_RISK_PORTS = {21, 22, 23, 445, 1433, 3306, 3389, 4444, 5900}

TOR_KEYWORDS = ["tor", "exit", "relay", "anonymize", "for-privacy", "torservers"]


def is_private_ip(ip):
    """Check if IP is private/local"""
    private_prefixes = [
        "10.", "192.168.", "127.", "172.16.", "172.17.",
        "172.18.", "172.19.", "172.20.", "172.21.", "172.22.",
        "172.23.", "172.24.", "172.25.", "172.26.", "172.27.",
        "172.28.", "172.29.", "172.30.", "172.31.", "0.", "::1"
    ]
    return any(ip.startswith(p) for p in private_prefixes)


def get_hostname(ip):
    """Get hostname via reverse DNS"""
    try:
        hostname = socket.gethostbyaddr(ip)[0]
        return hostname
    except Exception:
        return None


def is_tor_node(hostname):
    """Check if hostname indicates Tor exit node"""
    if not hostname:
        return False
    h = hostname.lower()
    return any(kw in h for kw in TOR_KEYWORDS)


def scan_with_nmap(ip):
    """
    Scan IP using local Nmap.
    Returns dict of open ports.
    Only runs if Nmap is available.
    """
    if not NMAP_AVAILABLE:
        return {}

    try:
        scanner = nmap.PortScanner()
        # Fast scan: top 100 ports, T4 speed, only open
        scanner.scan(ip, arguments="-F -T4 --open", timeout=60)

        open_ports = {}
        if ip in scanner.all_hosts():
            host = scanner[ip]
            for proto in host.all_protocols():
                ports = host[proto].keys()
                for port in ports:
                    state = host[proto][port]['state']
                    if state == 'open':
                        service = host[proto][port].get('name', 'unknown')
                        open_ports[port] = service
        return open_ports
    except Exception as e:
        return {}


def render_threat_intel(st_obj, ips):
    """
    Main function called from app.py
    Works on both local machine and Streamlit Cloud
    """

    if not ips:
        st_obj.info("No IP addresses found to scan.")
        return

    # Filter out private IPs
    public_ips = [ip for ip in ips if not is_private_ip(ip)]

    if not public_ips:
        st_obj.markdown("""
        <div style='background:rgba(245,158,11,0.08);
                    border:1px solid rgba(245,158,11,0.2);
                    border-radius:12px;padding:16px 20px;'>
            <div style='font-family:Exo 2,sans-serif;font-size:13px;color:#f59e0b;'>
                ⚠️ All detected IPs are private/local ranges
                (192.168.x.x, 10.x.x, 127.x.x).
                Nmap scanning skipped — private IPs cannot be scanned externally.
            </div>
        </div>
        """, unsafe_allow_html=True)
        return

    # Show cloud warning if Nmap not available
    if not NMAP_AVAILABLE:
        st_obj.markdown("""
        <div style='background:rgba(99,102,241,0.08);
                    border:1px solid rgba(99,102,241,0.2);
                    border-radius:12px;padding:16px 20px;margin-bottom:16px;'>
            <div style='font-family:Exo 2,sans-serif;font-size:14px;
                        font-weight:700;color:#818cf8;margin-bottom:6px;'>
                📡 NMAP CLOUD MODE
            </div>
            <div style='font-family:Exo 2,sans-serif;font-size:13px;color:#6b7280;'>
                Nmap port scanning is limited on cloud deployment.
                Showing DNS intelligence and known port risk analysis instead.
                For full port scanning, run Aegis Probe locally on your machine.
            </div>
        </div>
        """, unsafe_allow_html=True)

    # Process each public IP
    for ip in public_ips[:3]:  # Max 3 IPs to keep it fast

        st_obj.markdown(f"""
        <div style='background:rgba(0,10,20,0.6);
                    border:1px solid rgba(0,212,255,0.12);
                    border-radius:14px;padding:20px;margin-bottom:16px;'>
            <div style='font-family:Share Tech Mono,monospace;font-size:13px;
                        color:#00d4ff;margin-bottom:14px;
                        text-shadow:0 0 10px rgba(0,212,255,0.3);'>
                🎯 SCANNING: {ip}
            </div>
        """, unsafe_allow_html=True)

        # 1. Hostname / Tor detection
        hostname = get_hostname(ip)
        tor = is_tor_node(hostname)

        if tor:
            st_obj.markdown(f"""
            <div style='background:rgba(239,68,68,0.1);
                        border:1px solid rgba(239,68,68,0.3);
                        border-radius:10px;padding:14px 18px;margin-bottom:12px;
                        box-shadow:0 0 20px rgba(239,68,68,0.1);'>
                <div style='font-family:Rajdhani,sans-serif;font-size:18px;
                            font-weight:700;color:#ef4444;letter-spacing:2px;
                            text-shadow:0 0 15px rgba(239,68,68,0.4);'>
                    🧅 TOR EXIT NODE DETECTED — CRITICAL RISK
                </div>
                <div style='font-family:Share Tech Mono,monospace;font-size:12px;
                            color:rgba(239,68,68,0.7);margin-top:6px;'>
                    HOSTNAME: {hostname}
                </div>
                <div style='font-family:Exo 2,sans-serif;font-size:12px;
                            color:#6b7280;margin-top:4px;'>
                    This IP is a Tor exit node. Attacker is hiding real identity
                    through the Tor anonymity network. Extremely high risk.
                </div>
            </div>
            """, unsafe_allow_html=True)
        elif hostname:
            st_obj.markdown(f"""
            <div style='background:rgba(0,212,255,0.04);
                        border:1px solid rgba(0,212,255,0.1);
                        border-radius:8px;padding:10px 14px;margin-bottom:12px;'>
                <div style='font-family:Share Tech Mono,monospace;font-size:12px;
                            color:#4a7090;'>
                    🔗 HOSTNAME: {hostname}
                </div>
            </div>
            """, unsafe_allow_html=True)

        # 2. Nmap scan (local only)
        if NMAP_AVAILABLE:
            with st_obj.spinner(f"Scanning {ip} with Nmap..."):
                open_ports = scan_with_nmap(ip)

            if open_ports:
                st_obj.markdown("""
                <div style='font-family:Share Tech Mono,monospace;font-size:10px;
                            color:#4a7090;letter-spacing:2px;margin-bottom:8px;'>
                    OPEN PORTS DETECTED:
                </div>
                """, unsafe_allow_html=True)

                cols = st_obj.columns(min(len(open_ports), 4))
                for i, (port, service) in enumerate(open_ports.items()):
                    is_risky = port in HIGH_RISK_PORTS
                    danger_desc = DANGEROUS_PORTS.get(
                        port, f"{service.upper()} — Verify necessity"
                    )
                    with cols[i % 4]:
                        st_obj.markdown(f"""
                        <div style='background:{"rgba(239,68,68,0.08)" if is_risky else "rgba(16,185,129,0.06)"};
                                    border:1px solid {"rgba(239,68,68,0.25)" if is_risky else "rgba(16,185,129,0.15)"};
                                    border-radius:10px;padding:12px;text-align:center;'>
                            <div style='font-family:Rajdhani,sans-serif;font-size:22px;
                                        font-weight:700;
                                        color:{"#ef4444" if is_risky else "#10b981"};'>
                                {port}
                            </div>
                            <div style='font-family:Share Tech Mono,monospace;font-size:10px;
                                        color:{"#ef4444" if is_risky else "#10b981"};
                                        margin-bottom:4px;'>
                                {service.upper()}
                            </div>
                            <div style='font-family:Exo 2,sans-serif;font-size:10px;
                                        color:#4a7090;'>
                                {"⚠️ HIGH RISK" if is_risky else "✓ Open"}
                            </div>
                        </div>
                        """, unsafe_allow_html=True)

                # Risk summary
                risky = [p for p in open_ports if p in HIGH_RISK_PORTS]
                if risky:
                    risky_names = [
                        f"Port {p} ({DANGEROUS_PORTS.get(p, 'Unknown')})"
                        for p in risky
                    ]
                    st_obj.error(
                        f"🚨 {len(risky)} HIGH RISK port(s) found: "
                        + ", ".join(risky_names[:3])
                    )
            else:
                st_obj.markdown("""
                <div style='font-family:Share Tech Mono,monospace;font-size:12px;
                            color:#10b981;padding:8px 0;'>
                    ✓ No high-risk ports detected in top 100 scan
                </div>
                """, unsafe_allow_html=True)

        else:
            # Cloud mode — show known port info without scanning
            st_obj.markdown("""
            <div style='font-family:Share Tech Mono,monospace;font-size:11px;
                        color:#4a7090;letter-spacing:1px;margin-bottom:8px;'>
                ⬡ COMMON HIGH-RISK PORTS TO INVESTIGATE MANUALLY:
            </div>
            """, unsafe_allow_html=True)

            port_cols = st_obj.columns(4)
            risky_ports_display = [
                (22, "SSH", True), (3389, "RDP", True),
                (445, "SMB", True), (4444, "Backdoor", True)
            ]
            for i, (port, service, risky) in enumerate(risky_ports_display):
                with port_cols[i]:
                    st_obj.markdown(f"""
                    <div style='background:rgba(239,68,68,0.06);
                                border:1px solid rgba(239,68,68,0.2);
                                border-radius:8px;padding:10px;text-align:center;'>
                        <div style='font-family:Rajdhani,sans-serif;font-size:20px;
                                    font-weight:700;color:#ef4444;'>{port}</div>
                        <div style='font-family:Share Tech Mono,monospace;font-size:10px;
                                    color:#ef4444;'>{service}</div>
                        <div style='font-family:Exo 2,sans-serif;font-size:9px;
                                    color:#4a7090;margin-top:2px;'>Check manually</div>
                    </div>
                    """, unsafe_allow_html=True)

            st_obj.info(
                "💡 For full Nmap port scanning, run Aegis Probe locally "
                "on your Windows machine where Nmap 7.99 is installed."
            )

        st_obj.markdown("</div>", unsafe_allow_html=True)