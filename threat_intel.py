# threat_intel.py
# Threat intelligence using local Nmap scanning
# Free, unlimited, no API key needed!

import nmap
import socket
import requests


def check_nmap(ip):
    """
    Uses local Nmap to scan open ports and services on the IP
    Free and unlimited — runs on your machine!
    """
    print(f"\n[*] Scanning {ip} with Nmap...")

    try:
        # Skip private IPs
        private_ranges = ["192.168.", "10.", "172.16.", "127.", "0."]
        for private in private_ranges:
            if ip.startswith(private):
                print(f"[!] {ip} is private — skipping Nmap")
                return None

        # Initialize Nmap scanner
        nm = nmap.PortScanner()

        # Scan top 100 common ports (-F = fast scan)
        print(f"[*] Running fast port scan on {ip}...")
        nm.scan(ip, arguments="-F -T4 --open")

        open_ports = []
        port_details = []

        if ip in nm.all_hosts():
            for proto in nm[ip].all_protocols():
                ports = nm[ip][proto].keys()
                for port in sorted(ports):
                    state = nm[ip][proto][port]["state"]
                    if state == "open":
                        service = nm[ip][proto][port].get("name", "unknown")
                        version = nm[ip][proto][port].get("version", "")
                        open_ports.append(port)
                        port_details.append({
                            "port": port,
                            "service": service,
                            "version": version,
                            "state": state
                        })

        # ── Reverse DNS ──
        hostname = ""
        try:
            hostname = socket.gethostbyaddr(ip)[0]
        except:
            hostname = ""

        # ── Tor Detection ──
        is_tor = any(
            keyword in hostname.lower()
            for keyword in ["tor", "exit", "relay", "anonymize"]
        )

        # ── Dangerous Port Detection ──
        dangerous_ports_map = {
            22: "SSH", 23: "Telnet",
            3389: "RDP", 445: "SMB",
            1433: "MSSQL", 3306: "MySQL",
            21: "FTP", 5900: "VNC",
            4444: "Metasploit", 1080: "SOCKS Proxy",
            8080: "HTTP Proxy", 8443: "HTTPS Alt"
        }
        found_dangerous = [
            f"{dangerous_ports_map[p]} ({p})"
            for p in open_ports
            if p in dangerous_ports_map
        ]

        result = {
            "ip": ip,
            "open_ports": open_ports[:15],
            "port_details": port_details[:15],
            "found_dangerous": found_dangerous,
            "hostname": hostname,
            "is_tor": is_tor,
            "is_risky": len(found_dangerous) > 0 or is_tor,
            "scan_status": "success"
        }

        print(f"[+] Nmap: {len(open_ports)} open ports found")
        if is_tor:
            print(f"[!] TOR EXIT NODE DETECTED!")
        if found_dangerous:
            print(f"[!] Dangerous ports: {found_dangerous}")

        return result

    except nmap.PortScannerError as e:
        print(f"[!] Nmap error: {e}")
        return {
            "ip": ip,
            "error": "Nmap not found — please install from nmap.org"
        }

    except Exception as e:
        print(f"[!] Scan failed: {e}")
        return {"ip": ip, "error": str(e)}


def run_nmap_probes(ips):
    """
    Runs Nmap scan on a list of IPs
    """
    results = []
    for ip in ips:
        result = {
            "ip": ip,
            "nmap": check_nmap(ip)
        }
        results.append(result)
    return results


def render_threat_intel(st, ips):
    """
    Renders Nmap scan results in Streamlit
    """
    if not ips:
        st.info("No IPs to check.")
        return

    st.markdown("### 🎯 Nmap Port Intelligence")
    st.caption(
        "Local port scanning — free, unlimited, "
        "industry standard tool!"
    )

    with st.spinner(
        "🔍 Scanning ports with Nmap — this may take 30-60 seconds..."
    ):
        results = run_nmap_probes(ips)

    for result in results:
        ip = result["ip"]
        nmap_data = result.get("nmap")

        st.markdown(f"#### 🌐 IP: `{ip}`")

        if nmap_data is None:
            st.info("ℹ️ Private IP — scan skipped")
            st.divider()
            continue

        if "error" in nmap_data:
            st.warning(f"⚠️ {nmap_data['error']}")
            st.divider()
            continue

        # ── Tor Warning ──
        if nmap_data.get("is_tor"):
            st.error(
                "🧅 TOR EXIT NODE DETECTED — "
                "Attacker hiding identity via Tor network!"
            )

        # ── Metrics ──
        m1, m2, m3 = st.columns(3)
        with m1:
            st.metric(
                "Open Ports",
                len(nmap_data.get("open_ports", []))
            )
        with m2:
            st.metric(
                "Dangerous Ports",
                len(nmap_data.get("found_dangerous", []))
            )
        with m3:
            hostname = nmap_data.get("hostname", "N/A") or "N/A"
            st.metric(
                "Hostname",
                hostname[:20] if hostname != "N/A" else "N/A"
            )

        # ── Port Details ──
        c1, c2 = st.columns(2)

        with c1:
            st.markdown("**📡 Open Ports & Services:**")
            if nmap_data.get("port_details"):
                for pd in nmap_data["port_details"]:
                    version = f" — {pd['version']}" \
                        if pd.get("version") else ""
                    st.markdown(
                        f"`{pd['port']}` {pd['service']}{version}"
                    )
            else:
                st.info("No open ports found")

        with c2:
            st.markdown("**⚠️ Dangerous Ports:**")
            if nmap_data.get("found_dangerous"):
                for dp in nmap_data["found_dangerous"]:
                    st.error(f"🚨 {dp}")
            else:
                st.success("✅ No dangerous ports found")

            hostname = nmap_data.get("hostname", "")
            if hostname:
                st.markdown(f"**🌐 Hostname:** `{hostname}`")
                if nmap_data.get("is_tor"):
                    st.markdown("""
                    <div style='background:#3d0000;
                                border:1px solid #f85149;
                                border-radius:8px;
                                padding:10px; margin-top:8px;'>
                        <b style='color:#ffa198;'>🧅 TOR EXIT NODE</b><br>
                        <span style='color:#ffa198; font-size:12px;'>
                        Real attacker identity hidden via Tor
                        </span>
                    </div>
                    """, unsafe_allow_html=True)

        # ── Risk Banner ──
        st.markdown("")
        if nmap_data.get("is_tor"):
            st.error(
                "🔴 CRITICAL — TOR EXIT NODE! "
                "Attacker hiding real identity via Tor!"
            )
        elif nmap_data.get("found_dangerous"):
            st.error(
                f"🔴 HIGH RISK — Dangerous ports open: "
                f"{', '.join(nmap_data['found_dangerous'])}"
            )
        elif nmap_data.get("open_ports"):
            st.warning(
                "🟡 MODERATE — Open ports detected, monitor closely"
            )
        else:
            st.success("🟢 No open ports or risks detected")

        st.divider()


# Test it
if __name__ == "__main__":
    test_ips = ["185.220.101.45", "45.155.205.233"]

    for test_ip in test_ips:
        print(f"\n{'='*40}")
        print(f"Scanning {test_ip} with Nmap...")
        result = check_nmap(test_ip)

        if result and "error" not in result:
            print(f"IP             : {result['ip']}")
            print(f"Open Ports     : {result['open_ports']}")
            print(f"Dangerous Ports: {result['found_dangerous']}")
            print(f"Hostname       : {result['hostname']}")
            print(f"Is Tor         : {result['is_tor']}")
            print(f"Is Risky       : {result['is_risky']}")
        elif result:
            print(f"Info: {result['error']}")
        else:
            print("Scan failed")