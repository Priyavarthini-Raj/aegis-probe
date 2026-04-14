# geo_map.py
# Shows attacker IP locations on an interactive world map using Plotly

import requests
import plotly.graph_objects as go
import streamlit as st
IPINFO_TOKEN = st.secrets.get("IPINFO_TOKEN", "")

def get_ip_location(ip):
    """
    Gets the geographic location of an IP address
    """
    try:
        private_ranges = [
            "192.168.", "10.", "172.16.", "172.17.",
            "172.18.", "172.19.", "172.20.", "127.", "0."
        ]
        for private in private_ranges:
            if ip.startswith(private):
                return None

        response = requests.get(
            f"https://ipinfo.io/{ip}",
            headers={"Authorization": f"Bearer {IPINFO_TOKEN}"},
            timeout=10
        )

        if response.status_code == 200:
            data = response.json()
            loc = data.get("loc", "").split(",")
            if len(loc) == 2:
                return {
                    "ip": ip,
                    "lat": float(loc[0]),
                    "lon": float(loc[1]),
                    "city": data.get("city", "Unknown"),
                    "region": data.get("region", "Unknown"),
                    "country": data.get("country", "Unknown"),
                    "org": data.get("org", "Unknown"),
                }
    except Exception as e:
        print(f"[!] Geo lookup failed for {ip}: {e}")
    return None


def build_plotly_map(probe_results):
    """
    Builds an interactive Plotly map with attacker locations
    """
    lats, lons, texts, colors, sizes = [], [], [], [], []

    locations_found = []

    for probe in probe_results:
        ip = probe.get("ip", "")
        verdict = probe.get("verdict", "")
        location = get_ip_location(ip)

        if location:
            locations_found.append(location)

            ab = probe.get("abuseipdb") or {}
            vt = probe.get("virustotal") or {}
            abuse_score = ab.get("abuse_confidence_score", 0)
            vt_engines = vt.get("malicious_count", 0)

            lats.append(location["lat"])
            lons.append(location["lon"])
            texts.append(
                f"IP: {ip}<br>"
                f"City: {location['city']}, {location['country']}<br>"
                f"Org: {location['org']}<br>"
                f"Abuse Score: {abuse_score}%<br>"
                f"VT Engines: {vt_engines}<br>"
                f"Verdict: {verdict}"
            )
            colors.append(
                "red" if "DANGEROUS" in verdict else "orange"
            )
            sizes.append(
                20 if "DANGEROUS" in verdict else 14
            )

    if not lats:
        return None, []

    fig = go.Figure()

    # Add scatter points on map
    fig.add_trace(go.Scattergeo(
        lat=lats,
        lon=lons,
        text=texts,
        hoverinfo="text",
        mode="markers",
        marker=dict(
            size=sizes,
            color=colors,
            opacity=0.85,
            line=dict(width=1, color="white")
        )
    ))

    fig.update_layout(
        geo=dict(
            projection_type="natural earth",
            showland=True,
            landcolor="#1a1f2e",
            showocean=True,
            oceancolor="#0d1117",
            showcoastlines=True,
            coastlinecolor="#30363d",
            showframe=False,
            showcountries=True,
            countrycolor="#30363d",
            bgcolor="#0d1117",
        ),
        paper_bgcolor="#0d1117",
        plot_bgcolor="#0d1117",
        margin=dict(l=0, r=0, t=0, b=0),
        height=450,
        showlegend=False
    )

    return fig, locations_found


def render_map(st, probe_results):
    """
    Renders the geolocation map in Streamlit
    """
    st.markdown("#### 🌍 Attacker Location Map")

    if not probe_results:
        st.info("No probe results to map yet.")
        return

    with st.spinner("🌍 Looking up IP locations..."):
        fig, locations = build_plotly_map(probe_results)

    if not locations or fig is None:
        st.warning("⚠️ No public IPs to map — all IPs are private/local.")
        return

    # Show location summary
    st.markdown(f"**{len(locations)} public IP(s) located:**")
    for loc in locations:
        st.markdown(
            f"📍 `{loc['ip']}` → {loc['city']}, "
            f"{loc['region']}, {loc['country']} "
            f"| Org: {loc['org']}"
        )

    # Render Plotly map
    st.plotly_chart(fig, use_container_width=True)


# Test it
if __name__ == "__main__":
    location = get_ip_location("185.220.101.45")
    if location:
        print(f"[+] IP Location Found!")
        print(f"    City    : {location['city']}")
        print(f"    Country : {location['country']}")
        print(f"    Coords  : {location['lat']}, {location['lon']}")
        print(f"    Org     : {location['org']}")
    else:
        print("[!] Location not found")