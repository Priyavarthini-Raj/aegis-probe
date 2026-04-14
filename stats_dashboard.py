# stats_dashboard.py
# Statistics and analytics dashboard for Aegis Probe

import plotly.express as px
import plotly.graph_objects as go
import pandas as pd
import json
from evidence_ledger import get_all_investigations


def get_stats_data():
    """
    Pulls all investigations and converts to a pandas DataFrame
    """
    rows = get_all_investigations()

    if not rows:
        return None

    data = []
    for row in rows:
        # Parse keywords
        try:
            keywords = json.loads(row[4]) if row[4] else []
        except:
            keywords = []

        # Parse probe results
        try:
            probes = json.loads(row[6]) if row[6] else []
        except:
            probes = []

        # Get highest abuse score from probes
        max_abuse = 0
        max_vt = 0
        for probe in probes:
            ab = probe.get("abuseipdb") or {}
            vt = probe.get("virustotal") or {}
            score = ab.get("abuse_confidence_score", 0) or 0
            vt_score = vt.get("malicious_count", 0) or 0
            if score > max_abuse:
                max_abuse = score
            if vt_score > max_vt:
                max_vt = vt_score

        data.append({
            "id": row[0],
            "timestamp": row[1],
            "alert": row[2][:50] + "..." if len(str(row[2])) > 50 else row[2],
            "keywords": ", ".join(keywords) if keywords else "none",
            "verdict": "Dangerous" if "DANGEROUS" in str(row[7]) else "Suspicious",
            "max_abuse_score": max_abuse,
            "max_vt_engines": max_vt,
            "num_keywords": len(keywords),
        })

    df = pd.DataFrame(data)
    df["timestamp"] = pd.to_datetime(df["timestamp"])
    df["date"] = df["timestamp"].dt.date
    return df


def render_stats(st):
    """
    Renders the full statistics dashboard in Streamlit
    """
    st.markdown("""
    <div style='text-align:center; padding: 10px 0 20px 0;'>
      <h1 style='font-size:32px; color:#58a6ff !important;'>📊 AEGIS PROBE ANALYTICS</h1>
      <p style='color:#8b949e; font-size:13px; letter-spacing:2px;'>INVESTIGATION STATISTICS & THREAT TRENDS</p>
    </div>
    """, unsafe_allow_html=True)

    df = get_stats_data()

    if df is None or df.empty:
        st.warning("⚠️ No investigations yet! Run some investigations first.")
        return

    # ── Top Metrics ──
    total = len(df)
    dangerous = len(df[df["verdict"] == "Dangerous"])
    suspicious = len(df[df["verdict"] == "Suspicious"])
    avg_abuse = round(df["max_abuse_score"].mean(), 1)

    m1, m2, m3, m4 = st.columns(4)
    with m1: st.metric("Total Investigations", total)
    with m2: st.metric("🔴 Dangerous", dangerous, f"{round(dangerous/total*100)}%")
    with m3: st.metric("🟡 Suspicious", suspicious, f"{round(suspicious/total*100)}%")
    with m4: st.metric("Avg Abuse Score", f"{avg_abuse}%")

    st.divider()

    # ── Row 1: Pie + Bar ──
    c1, c2 = st.columns(2)

    with c1:
        st.markdown("#### 🥧 Verdict Distribution")
        verdict_counts = df["verdict"].value_counts().reset_index()
        verdict_counts.columns = ["Verdict", "Count"]
        fig_pie = px.pie(
            verdict_counts,
            names="Verdict",
            values="Count",
            color="Verdict",
            color_discrete_map={
                "Dangerous": "#f85149",
                "Suspicious": "#d29922"
            },
            hole=0.4
        )
        fig_pie.update_layout(
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(0,0,0,0)",
            font_color="#c9d1d9",
            legend=dict(font=dict(color="#c9d1d9")),
            margin=dict(t=20, b=20, l=20, r=20)
        )
        st.plotly_chart(fig_pie, use_container_width=True)

    with c2:
        st.markdown("#### 📊 Abuse Score Per Case")
        fig_bar = px.bar(
            df,
            x="id",
            y="max_abuse_score",
            color="verdict",
            color_discrete_map={
                "Dangerous": "#f85149",
                "Suspicious": "#d29922"
            },
            labels={"id": "Case #", "max_abuse_score": "Abuse Score (%)"},
        )
        fig_bar.update_layout(
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(0,0,0,0)",
            font_color="#c9d1d9",
            xaxis=dict(gridcolor="#21262d", color="#c9d1d9"),
            yaxis=dict(gridcolor="#21262d", color="#c9d1d9"),
            legend=dict(font=dict(color="#c9d1d9")),
            margin=dict(t=20, b=20, l=20, r=20)
        )
        st.plotly_chart(fig_bar, use_container_width=True)

    st.divider()

    # ── Row 2: Timeline + VT Engines ──
    c3, c4 = st.columns(2)

    with c3:
        st.markdown("#### 📅 Investigations Over Time")
        timeline = df.groupby("date").size().reset_index(name="count")
        fig_line = px.line(
            timeline,
            x="date",
            y="count",
            markers=True,
            labels={"date": "Date", "count": "Investigations"},
            color_discrete_sequence=["#58a6ff"]
        )
        fig_line.update_layout(
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(0,0,0,0)",
            font_color="#c9d1d9",
            xaxis=dict(gridcolor="#21262d", color="#c9d1d9"),
            yaxis=dict(gridcolor="#21262d", color="#c9d1d9"),
            margin=dict(t=20, b=20, l=20, r=20)
        )
        st.plotly_chart(fig_line, use_container_width=True)

    with c4:
        st.markdown("#### 🧬 VirusTotal Engines Per Case")
        fig_vt = px.bar(
            df,
            x="id",
            y="max_vt_engines",
            color="verdict",
            color_discrete_map={
                "Dangerous": "#f85149",
                "Suspicious": "#d29922"
            },
            labels={"id": "Case #", "max_vt_engines": "Malicious Engines"},
        )
        fig_vt.update_layout(
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(0,0,0,0)",
            font_color="#c9d1d9",
            xaxis=dict(gridcolor="#21262d", color="#c9d1d9"),
            yaxis=dict(gridcolor="#21262d", color="#c9d1d9"),
            legend=dict(font=dict(color="#c9d1d9")),
            margin=dict(t=20, b=20, l=20, r=20)
        )
        st.plotly_chart(fig_vt, use_container_width=True)

    st.divider()

    # ── Row 3: Scatter + Table ──
    st.markdown("#### 🔵 Abuse Score vs VirusTotal Engines")
    fig_scatter = px.scatter(
        df,
        x="max_abuse_score",
        y="max_vt_engines",
        color="verdict",
        size="num_keywords",
        hover_data=["id", "alert"],
        color_discrete_map={
            "Dangerous": "#f85149",
            "Suspicious": "#d29922"
        },
        labels={
            "max_abuse_score": "Abuse Score (%)",
            "max_vt_engines": "VT Malicious Engines"
        }
    )
    fig_scatter.update_layout(
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        font_color="#c9d1d9",
        xaxis=dict(gridcolor="#21262d", color="#c9d1d9"),
        yaxis=dict(gridcolor="#21262d", color="#c9d1d9"),
        legend=dict(font=dict(color="#c9d1d9")),
        margin=dict(t=20, b=20, l=20, r=20)
    )
    st.plotly_chart(fig_scatter, use_container_width=True)

    st.divider()

    # ── Full Case Table ──
    st.markdown("#### 📋 All Investigations")
    display_df = df[["id", "timestamp", "alert", "verdict",
                      "max_abuse_score", "max_vt_engines", "keywords"]].copy()
    display_df.columns = ["Case #", "Timestamp", "Alert",
                          "Verdict", "Abuse Score %", "VT Engines", "Keywords"]
    st.dataframe(
        display_df,
        use_container_width=True,
        hide_index=True
    )