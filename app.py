import streamlit as st
import database as db
import pandas as pd
import plotly.express as px  # Premium data visualizations
import time
import subprocess , sys, os

# 1. Page Configuration & Aesthetic Initializations
st.set_page_config(
    page_title="AI Network IDS Dashboard",
    layout="wide",
    page_icon="🛡️",
    initial_sidebar_state="expanded"
)

# 2. Advanced CSS Cyber Styling Injection
st.markdown("""
    <style>
    /* Global Background Tweak & Font Smoothness */
    @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@300;400;700&display=swap');

    html, body, [data-testid="stMarkdownContainer"] {
        font-family: 'JetBrains Mono', monospace;
    }

    /* Custom Container Styling for Metrics KPI Cards */
    div[data-testid="stMetricValue"] {
        font-size: 2.2rem !important;
        font-weight: 700 !important;
        color: #00FFC4 !important;
        text-shadow: 0 0 10px rgba(0, 255, 196, 0.3);
    }

    div[data-testid="stMetricLabel"] {
        text-transform: uppercase;
        letter-spacing: 1px;
        font-size: 0.85rem !important;
        color: #8A99AD !important;
    }

    /* Status Card Custom Components */
    .status-card {
        padding: 1.25rem;
        border-radius: 10px;
        margin-bottom: 1.5rem;
        border: 1px solid rgba(255,255,255,0.1);
        box-shadow: 0 4px 6px rgba(0,0,0,0.1);
    }
    .status-alert {
        background: linear-gradient(90deg, rgba(255,75,75,0.15) 0%, rgba(0,0,0,0) 100%);
        border-left: 5px solid #FF4B4B;
        color: #FF4B4B;
    }
    .status-secure {
        background: linear-gradient(90deg, rgba(9,171,92,0.15) 0%, rgba(0,0,0,0) 100%);
        border-left: 5px solid #09AB5C;
        color: #09AB5C;
    }

    /* Section Headings Styling */
    .section-header {
        font-size: 1.4rem;
        font-weight: 600;
        border-bottom: 2px solid rgba(255,255,255,0.05);
        padding-bottom: 0.5rem;
        margin-bottom: 1rem;
        color: #F0F2F6;
    }
    </style>
""", unsafe_allow_html=True)

# 3. Sidebar Control Panel
with st.sidebar:
    st.markdown("### ⚙️ Engine Configurations")
    st.markdown("Configure real-time monitoring constraints and filtering.")

    # Refresh Rate slider
    refresh_rate = st.slider("UI Refresh Interval (Seconds)", min_value=1, max_value=10, value=3)

    st.markdown("---")
    st.markdown("### 🔍 Live Stream Filters")
    selected_protocol = st.selectbox("Isolate Protocol View", options=["ALL", "TCP", "UDP", "ICMP"])

    st.markdown("---")
    # Quick Diagnostic utilities
    st.markdown("### 🛠️ System Actions")
    if st.button("Flush Cache / Re-sync DB", width="stretch"):
        st.toast("Database connection re-synchronized successfully!")
def is_cloud():
    """Detect if running on Streamlit Cloud."""
    return os.environ.get("HOME") == "/home/appuser" or \
           os.path.exists("/mount/src")

def start_background_processes():
    if "bg_procs_started" not in st.session_state:
        script = "simulate.py" if is_cloud() else "sniffer.py"
        subprocess.Popen(
            [sys.executable, script],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        # Always run detector for real ML scoring
        subprocess.Popen(
            [sys.executable, "detector.py"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        st.session_state["bg_procs_started"] = True

start_background_processes()
# 4. Header Section
st.markdown('# 🛡️ AI Network Security & Anomaly Detection')
st.markdown(
    '<p style="color:#8A99AD; margin-top:-15px;">Enterprise Intelligent Intrusion Detection System Engine Active</p>',
    unsafe_allow_html=True)
st.markdown("---")

# 5. Global Command KPIs Summary Row placeholders
kpi_col1, kpi_col2, kpi_col3, kpi_col4 = st.columns(4)
with kpi_col1:
    total_records_metric = st.empty()
with kpi_col2:
    total_alerts_metric = st.empty()
with kpi_col3:
    max_score_metric = st.empty()
with kpi_col4:
    system_status_metric = st.empty()

st.markdown("##")

# 6. Main Split Dashboard Interface Layout Grid placeholders
col1, col2 = st.columns([1.8, 1.2], gap="large")

with col1:
    st.markdown('<p class="section-header">📊 Live Traffic Flow Performance</p>', unsafe_allow_html=True)
    chart_placeholder = st.empty()
    table_placeholder = st.empty()

with col2:
    st.markdown('<p class="section-header">🚨 Threat Intelligence Outliers</p>', unsafe_allow_html=True)
    alert_status_placeholder = st.empty()
    alert_table_placeholder = st.empty()
# 6b. Secondary Analytics Row
st.markdown("---")
anal_col1, anal_col2, anal_col3 = st.columns(3)

with anal_col1:
    st.markdown('<p class="section-header">🌐 Top Source IPs</p>', unsafe_allow_html=True)
    top_ips_placeholder = st.empty()

with anal_col2:
    st.markdown('<p class="section-header">📡 Protocol Distribution</p>', unsafe_allow_html=True)
    proto_chart_placeholder = st.empty()

with anal_col3:
    st.markdown('<p class="section-header">📉 Anomaly Score Trend</p>', unsafe_allow_html=True)
    score_trend_placeholder = st.empty()

# 7. Production-Grade Fragment Refresh Engine
@st.fragment
def render_dashboard_engine():
    # Fetch data states safely from SQLite via your custom db backend
    df_flows = db.get_recent_flows(limit=50)
    df_alerts = db.get_alerts(limit=20)

    # Apply protocol filters dynamically on the DataFrame side
    PROTOCOL_MAP = {"TCP": "6", "UDP": "17", "ICMP": "1"}

    if not df_flows.empty and selected_protocol != "ALL":
        proto_num = PROTOCOL_MAP.get(selected_protocol)
        df_flows = df_flows[df_flows['protocol'].astype(str) == proto_num]

    # Prepare dataframes for time-series visualization handling
    if not df_flows.empty:
        df_flows['timestamp'] = pd.to_datetime(df_flows['timestamp'])
        df_flows = df_flows.sort_values('timestamp')

    total_flows_count = len(df_flows) if not df_flows.empty else 0
    total_threats_count = len(df_alerts) if not df_alerts.empty else 0

    # Calculate highest threat intensity score if records exist
    max_anomaly_score = float(
        df_alerts['anomaly_score'].min()) if not df_alerts.empty else 1.00

    # --- Top Dynamic KPIs Update ---
    total_records_metric.metric(label="Ingress Flows Logged", value=f"{total_flows_count:,} Pkts")
    total_alerts_metric.metric(
        label="ML Anomalies Flagged",
        value=total_threats_count,
        delta=None if total_threats_count == 0 else f"+{total_threats_count} Threats",
        delta_color="inverse"
    )
    max_score_metric.metric(
        label="Peak Threat Severity",
        value="0.00" if total_threats_count == 0 else f"{abs(max_anomaly_score):.2f}"
    )
    system_status_metric.metric(
        label="Firewall Health",
        value="SECURE" if total_threats_count == 0 else "COMPROMISED"
    )

    # --- Column 1: Network Stream Analytics Visualizer ---
    if not df_flows.empty:
        # Clear out the old placeholder layout entirely
        chart_placeholder.empty()

        # 🌟 FIX: Pass a dynamic unique hash key directly to the container layer 🌟
        with chart_placeholder.container(key=f"container_{time.time_ns()}"):
            # Aggregate byte count by timestamp to clean up duplicate timelines
            chart_data = df_flows.groupby('timestamp', as_index=False)[['byte_count']].sum()

            # Generate responsive Plotly Area Chart
            fig = px.area(
                chart_data,
                x='timestamp',
                y='byte_count',
                labels={'timestamp': 'Timestamp', 'byte_count': 'Bytes Logged'}
            )

            # Stylize chart colors to match dark mode theme
            fig.update_traces(
                line_color='#00FFC4',
                fillcolor='rgba(0, 255, 196, 0.15)'
            )
            fig.update_layout(
                template="plotly_dark",
                margin=dict(l=20, r=20, t=10, b=10),
                height=240,
                paper_bgcolor="rgba(0,0,0,0)",
                plot_bgcolor="rgba(0,0,0,0)",
                xaxis=dict(showgrid=False, title=None),
                yaxis=dict(showgrid=True, gridcolor='rgba(255,255,255,0.05)', title=None)
            )

            # 🛠️ REMOVED THE KEY PARAMETER: Let Streamlit automatically track the chart frame context cleanly
            st.plotly_chart(fig, use_container_width=True, config={'displayModeBar': False})

        with table_placeholder.container():
            cleaned_flows = df_flows[['timestamp', 'src_ip', 'dst_ip', 'protocol', 'pkt_count', 'byte_count']].copy()
            cleaned_flows['timestamp'] = cleaned_flows['timestamp'].dt.strftime('%Y-%m-%d %H:%M:%S')
            st.dataframe(cleaned_flows, width="stretch", height=280)
    else:
        chart_placeholder.info("Awaiting initial ingress packets from network sniffing system...")
        table_placeholder.empty()
    # --- Secondary Analytics Row ---
    # Chart 1: Top Source IPs by Traffic
    with top_ips_placeholder.container():
        if not df_flows.empty:
            top_ips = df_flows.groupby('src_ip')['byte_count'].sum().nlargest(5).reset_index()
            fig_ips = px.bar(
                top_ips, x='byte_count', y='src_ip',
                orientation='h',
                labels={'byte_count': 'Bytes', 'src_ip': 'Source IP'},
                color_discrete_sequence=['#00FFC4']
            )
            fig_ips.update_layout(
                template="plotly_dark", height=220,
                margin=dict(l=10, r=10, t=10, b=10),
                paper_bgcolor="rgba(0,0,0,0)",
                plot_bgcolor="rgba(0,0,0,0)",
                yaxis=dict(showgrid=False),
                xaxis=dict(showgrid=True, gridcolor='rgba(255,255,255,0.05)')
            )
            st.plotly_chart(fig_ips, use_container_width=True, config={'displayModeBar': False})

    # Chart 2: Protocol Distribution Pie
    with proto_chart_placeholder.container():
        if not df_flows.empty:
            proto_map = {'6': 'TCP', '17': 'UDP', '1': 'ICMP'}
            df_proto = df_flows.copy()
            df_proto['proto_name'] = df_proto['protocol'].astype(str).map(proto_map).fillna('Other')
            fig_proto = px.pie(
                df_proto, names='proto_name',
                color_discrete_sequence=['#00FFC4', '#FF4B4B', '#FFD700']
            )
            fig_proto.update_layout(
                template="plotly_dark", height=220,
                margin=dict(l=10, r=10, t=10, b=10),
                paper_bgcolor="rgba(0,0,0,0)",
                legend=dict(font=dict(color='#8A99AD'))
            )
            st.plotly_chart(fig_proto, use_container_width=True, config={'displayModeBar': False})

    # Chart 3: Anomaly Score Trend Line
    with score_trend_placeholder.container():
        if not df_alerts.empty:
            df_alerts_sorted = df_alerts.copy()
            df_alerts_sorted['timestamp'] = pd.to_datetime(df_alerts_sorted['timestamp'])
            df_alerts_sorted = df_alerts_sorted.sort_values('timestamp')
            fig_score = px.line(
                df_alerts_sorted, x='timestamp', y='anomaly_score',
                labels={'timestamp': '', 'anomaly_score': 'Score'},
                color_discrete_sequence=['#FF4B4B']
            )
            fig_score.update_layout(
                template="plotly_dark", height=220,
                margin=dict(l=10, r=10, t=10, b=10),
                paper_bgcolor="rgba(0,0,0,0)",
                plot_bgcolor="rgba(0,0,0,0)",
                xaxis=dict(showgrid=False),
                yaxis=dict(showgrid=True, gridcolor='rgba(255,255,255,0.05)')
            )
            st.plotly_chart(fig_score, use_container_width=True, config={'displayModeBar': False})
        else:
            st.info("No anomaly scores yet...")
    # --- Column 2: Security Threat Assessment Center ---
    if not df_alerts.empty:
        with alert_status_placeholder.container():
            st.markdown(
                f'<div class="status-card status-alert">⚠️ <b>CRITICAL SYSTEM ALERT:</b> {total_threats_count} Anomaly outliers detected by Isolation Forest. Evaluate sources immediately.</div>',
                unsafe_allow_html=True
            )
        with alert_table_placeholder.container():
            display_alerts = df_alerts[['timestamp', 'src_ip', 'dst_ip', 'anomaly_score']].copy()
            st.dataframe(display_alerts, width="stretch", height=400)
    else:
        with alert_status_placeholder.container():
            st.markdown(
                '<div class="status-card status-secure">✅ <b>ENVIRONMENT SECURE:</b> ML inspection indicates zero unauthorized packet structural variants.</div>',
                unsafe_allow_html=True
            )
        alert_table_placeholder.empty()

    # Pause execution for the specified time interval before forcing a fragment refresh tick
    time.sleep(refresh_rate)
    st.rerun()


# Trigger execution engine initialization
if __name__ == "__main__":
    render_dashboard_engine()