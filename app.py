import random
import statistics
import ipaddress
from datetime import datetime, timezone
from pathlib import Path

import altair as alt
import pandas as pd
import streamlit as st

from collectors.structured_logs import ingest_event_text
from services.event_aggregation import (
    aggregate_device_events,
    count_scoring_usable_events,
    uploaded_batch_status,
)
from services.scoring import (
    NUMERIC_FIELDS,
    REQUIRED,
    analyse,
    build_investigation_report,
    filter_records,
)

st.set_page_config(page_title="GhostSignal | Security Triage", page_icon="🛡️", layout="wide")

st.markdown(
    """
    <style>
    :root {
        --gs-bg: #080b10;
        --gs-sidebar: #10151d;
        --gs-panel: #10151d;
        --gs-raised: #171e28;
        --gs-border: #27313d;
        --gs-text: #f3f6fa;
        --gs-muted: #98a5b5;
        --gs-cyan: #53e0d0;
        --gs-red: #ff646e;
        --gs-amber: #e8b45e;
        --gs-green: #65d6a2;
    }
    html, body, [data-testid="stAppViewContainer"] {
        background: var(--gs-bg);
        color: var(--gs-text);
        font-family: "Segoe UI", "Inter", "Roboto", sans-serif;
    }
    *, *::before, *::after {
        box-sizing: border-box;
    }
    [data-testid="stHeader"] {
        background: transparent;
    }
    [data-testid="stAppViewContainer"] .main .block-container {
        width: 100%;
        max-width: 1580px;
        min-width: 0;
        padding: 0.95rem 2.25rem 3.5rem;
    }
    [data-testid="stVerticalBlock"],
    [data-testid="stHorizontalBlock"],
    [data-testid="column"] {
        min-width: 0;
        max-width: 100%;
    }
    [data-testid="stHorizontalBlock"] {
        align-items: stretch;
    }
    [data-testid="stSidebar"] {
        background: var(--gs-sidebar);
        border-right: 1px solid var(--gs-border);
    }
    [data-testid="stSidebar"] > div:first-child {
        padding-top: 1.25rem;
    }
    h1, h2, h3, [data-testid="stMetricValue"] {
        color: var(--gs-text);
    }
    h1 {
        margin: 0.1rem 0 0.35rem;
        font-size: clamp(2rem, 3vw, 2.7rem);
        font-weight: 720;
        letter-spacing: -0.055em;
    }
    h2 {
        margin: 2rem 0 0.35rem;
        font-size: 1.2rem;
        font-weight: 680;
        letter-spacing: -0.025em;
        overflow-wrap: anywhere;
    }
    h3 {
        color: var(--gs-text);
        font-weight: 650;
        overflow-wrap: anywhere;
    }
    p, label, [data-testid="stMarkdownContainer"] {
        color: var(--gs-text);
    }
    [data-testid="stCaptionContainer"] {
        color: var(--gs-muted);
    }
    [data-testid="stMetric"] {
        min-height: 112px;
        padding: 17px 18px;
        background: linear-gradient(145deg, #171e28 0%, #111720 100%);
        border: 1px solid var(--gs-border);
        border-radius: 9px;
        box-shadow: 0 10px 24px rgba(0, 0, 0, 0.14);
        transition: border-color 160ms ease, transform 160ms ease;
    }
    [data-testid="stMetric"]:hover {
        border-color: #3a4a59;
        transform: translateY(-1px);
    }
    [data-testid="stMetricLabel"] {
        color: var(--gs-muted);
        font-size: 0.78rem;
        font-weight: 600;
        letter-spacing: 0.025em;
    }
    [data-testid="stMetricValue"] {
        font-size: 1.7rem;
        font-weight: 700;
        letter-spacing: -0.035em;
    }
    .st-key-gs-metric-total [data-testid="stMetric"] {
        border-left: 2px solid var(--gs-cyan);
    }
    .st-key-gs-metric-high [data-testid="stMetric"] {
        border-left: 2px solid var(--gs-red);
    }
    .st-key-gs-metric-triggered [data-testid="stMetric"] {
        border-left: 2px solid var(--gs-amber);
    }
    .st-key-gs-metric-quality [data-testid="stMetric"] {
        border-left: 2px solid var(--gs-amber);
    }
    [data-testid="stAlert"] {
        border-radius: 8px;
        border: 1px solid var(--gs-border);
    }
    [data-testid="stDataFrame"] {
        width: 100%;
        max-width: 100%;
        border: 1px solid var(--gs-border);
        border-radius: 9px;
        overflow-x: auto;
        overflow-y: hidden;
    }
    [data-testid="stDataFrame"] > div {
        max-width: 100%;
    }
    [data-baseweb="select"] > div,
    [data-testid="stTextInput"] input,
    [data-testid="stNumberInput"] input,
    [data-testid="stFileUploader"] section {
        background: var(--gs-raised);
        border-color: var(--gs-border);
        border-radius: 7px;
        color: var(--gs-text);
        transition: border-color 150ms ease, box-shadow 150ms ease;
    }
    [data-baseweb="select"] > div:hover,
    [data-testid="stTextInput"] input:hover,
    [data-testid="stNumberInput"] input:hover,
    [data-testid="stFileUploader"] section:hover {
        border-color: #3a4a59;
    }
    [data-baseweb="select"] > div:focus-within,
    [data-testid="stTextInput"] input:focus,
    [data-testid="stNumberInput"] input:focus {
        border-color: var(--gs-cyan);
        box-shadow: 0 0 0 1px rgba(83, 224, 208, 0.22);
    }
    [data-testid="stFileUploader"] section {
        border: 1px dashed #3a4a59;
    }
    [data-testid="stExpander"] {
        border-color: var(--gs-border);
        border-radius: 9px;
        background: rgba(16, 21, 29, 0.48);
    }
    div[data-testid="stVerticalBlockBorderWrapper"] {
        border-color: var(--gs-border);
        border-radius: 10px;
        background: linear-gradient(145deg, rgba(23, 30, 40, 0.72), rgba(16, 21, 29, 0.76));
    }
    div[data-testid="stVerticalBlockBorderWrapper"]:hover {
        border-color: #344251;
    }
    [data-testid="stDownloadButton"] button,
    [data-testid="stButton"] button {
        min-height: 2.55rem;
        border: 1px solid #34524f;
        border-radius: 7px;
        background: linear-gradient(135deg, #1b3939, #15302f);
        color: var(--gs-cyan);
        font-weight: 650;
        transition: border-color 150ms ease, background 150ms ease, transform 150ms ease;
    }
    [data-testid="stDownloadButton"] button:hover,
    [data-testid="stButton"] button:hover {
        border-color: var(--gs-cyan);
        background: #1b3d3b;
        color: #d9fffa;
        transform: translateY(-1px);
    }
    [data-testid="stDownloadButton"] button:disabled {
        border-color: var(--gs-border);
        background: #171e28;
        color: #647181;
    }
    .gs-hero {
        display: flex;
        align-items: center;
        gap: 1.1rem;
        margin: 0.15rem 0 1rem;
        padding: 1.35rem 1.55rem;
        border: 1px solid #26333f;
        border-radius: 12px;
        background:
            radial-gradient(ellipse at 4% 0%, rgba(83, 224, 208, 0.13), transparent 43%),
            linear-gradient(120deg, #121a24 0%, #0e141c 62%, #111a21 100%);
        box-shadow: 0 18px 46px rgba(0, 0, 0, 0.2);
    }
    .gs-brand-mark {
        display: grid;
        width: 3.35rem;
        height: 3.35rem;
        flex: 0 0 3.35rem;
        place-items: center;
        border: 1px solid rgba(83, 224, 208, 0.45);
        border-radius: 10px;
        background: rgba(83, 224, 208, 0.08);
        color: var(--gs-cyan);
        font-size: 1rem;
        font-weight: 800;
        letter-spacing: 0.05em;
    }
    .gs-hero-copy {
        min-width: 0;
        flex: 1;
    }
    .gs-hero-copy h1 {
        color: var(--gs-text);
    }
    .gs-hero-copy p {
        margin: 0;
        color: var(--gs-muted);
        font-size: 0.9rem;
    }
    .gs-eyebrow {
        margin-bottom: 0.2rem;
        color: var(--gs-cyan);
        font-size: 0.67rem;
        font-weight: 750;
        letter-spacing: 0.16em;
    }
    .gs-hero-status {
        display: flex;
        min-width: 205px;
        flex-direction: column;
        align-items: flex-end;
        gap: 0.36rem;
        padding-left: 1rem;
        border-left: 1px solid var(--gs-border);
        color: var(--gs-text);
        font-size: 0.78rem;
        font-weight: 650;
        text-align: right;
    }
    .gs-hero-status,
    .gs-source-status > div,
    .gs-source-note {
        overflow-wrap: anywhere;
    }
    .gs-hero-status small {
        color: var(--gs-muted);
        font-size: 0.7rem;
        font-weight: 450;
    }
    .gs-status-dot {
        display: inline-block;
        width: 0.48rem;
        height: 0.48rem;
        margin-right: 0.4rem;
        border-radius: 50%;
        background: var(--gs-green);
        box-shadow: 0 0 0 3px rgba(101, 214, 162, 0.12);
        vertical-align: middle;
    }
    .gs-trust-note {
        margin: 0.9rem 0 1.4rem;
        padding: 0.72rem 0.9rem;
        border: 1px solid rgba(83, 224, 208, 0.19);
        border-left: 2px solid var(--gs-cyan);
        border-radius: 0 7px 7px 0;
        background: rgba(83, 224, 208, 0.045);
        color: #bdcbd2;
        font-size: 0.78rem;
        line-height: 1.55;
    }
    .gs-section-kicker {
        margin: 1.45rem 0 0.3rem;
        color: var(--gs-cyan);
        font-size: 0.66rem;
        font-weight: 750;
        letter-spacing: 0.14em;
        text-transform: uppercase;
    }
    .gs-source-status {
        display: flex;
        justify-content: space-between;
        align-items: center;
        gap: 1rem;
        margin-bottom: 1rem;
        padding: 0.8rem 0.95rem;
        border: 1px solid var(--gs-border);
        border-radius: 8px;
        background: rgba(8, 11, 16, 0.38);
    }
    .gs-source-status.demo {
        border-left: 2px solid var(--gs-green);
    }
    .gs-source-status.snapshot {
        border-left: 2px solid var(--gs-cyan);
    }
    .gs-source-status.stale {
        border-left: 2px solid var(--gs-red);
    }
    .gs-source-status strong {
        color: var(--gs-text);
        font-size: 0.83rem;
    }
    .gs-source-mode {
        display: inline-block;
        margin-left: 0.65rem;
        color: var(--gs-muted);
        font-size: 0.76rem;
    }
    .gs-source-note {
        color: var(--gs-muted);
        font-size: 0.72rem;
        text-align: right;
    }
    .gs-rule-row {
        display: flex;
        flex-wrap: wrap;
        justify-content: space-between;
        align-items: flex-start;
        gap: 1rem;
        margin: 0.45rem 0;
        padding: 0.75rem 0.85rem;
        border: 1px solid var(--gs-border);
        border-radius: 7px;
        background: rgba(8, 11, 16, 0.38);
    }
    .gs-rule-row strong {
        color: var(--gs-text);
        font-size: 0.82rem;
    }
    .gs-rule-row span {
        display: block;
        margin-top: 0.2rem;
        color: var(--gs-muted);
        font-size: 0.76rem;
        line-height: 1.45;
    }
    .gs-rule-points {
        flex: 0 0 auto;
        color: var(--gs-cyan);
        font-size: 0.8rem;
        font-weight: 750;
    }
    .gs-classification-badge {
        display: inline-block;
        margin: 0.15rem 0 0.85rem;
        padding: 0.32rem 0.6rem;
        border: 1px solid var(--gs-border);
        border-radius: 999px;
        font-size: 0.72rem;
        font-weight: 700;
        letter-spacing: 0.025em;
    }
    .gs-classification-badge.high {
        border-color: rgba(255, 100, 110, 0.42);
        background: rgba(255, 100, 110, 0.1);
        color: var(--gs-red);
    }
    .gs-classification-badge.review {
        border-color: rgba(232, 180, 94, 0.4);
        background: rgba(232, 180, 94, 0.09);
        color: var(--gs-amber);
    }
    .gs-classification-badge.clear {
        border-color: rgba(101, 214, 162, 0.34);
        background: rgba(101, 214, 162, 0.08);
        color: var(--gs-green);
    }
    [data-testid="stSidebar"] [data-testid="stMarkdownContainer"] h2 {
        margin-top: 0.6rem;
        color: var(--gs-text);
        font-size: 0.9rem;
        letter-spacing: 0.02em;
    }
    [data-testid="stSidebar"] hr {
        border-color: var(--gs-border);
    }
    @media (min-width: 721px) and (max-width: 1120px) {
        [data-testid="stAppViewContainer"] .main .block-container {
            padding: 1.25rem 1.35rem 3rem;
        }
        [data-testid="stSidebar"] {
            width: 15rem !important;
            min-width: 15rem !important;
        }
        [data-testid="stHorizontalBlock"] {
            flex-wrap: wrap;
            row-gap: 0.8rem;
        }
        [data-testid="stHorizontalBlock"] > [data-testid="column"] {
            flex: 1 1 calc(50% - 0.5rem) !important;
        }
        [data-testid="stHorizontalBlock"]:has(.st-key-gs-metric-total) > [data-testid="column"] {
            flex: 1 1 calc(50% - 0.5rem) !important;
        }
        .gs-source-status {
            align-items: flex-start;
        }
        .gs-source-note {
            max-width: 42%;
        }
    }
    @media (max-width: 720px) {
        [data-testid="stAppViewContainer"] .main .block-container {
            padding: 1rem 0.85rem 2rem;
        }
        [data-testid="stHorizontalBlock"] {
            flex-wrap: wrap;
            row-gap: 0.7rem;
        }
        [data-testid="stHorizontalBlock"] > [data-testid="column"] {
            flex: 1 1 100% !important;
        }
        [data-testid="stHorizontalBlock"]:has(.st-key-gs-metric-total) > [data-testid="column"] {
            flex: 1 1 calc(50% - 0.35rem) !important;
        }
        .gs-hero {
            align-items: flex-start;
            flex-wrap: wrap;
            padding: 1.1rem;
        }
        .gs-hero-status {
            width: 100%;
            min-width: 0;
            align-items: flex-start;
            padding: 0.75rem 0 0;
            border-top: 1px solid var(--gs-border);
            border-left: 0;
            text-align: left;
        }
        [data-testid="stMetric"] {
            min-height: 100px;
            padding: 12px;
        }
        .gs-source-status {
            align-items: flex-start;
            flex-direction: column;
        }
        .gs-source-note {
            text-align: left;
        }
    }
    </style>
    """,
    unsafe_allow_html=True,
)

SCENARIOS = ["Normal traffic", "Sudden outbound spike", "Repeated elevated traffic"]
MAX_UPLOAD_BYTES = 5 * 1024 * 1024
SOURCE_MODES = [
    "Demo device records",
    "Upload device-summary CSV",
    "Upload JSONL / RFC 5424 logs",
    "Replay bundled sample events",
]

SAMPLE = pd.DataFrame([
    {"device": "Laptop-01", "failed_connections": 1, "external_connections": 5, "unusual_port": 0, "bytes_out": 200_000},
    {"device": "Office-PC-02", "failed_connections": 2, "external_connections": 8, "unusual_port": 0, "bytes_out": 450_000},
    {"device": "Test-Device-03", "failed_connections": 15, "external_connections": 25, "unusual_port": 1, "bytes_out": 6_500_000},
    {"device": "Camera-04", "failed_connections": 12, "external_connections": 3, "unusual_port": 0, "bytes_out": 100_000},
    {"device": "Design-PC-05", "failed_connections": 0, "external_connections": 24, "unusual_port": 0, "bytes_out": 900_000},
    {"device": "Backup-Server-06", "failed_connections": 1, "external_connections": 4, "unusual_port": 0, "bytes_out": 8_000_000},
])


def build_traffic_scenario(scenario: str) -> tuple[pd.DataFrame, float, float | None]:
    """Build reproducible illustrative traffic and compare it with a median baseline."""
    history_rng = random.Random(41)
    historical_normal = [history_rng.uniform(0.75, 1.25) for _ in range(21)]
    baseline_mb = statistics.median(historical_normal)

    intervals = [f"{hour:02d}:00" for hour in range(8, 20)]
    scenario_rng = random.Random(SCENARIOS.index(scenario) + 2026)
    observed = [baseline_mb * scenario_rng.uniform(0.75, 1.35) for _ in intervals]
    if scenario == "Sudden outbound spike":
        observed[-1] = baseline_mb * 5.2
    elif scenario == "Repeated elevated traffic":
        observed[-4:] = [baseline_mb * factor for factor in (3.4, 4.0, 3.6, 4.5)]

    traffic = pd.DataFrame({
        "Interval": intervals,
        "Typical baseline (MB)": [baseline_mb] * len(intervals),
        "Observed traffic (MB)": observed,
    })
    traffic["Anomaly highlight"] = traffic["Observed traffic (MB)"].where(
        traffic["Observed traffic (MB)"] >= 3 * baseline_mb
    )
    latest_mb = float(traffic["Observed traffic (MB)"].iloc[-1])
    ratio = latest_mb / baseline_mb if baseline_mb > 0 else None
    return traffic, baseline_mb, ratio


st.markdown(
    """
    <div class="gs-hero">
      <div class="gs-brand-mark" aria-hidden="true">GS</div>
      <div class="gs-hero-copy">
        <div class="gs-eyebrow">SECURITY OPERATIONS / TRIAGE</div>
        <h1>GhostSignal</h1>
        <p>Explainable device-activity review for supplied summaries and structured event batches.</p>
      </div>
      <div class="gs-hero-status">
        <span><i class="gs-status-dot"></i>Demo-ready · snapshot analysis</span>
        <small>No live network source connected</small>
      </div>
    </div>
    <div class="gs-trust-note">
      GhostSignal reviews uploaded snapshots and bundled demonstrations. It does not monitor a live network,
      use machine learning, or determine whether a device is compromised.
    </div>
    """,
    unsafe_allow_html=True,
)

with st.sidebar:
    st.header("Data source")
    source_mode = st.selectbox("Input mode", SOURCE_MODES)
    uploaded_csv = None
    uploaded_log = None
    internal_network_text = "192.168.0.0/16,10.0.0.0/8,172.16.0.0/12"
    unusual_port_text = ""
    stale_after_minutes = 60
    if source_mode == "Upload device-summary CSV":
        uploaded_csv = st.file_uploader("Upload a device-summary CSV", type=["csv"])
    elif source_mode == "Upload JSONL / RFC 5424 logs":
        uploaded_log = st.file_uploader(
            "Upload JSONL or RFC 5424 syslog",
            type=["jsonl", "ndjson", "log", "txt"],
            help="RFC 5424 is supported when the message portion contains a JSON event object.",
        )
        internal_network_text = st.text_input(
            "Internal network CIDRs",
            value="192.168.0.0/16,10.0.0.0/8,172.16.0.0/12",
            help="Used only to count outbound connections from a configured internal address to an address outside these networks.",
        )
        unusual_port_text = st.text_input(
            "Ports treated as unusual",
            placeholder="e.g. 22, 2323",
            help="The unusual-port rule is unevaluable until a port list is configured.",
        )
        stale_after_minutes = st.number_input(
            "Mark event batch stale after (minutes)",
            min_value=1,
            max_value=10080,
            value=60,
        )
    st.markdown("---")
    st.subheader("Scoring rules")
    st.write("• 10+ failed connections: +30")
    st.write("• 20+ external connections: +25")
    st.write("• Unusual port flag = 1: +25")
    st.write("• Outgoing data > 5,000,000 bytes: +20")
    st.caption("Score is capped at 100. These thresholds are demonstration rules, not validated security standards.")

now = datetime.now(timezone.utc)
accepted_events = []
rejected_events = []
duplicate_events = 0
loaded_at = None
latest_event_at = None
timeline = pd.DataFrame(columns=["timestamp", "event_count"])
scoring_usable_events = 0
event_mode = source_mode in {"Upload JSONL / RFC 5424 logs", "Replay bundled sample events"}
source_status = "Demo Mode" if source_mode in {"Demo device records", "Replay bundled sample events"} else "Configuration Required"
raw = pd.DataFrame(columns=REQUIRED)

if source_mode == "Demo device records":
    raw = SAMPLE.copy()
    st.caption("Showing synthetic device-summary records. No source is connected.")
elif source_mode == "Upload device-summary CSV":
    if uploaded_csv is not None:
        if len(uploaded_csv.getvalue()) > MAX_UPLOAD_BYTES:
            st.error("CSV upload exceeds the 5 MiB limit.")
            raw = pd.DataFrame(columns=REQUIRED)
            source_status = "Disconnected"
        else:
            try:
                raw = pd.read_csv(uploaded_csv)
                loaded_at = now
                source_status = "Disconnected"
            except pd.errors.EmptyDataError:
                st.warning("The uploaded CSV has no header or records.")
                raw = pd.DataFrame(columns=REQUIRED)
                source_status = "Disconnected"
                loaded_at = None
            except (pd.errors.ParserError, UnicodeDecodeError, ValueError) as exc:
                st.error(f"Could not read this CSV. Check that it is valid UTF-8 CSV: {exc}")
                raw = pd.DataFrame(columns=REQUIRED)
                source_status = "Disconnected"
    else:
        st.info("Upload a device-summary CSV to analyse records. Demo data will not replace this selected source.")
elif source_mode == "Upload JSONL / RFC 5424 logs":
    if uploaded_log is not None:
        uploaded_log_bytes = uploaded_log.getvalue()
        if len(uploaded_log_bytes) > MAX_UPLOAD_BYTES:
            st.error("Log upload exceeds the 5 MiB limit.")
            rejected_events = ["Uploaded file exceeds the 5 MiB size limit."]
        else:
            try:
                log_text = uploaded_log_bytes.decode("utf-8-sig")
            except UnicodeDecodeError:
                st.error("Log file must be UTF-8 encoded.")
                rejected_events = ["Uploaded file is not UTF-8 encoded."]
            else:
                accepted_events, rejected_events, duplicate_events = ingest_event_text(log_text)
        loaded_at = now if accepted_events else None
        source_status = "Disconnected"
    else:
        st.info("Upload a JSONL or supported RFC 5424 log batch. No network receiver is running.")
elif source_mode == "Replay bundled sample events":
    sample_path = Path(__file__).with_name("sample_events.ndjson")
    try:
        accepted_events, rejected_events, duplicate_events = ingest_event_text(
            sample_path.read_text(encoding="utf-8")
        )
        loaded_at = now if accepted_events else None
    except OSError as exc:
        st.error(f"Could not load the bundled sample event file: {exc}")

if source_mode == "Upload device-summary CSV" and uploaded_csv is not None:
    missing = [column for column in REQUIRED if column not in raw.columns]
    if missing:
        st.error("CSV is missing required columns: " + ", ".join(missing))
        st.caption("Required CSV header: `" + ",".join(REQUIRED) + "`")
        raw = pd.DataFrame(columns=REQUIRED)
        loaded_at = None

if event_mode:
    try:
        internal_networks = [
            str(ipaddress.ip_network(value.strip(), strict=False))
            for value in internal_network_text.split(",")
            if value.strip()
        ]
        unusual_ports = {
            int(value.strip())
            for value in unusual_port_text.split(",")
            if value.strip()
        }
        if any(port < 0 or port > 65535 for port in unusual_ports):
            raise ValueError("Ports must be integers from 0 to 65535.")
    except ValueError as exc:
        st.error(f"Invalid event-scoring configuration: {exc}")
        st.stop()
    if accepted_events:
        latest_event_at = max(
            datetime.fromisoformat(item["timestamp"].replace("Z", "+00:00"))
            for item in accepted_events
        )
        scoring_usable_events = count_scoring_usable_events(
            accepted_events,
            internal_networks,
            unusual_ports,
        )
        raw = pd.DataFrame(aggregate_device_events(
            accepted_events,
            internal_networks,
            unusual_ports,
        ))
        raw["_record_id"] = range(len(raw))
        event_times = pd.to_datetime([item["timestamp"] for item in accepted_events], utc=True)
        timeline = (
            pd.DataFrame({"timestamp": event_times})
            .assign(interval=lambda frame: frame["timestamp"].dt.floor("h"))
            .groupby("interval", as_index=False)
            .size()
            .rename(columns={"interval": "timestamp", "size": "event_count"})
        )
    if source_mode == "Upload JSONL / RFC 5424 logs":
        source_status = uploaded_batch_status(
            uploaded_log is not None,
            latest_event_at,
            now,
            int(stale_after_minutes),
        )

if source_mode == "Upload device-summary CSV" and raw.empty and uploaded_csv is not None:
    st.warning("No valid device rows are available from this CSV.")
if event_mode and not accepted_events:
    if uploaded_log is not None or source_mode == "Replay bundled sample events":
        st.warning("No valid events were accepted. Review the rejection details below.")

if source_mode == "Upload JSONL / RFC 5424 logs" and uploaded_log is not None and not accepted_events and not rejected_events:
    st.info("The selected log file contains no event lines.")
if rejected_events:
    with st.expander(f"Rejected event lines ({len(rejected_events)})"):
        for message in rejected_events[:50]:
            st.write(f"- {message}")
        if len(rejected_events) > 50:
            st.caption(f"{len(rejected_events) - 50} additional rejection messages were omitted.")

if not raw.empty:
    if "_record_id" not in raw.columns:
        raw["_record_id"] = range(len(raw))
else:
    raw = pd.DataFrame(columns=REQUIRED + ["_record_id"])
results = analyse(raw[REQUIRED + ["_record_id"]])

invalid_count = int(results["invalid_fields"].map(bool).sum())
high_count = int((results["priority_score"] >= 50).sum())
review_count = int((results["priority_score"] > 0).sum())

status_tone = "stale" if source_status == "Stale" else (
    "demo" if source_status == "Demo Mode" else "snapshot"
)
st.markdown(
    f"""
    <div class="gs-source-status {status_tone}">
      <div><strong>Source status: {source_status}</strong>
        <span class="gs-source-mode">{source_mode}</span></div>
      <span class="gs-source-note">Connected network sources: 0 · Imported data is a finite snapshot</span>
    </div>
    """,
    unsafe_allow_html=True,
)
if loaded_at is not None:
    st.caption(
        "Last successful batch ingestion: "
        f"{loaded_at.astimezone(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}"
    )
if latest_event_at is not None:
    st.caption(f"Latest event timestamp: {latest_event_at.strftime('%Y-%m-%d %H:%M:%S UTC')}")
if source_status == "Stale":
    st.warning(
        f"Stale event batch: the latest event is older than the configured "
        f"{int(stale_after_minutes)}-minute freshness interval."
    )
if source_mode == "Upload JSONL / RFC 5424 logs" and accepted_events:
    st.info(
        "Uploaded log snapshot only: this dashboard is not connected to the sending device. "
        "The file upload does not establish an ongoing feed."
    )
if invalid_count:
    st.warning(
        f"{invalid_count} record(s) contain invalid or missing numeric values. Records are retained; "
        "unknown values are not treated as zero, and those fields cannot trigger a scoring rule."
    )

st.markdown('<div class="gs-section-kicker">01 / Security overview</div>', unsafe_allow_html=True)
st.subheader("Triage at a glance")
with st.container(border=True):
    metric_a, metric_b, metric_c, metric_d = st.columns(4)
    with metric_a:
        with st.container(key="gs-metric-total"):
            st.metric(
                "Events processed" if event_mode else "Records analysed",
                len(accepted_events) if event_mode else len(results),
                help="Count for the complete loaded batch, independent of the table filters.",
            )
    with metric_b:
        with st.container(key="gs-metric-high"):
            st.metric("High-priority reviews", high_count)
    with metric_c:
        with st.container(key="gs-metric-triggered"):
            st.metric("Records with triggered rules", review_count)
    with metric_d:
        with st.container(key="gs-metric-quality"):
            st.metric("Records needing data review", invalid_count)
    st.caption(
        "Counts describe the full loaded dataset, not the filtered table. "
        "A zero score is not evidence that a device is safe."
    )

st.markdown('<div class="gs-section-kicker">02 / Device triage</div>', unsafe_allow_html=True)
st.subheader("Prioritised records")
with st.container(border=True):
    filter_search, filter_classification = st.columns([2, 1])
    with filter_search:
        search_text = st.text_input(
            "Search devices",
            placeholder="Enter part of a device name",
            help="Case-insensitive literal text search; characters such as .* are not treated as patterns.",
        )
    with filter_classification:
        classification = st.selectbox(
            "Risk classification",
            [
                "All classifications",
                "High-priority review",
                "Review recommended",
                "No configured rule triggered",
            ],
        )

    filtered_results = filter_records(results, search_text, classification)
    st.caption(f"{len(filtered_results)} matching record(s) out of {len(results)} analysed.")
    display_cols = [
        "device", "priority_score", "status", "failed_connections", "external_connections",
        "unusual_port", "bytes_out", "evidence", "data_quality",
    ]
    if filtered_results.empty:
        st.info("No records match the current search and classification filters. Try clearing one or both filters.")
    else:
        display_results = filtered_results.drop(columns=["invalid_fields"]).copy()
        display_results["data_quality"] = filtered_results["invalid_fields"].map(
            lambda fields: ", ".join(fields) if fields else "None"
        )
        st.dataframe(
            display_results[display_cols],
            width="stretch",
            hide_index=True,
            column_config={
                "device": st.column_config.TextColumn("Device"),
                "priority_score": st.column_config.ProgressColumn("Priority score", min_value=0, max_value=100, format="%d/100"),
                "status": st.column_config.TextColumn("Risk classification"),
                "failed_connections": st.column_config.NumberColumn("Failed connections", format="%d"),
                "external_connections": st.column_config.NumberColumn("External connections", format="%d"),
                "unusual_port": st.column_config.NumberColumn("Unusual port flag", format="%d"),
                "bytes_out": st.column_config.NumberColumn("Outgoing bytes", format="%d"),
                "evidence": st.column_config.TextColumn("Rule evidence"),
                "data_quality": st.column_config.TextColumn("Invalid or missing fields"),
            },
        )

    st.download_button(
        "Download investigation report",
        data=build_investigation_report(filtered_results, raw).to_csv(index=False).encode("utf-8"),
        file_name="ghostsignal_investigation_report.csv",
        mime="text/csv",
        disabled=filtered_results.empty,
        help="Exports only records currently matching the search and classification filters.",
    )

st.markdown('<div class="gs-section-kicker">03 / Event ingestion</div>', unsafe_allow_html=True)
st.subheader("Event batch review")
with st.container(border=True):
    if event_mode:
        st.caption(
            "Finite uploaded or bundled event batch · normalised, deduplicated, and grouped for review. "
            "This is not a connected source or live-updating feed."
        )
        event_count_a, event_count_b, event_count_c, event_count_d = st.columns(4)
        event_count_a.metric("Accepted events", len(accepted_events))
        event_count_b.metric("Usable for scoring", scoring_usable_events)
        event_count_c.metric("Rejected lines", len(rejected_events))
        event_count_d.metric("Duplicate events skipped", duplicate_events)
        st.caption(
            f"Device records with missing scoring data: {invalid_count} of {len(results)}. "
            "Accepted means structurally valid; usable means at least one scoring input is available. "
            "Missing inputs remain unknown and do not count as zero."
        )
        if timeline.empty:
            st.info("No accepted events are available for a timeline.")
        else:
            st.caption("Event volume by observed timestamp (UTC).")
            event_chart = alt.Chart(timeline).mark_bar(
                color="#53e0d0",
                cornerRadiusTopLeft=3,
                cornerRadiusTopRight=3,
            ).encode(
                x=alt.X("timestamp:T", title="Event time", axis=alt.Axis(format="%H:%M")),
                y=alt.Y("event_count:Q", title="Accepted events", axis=alt.Axis(tickMinStep=1)),
                tooltip=[
                    alt.Tooltip("timestamp:T", title="Interval", format="%Y-%m-%d %H:%M UTC"),
                    alt.Tooltip("event_count:Q", title="Accepted events"),
                ],
            ).properties(height=230, background="#171e28")
            styled_event_chart = event_chart.configure_view(
                strokeOpacity=0,
            ).configure_axis(
                labelColor="#98a5b5",
                titleColor="#cbd4df",
                gridColor="#27313d",
                domainColor="#3a4654",
                tickColor="#3a4654",
            )
            st.altair_chart(styled_event_chart, width="stretch")
    else:
        st.info(
            "No event batch is loaded in this input mode. Choose “Upload JSONL / RFC 5424 logs” "
            "or “Replay bundled sample events” in the Data source sidebar to inspect event ingestion."
        )

st.markdown('<div class="gs-section-kicker">04 / Simulated analytics</div>', unsafe_allow_html=True)
st.subheader("Illustrative traffic profile")
with st.container(border=True):
    st.caption(
        "Simulated traffic only. It is independent of uploaded records, event batches, and device risk scores."
    )
    scenario = st.selectbox("Simulated traffic scenario", SCENARIOS)
    traffic, baseline_mb, ratio = build_traffic_scenario(scenario)

    latest_mb = float(traffic["Observed traffic (MB)"].iloc[-1])
    traffic_a, traffic_b, traffic_c = st.columns(3)
    traffic_a.metric("Latest simulated traffic", f"{latest_mb:.2f} MB")
    traffic_b.metric("Typical baseline", f"{baseline_mb:.2f} MB")
    traffic_c.metric("Latest / baseline", f"{ratio:.2f}×" if ratio is not None else "N/A")

    chart_data = traffic.melt(
        id_vars=["Interval", "Anomaly highlight"],
        value_vars=["Typical baseline (MB)", "Observed traffic (MB)"],
        var_name="Series",
        value_name="Outgoing traffic (MB)",
    )
    traffic_chart = alt.Chart(chart_data).mark_line(
        point=alt.OverlayMarkDef(size=48, filled=True),
        strokeWidth=2.5,
    ).encode(
        x=alt.X("Interval:N", sort=traffic["Interval"].tolist(), title="Time interval"),
        y=alt.Y(
            "Outgoing traffic (MB):Q",
            title="Simulated outgoing traffic (MB)",
            scale=alt.Scale(zero=True),
            axis=alt.Axis(format=".1f"),
        ),
        color=alt.Color(
            "Series:N",
            title="Simulated series",
            scale=alt.Scale(
                domain=["Typical baseline (MB)", "Observed traffic (MB)"],
                range=["#8492a6", "#53e0d0"],
            ),
        ),
        tooltip=[
            "Interval:N",
            "Series:N",
            alt.Tooltip("Outgoing traffic (MB):Q", title="Traffic (MB)", format=".2f"),
        ],
    ).properties(height=320)
    threshold_rule = alt.Chart(
        pd.DataFrame({"Threshold (MB)": [3 * baseline_mb]})
    ).mark_rule(
        color="#e8b45e",
        strokeDash=[6, 4],
        strokeWidth=1.5,
    ).encode(
        y=alt.Y("Threshold (MB):Q"),
        tooltip=[alt.Tooltip("Threshold (MB):Q", title="Illustrative 3× threshold", format=".2f")],
    )
    anomaly_points = alt.Chart(traffic).transform_filter(
        "datum['Anomaly highlight'] != null"
    ).mark_point(
        color="#ff646e",
        size=115,
        filled=True,
        stroke="#080b10",
        strokeWidth=1.5,
    ).encode(
        x=alt.X("Interval:N", sort=traffic["Interval"].tolist()),
        y=alt.Y("Anomaly highlight:Q"),
        tooltip=[
            "Interval:N",
            alt.Tooltip("Anomaly highlight:Q", title="Highlighted simulated traffic (MB)", format=".2f"),
        ],
    )
    chart_layers = traffic_chart + threshold_rule
    if traffic["Anomaly highlight"].notna().any():
        chart_layers += anomaly_points
    styled_traffic_chart = chart_layers.properties(background="#171e28").configure_view(
        strokeOpacity=0,
    ).configure_axis(
        labelColor="#98a5b5",
        titleColor="#cbd4df",
        gridColor="#27313d",
        domainColor="#3a4654",
        tickColor="#3a4654",
    ).configure_legend(
        labelColor="#cbd4df",
        titleColor="#cbd4df",
        orient="top",
    )
    st.altair_chart(styled_traffic_chart, width="stretch")

    if ratio is not None and ratio >= 3:
        st.warning(
            f"Illustrative anomaly: latest simulated traffic is {ratio:.2f}× the median baseline (3× threshold). "
            "A spike can have legitimate causes, such as backups or software updates."
        )
    else:
        st.success("The latest simulated interval is below the illustrative 3× baseline anomaly threshold.")
    st.caption(
        "Baseline is the median of 21 seeded, simulated normal historical intervals. "
        "The 3× threshold is illustrative, not a validated cybersecurity standard; "
        "no historical baseline is inferred from the uploaded CSV."
    )

st.markdown('<div class="gs-section-kicker">05 / Investigation</div>', unsafe_allow_html=True)
st.subheader("Device investigation")
with st.container(border=True):
    if not results.empty:
        duplicated_names = results["device"].duplicated(keep=False)

        def device_label(position: int) -> str:
            name = results.iloc[position]["device"]
            return f"{name} · record {position + 1}" if duplicated_names.iloc[position] else name

        selected_position = st.selectbox("Select a device record", range(len(results)), format_func=device_label)
        item = results.iloc[selected_position]

        detail_a, detail_b, detail_c = st.columns(3)
        detail_a.metric("Device", item["device"])
        detail_b.metric("Risk score", f"{int(item['priority_score'])}/100")
        detail_c.metric("Classification", item["status"])
        classification_tone = (
            "high" if item["status"] == "High-priority review"
            else "review" if item["status"] == "Review recommended"
            else "clear"
        )
        st.markdown(
            f'<span class="gs-classification-badge {classification_tone}">{item["status"]}</span>',
            unsafe_allow_html=True,
        )
        st.progress(
            int(item["priority_score"]),
            text="Configured rule score · capped at 100",
        )

        if event_mode:
            device_events = [
                event for event in accepted_events
                if event["device"] == item["device"]
            ]
            st.caption(
                f"Derived from {len(device_events)} accepted event(s); source(s): "
                + (", ".join(sorted({event["source"] for event in device_events})) or "unavailable")
            )
            if device_events:
                observed_columns = [
                    "timestamp",
                    "event_id",
                    "source",
                    "source_ip",
                    "destination_ip",
                    "destination_port",
                    "protocol",
                    "event_type",
                    "action",
                    "direction",
                    "bytes_out",
                ]
                st.dataframe(
                    pd.DataFrame(device_events)[observed_columns],
                    width="stretch",
                    hide_index=True,
                )

        st.markdown("**Recorded inputs**")
        value_labels = ["Failed connections", "External connections", "Unusual port indicator", "Outgoing bytes"]
        for start in (0, 2):
            value_columns = st.columns(2)
            for column, field, label in zip(
                value_columns,
                NUMERIC_FIELDS[start:start + 2],
                value_labels[start:start + 2],
            ):
                value = item[field]
                column.metric(
                    label,
                    "Unknown · review needed" if pd.isna(value) else f"{value:,.0f}",
                )

        st.markdown("**Triggered rule evidence**")
        if item["triggered_rules"]:
            for name, explanation, points in item["triggered_rules"]:
                st.markdown(
                    f"""
                    <div class="gs-rule-row">
                      <div><strong>{name}</strong><span>{explanation}</span></div>
                      <div class="gs-rule-points">+{points} pts</div>
                    </div>
                    """,
                    unsafe_allow_html=True,
                )
            if item["priority_score"] >= 50:
                st.warning(
                    "Recommendation: investigate the activity, review destinations and timing, "
                    "and compare the observations with expected device behaviour."
                )
            else:
                st.info(
                    "Recommendation: review the configured indicators and confirm whether the "
                    "recorded behaviour is expected."
                )
        else:
            st.info(
                "No configured scoring rule was triggered for the known values. "
                "This is not evidence that the device is safe."
            )
        if item["invalid_fields"]:
            st.warning(
                "Scoring is incomplete for: " + ", ".join(item["invalid_fields"]) +
                ". Unknown values are not zero; correct or verify them before relying on this review."
            )
    else:
        st.info("Device investigation is available after at least one valid record is supplied.")

with st.expander("View supplied records"):
    st.dataframe(raw[REQUIRED], width="stretch", hide_index=True)

if event_mode:
    with st.expander("Event format and aggregation assumptions"):
        st.write(
            "JSONL requires one JSON object per line. Required fields are timestamp (ISO 8601), source, "
            "device, and event_type. RFC 5424 is accepted only when its message is a JSON object. "
            "Unknown optional values stay unavailable; raw payloads are not retained."
        )
        st.write(
            "Scoring aggregates the uploaded batch per device (not a rolling time window). Failed "
            "connections count only explicit failed/failure/connection_failed actions; denied/blocked "
            "actions are not counted as failures. External counts require configured internal CIDRs and "
            "both IP addresses. Outgoing bytes require outbound direction and bytes_out on each outbound "
            "connection event. Unusual ports require the configured destination-port list."
        )
        st.write(
            "These adapter mappings are generic and do not imply compatibility with a particular vendor. "
            "Use vendor documentation to map its event fields into the GhostSignal schema."
        )
else:
    with st.expander("CSV format and required columns"):
        st.write("Include every required column. Numeric fields must contain numbers; invalid or blank values are reported, not silently discarded.")
        st.code(
            "device,failed_connections,external_connections,unusual_port,bytes_out\n"
            "Laptop-01,1,5,0,200000\n"
            "Test-Device-03,15,25,1,6500000",
            language="csv",
        )

st.caption(
    "A high score means configured rules matched; it is not a probability and does not prove compromise or data theft. "
    "Real-world performance requires validation against labelled data."
)
