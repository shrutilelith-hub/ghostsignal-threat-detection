import random
import statistics

import altair as alt
import pandas as pd
import streamlit as st


st.set_page_config(page_title="GhostSignal | Security Triage", page_icon="🛡️", layout="wide")

REQUIRED = ["device", "failed_connections", "external_connections", "unusual_port", "bytes_out"]
NUMERIC_FIELDS = ["failed_connections", "external_connections", "unusual_port", "bytes_out"]
SCENARIOS = ["Normal traffic", "Sudden outbound spike", "Repeated elevated traffic"]

SAMPLE = pd.DataFrame([
    {"device": "Laptop-01", "failed_connections": 1, "external_connections": 5, "unusual_port": 0, "bytes_out": 200_000},
    {"device": "Office-PC-02", "failed_connections": 2, "external_connections": 8, "unusual_port": 0, "bytes_out": 450_000},
    {"device": "Test-Device-03", "failed_connections": 15, "external_connections": 25, "unusual_port": 1, "bytes_out": 6_500_000},
    {"device": "Camera-04", "failed_connections": 12, "external_connections": 3, "unusual_port": 0, "bytes_out": 100_000},
    {"device": "Design-PC-05", "failed_connections": 0, "external_connections": 24, "unusual_port": 0, "bytes_out": 900_000},
    {"device": "Backup-Server-06", "failed_connections": 1, "external_connections": 4, "unusual_port": 0, "bytes_out": 8_000_000},
])


def analyse(df: pd.DataFrame) -> pd.DataFrame:
    """Score known values and retain a row-level record of invalid numeric fields."""
    df = df.copy()
    invalid_fields = [[] for _ in range(len(df))]
    for field in NUMERIC_FIELDS:
        converted = pd.to_numeric(df[field], errors="coerce")
        for position, value in enumerate(converted):
            if pd.isna(value):
                invalid_fields[position].append(field)
        df[field] = converted

    scores, explanations, statuses, triggered_rules = [], [], [], []
    for position, (_, row) in enumerate(df.iterrows()):
        score = 0
        rules = []
        if pd.notna(row["failed_connections"]) and row["failed_connections"] >= 10:
            score += 30
            rules.append(("Failed connections", "At least 10 failed connections were recorded.", 30))
        if pd.notna(row["external_connections"]) and row["external_connections"] >= 20:
            score += 25
            rules.append(("External connections", "At least 20 external connections were recorded.", 25))
        if pd.notna(row["unusual_port"]) and row["unusual_port"] == 1:
            score += 25
            rules.append(("Unusual port", "The unusual_port indicator is set to 1.", 25))
        if pd.notna(row["bytes_out"]) and row["bytes_out"] > 5_000_000:
            score += 20
            rules.append(("Outgoing data", "Outgoing data exceeds 5,000,000 bytes (5 MB).", 20))

        score = min(score, 100)
        status = (
            "High-priority review" if score >= 50
            else "Review recommended" if score > 0
            else "No configured rule triggered"
        )
        reasons = [f"{name} (+{points})" for name, _, points in rules]
        if not reasons:
            reasons.append("No configured warning rules triggered")
        if invalid_fields[position]:
            reasons.append("Invalid or missing values: " + ", ".join(invalid_fields[position]))

        scores.append(score)
        explanations.append("; ".join(reasons))
        statuses.append(status)
        triggered_rules.append(rules)

    df["priority_score"] = scores
    df["status"] = statuses
    df["evidence"] = explanations
    df["triggered_rules"] = triggered_rules
    df["invalid_fields"] = invalid_fields
    return df.sort_values(["priority_score", "device"], ascending=[False, True], na_position="last").reset_index(drop=True)


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


st.title("GhostSignal")
st.caption("Explainable device-activity triage | Demonstration prototype")
st.info(
    "This prototype scores supplied activity records with fixed rules. The traffic chart below uses simulated data; "
    "it does not monitor live networks or determine whether a device is compromised."
)

with st.sidebar:
    st.header("Data source")
    uploaded = st.file_uploader("Upload a CSV file (optional)", type=["csv"])
    st.markdown("---")
    st.subheader("Scoring rules")
    st.write("• 10+ failed connections: +30")
    st.write("• 20+ external connections: +25")
    st.write("• Unusual port flag = 1: +25")
    st.write("• Outgoing data > 5,000,000 bytes: +20")
    st.caption("Score is capped at 100. These thresholds are demonstration rules, not validated security standards.")

empty_upload = False
if uploaded is not None:
    try:
        raw = pd.read_csv(uploaded)
    except pd.errors.EmptyDataError:
        raw = pd.DataFrame(columns=REQUIRED)
        empty_upload = True
    except (pd.errors.ParserError, UnicodeDecodeError, ValueError) as exc:
        st.error(f"Could not read this CSV. Check that it is a valid UTF-8 CSV file: {exc}")
        st.stop()
else:
    raw = SAMPLE.copy()
    st.caption("Showing built-in synthetic sample data. Upload a CSV in the sidebar to analyse your records.")

missing = [column for column in REQUIRED if column not in raw.columns]
if missing:
    st.error("CSV is missing required columns: " + ", ".join(missing))
    st.write("Required CSV header: `" + ",".join(REQUIRED) + "`")
    st.stop()

if raw.empty:
    if empty_upload:
        st.warning("The uploaded CSV is empty. Add a header and at least one device row using the required CSV format.")
    else:
        st.warning("No device rows found. Add at least one record to see device scoring and investigation details.")

raw["device"] = raw["device"].fillna("Unknown device").astype(str)
raw["_record_id"] = range(len(raw))
results = analyse(raw[REQUIRED + ["_record_id"]])

invalid_count = int(results["invalid_fields"].map(bool).sum())
high_count = int((results["priority_score"] >= 50).sum())
review_count = int((results["priority_score"] > 0).sum())

metric_a, metric_b, metric_c, metric_d = st.columns(4)
metric_a.metric("Devices analysed", len(results))
metric_b.metric("High-priority reviews", high_count)
metric_c.metric("Devices with triggered rules", review_count)
metric_d.metric("Rows needing data review", invalid_count)

if invalid_count:
    st.warning(
        f"{invalid_count} record(s) contain invalid or missing numeric values. Records are retained; "
        "unknown values are not treated as zero, and those fields cannot trigger a scoring rule."
    )

st.subheader("Device triage overview")
display_cols = [
    "device", "priority_score", "status", "failed_connections", "external_connections", "unusual_port", "bytes_out"
]
st.dataframe(
    results[display_cols],
    width="stretch",
    hide_index=True,
    column_config={
        "priority_score": st.column_config.ProgressColumn("Priority score", min_value=0, max_value=100, format="%d/100"),
        "failed_connections": st.column_config.NumberColumn("Failed connections", format="%d"),
        "external_connections": st.column_config.NumberColumn("External connections", format="%d"),
        "unusual_port": st.column_config.NumberColumn("Unusual port flag", format="%d"),
        "bytes_out": st.column_config.NumberColumn("Outgoing bytes", format="%d"),
    },
)

st.subheader("Traffic over time")
st.caption("Illustrative simulated traffic only. It is independent of uploaded CSV records and device risk scores.")
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
traffic_chart = alt.Chart(chart_data).mark_line(point=alt.OverlayMarkDef(size=55)).encode(
    x=alt.X("Interval:N", sort=traffic["Interval"].tolist(), title="Time interval"),
    y=alt.Y("Outgoing traffic (MB):Q", title="Outgoing traffic (MB)", scale=alt.Scale(zero=True)),
    color=alt.Color(
        "Series:N",
        title="Simulated series",
        scale=alt.Scale(domain=["Typical baseline (MB)", "Observed traffic (MB)"], range=["#64748b", "#0f766e"]),
    ),
    tooltip=["Interval:N", "Series:N", alt.Tooltip("Outgoing traffic (MB):Q", format=".2f")],
).properties(height=320)
anomaly_points = alt.Chart(traffic).transform_filter(
    "datum['Anomaly highlight'] != null"
).mark_point(color="#e4572e", size=150, filled=True).encode(
    x=alt.X("Interval:N", sort=traffic["Interval"].tolist()),
    y=alt.Y("Anomaly highlight:Q"),
    tooltip=["Interval:N", alt.Tooltip("Anomaly highlight:Q", title="Simulated spike (MB)", format=".2f")],
)
st.altair_chart(traffic_chart + anomaly_points, width="stretch")

if ratio is not None and ratio >= 3:
    st.warning(
        f"Illustrative anomaly: latest simulated traffic is {ratio:.2f}× the median baseline (3× threshold). "
        "A spike can have legitimate causes, such as backups or software updates."
    )
else:
    st.success("The latest simulated interval is below the illustrative 3× baseline anomaly threshold.")
st.caption("Baseline is the median of 21 seeded, simulated normal historical intervals. No historical baseline is inferred from the uploaded CSV.")

st.subheader("Investigate a device")
if not results.empty:
    duplicated_names = results["device"].duplicated(keep=False)

    def device_label(position: int) -> str:
        name = results.iloc[position]["device"]
        return f"{name} · record {position + 1}" if duplicated_names.iloc[position] else name

    selected_position = st.selectbox("Choose a device", range(len(results)), format_func=device_label)
    item = results.iloc[selected_position]

    detail_a, detail_b, detail_c = st.columns(3)
    detail_a.metric("Device", item["device"])
    detail_b.metric("Risk score", f"{int(item['priority_score'])}/100")
    detail_c.metric("Classification", item["status"])

    value_columns = st.columns(4)
    for column, field, label in zip(
        value_columns,
        NUMERIC_FIELDS,
        ["Failed connections", "External connections", "Unusual port indicator", "Outgoing bytes"],
    ):
        value = item[field]
        column.metric(label, "Invalid / missing" if pd.isna(value) else f"{value:,.0f}")

    st.write("**Triggered scoring rules**")
    if item["triggered_rules"]:
        for name, explanation, points in item["triggered_rules"]:
            st.write(f"- **{name}: +{points} points.** {explanation}")
        if item["priority_score"] >= 50:
            st.warning("Recommendation: investigate the activity, review destination and timing, and compare it with expected device behaviour.")
        else:
            st.info("Recommendation: review the triggered indicators and check whether the behaviour is expected.")
    else:
        st.success("No configured scoring rule was triggered for this record. This does not guarantee the device is safe.")
    if item["invalid_fields"]:
        st.warning("Scoring is incomplete for: " + ", ".join(item["invalid_fields"]) + ". Correct these values before relying on the score.")
else:
    st.info("Device investigation is available after at least one valid record is supplied.")

with st.expander("View supplied records"):
    st.dataframe(raw[REQUIRED], width="stretch", hide_index=True)

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
