# GhostSignal

**Explainable Device-Activity Triage | Demonstration Prototype**

GhostSignal is a Streamlit-based prototype that analyses supplied device-activity records, assigns rule-based risk scores, and explains which configured indicators contributed to each score.

## Features

- **Explainable risk scoring:** Shows the points contributed by each triggered rule.
- **Device investigation:** Displays device activity indicators and a review recommendation.
- **Data validation:** Identifies records containing invalid or missing numeric values.
- **Interactive triage:** Filter records by case-insensitive device-name search and risk classification; summary metrics cover the full dataset.
- **Investigation report:** Download the currently filtered records, rule evidence, and data-quality findings as CSV.
- **Structured event import:** Validate JSON Lines or RFC 5424 syslog records with a JSON message, deduplicate them, and aggregate a finite batch by device.
- **Sample event replay:** Replay the checked-in, synthetic `sample_events.ndjson` file without configuring a physical source.
- **Simulated traffic visualisation:** Displays independent illustrative traffic against a seeded historical baseline; the 3× threshold is not a validated security standard.
- **CSV-based analysis:** Analyses uploaded activity records using a defined set of required columns.

## Technology Stack

- Python
- Streamlit
- Pandas
- CSV and JSON Lines data

## Requirements

- Python 3.11, 3.12, or 3.13 recommended
- Internet connection for first-time package installation

## Getting Started

### 1. Clone the repository

```bash
git clone https://github.com/shrutilelith-hub/ghostsignal-threat-detection
cd ghostsignal-threat-detection
```

### 2. Create a virtual environment

On Windows PowerShell:

```powershell
py -3.13 -m venv .venv
```

If Python 3.13 is unavailable, try `py -3.12` or `py -3.11`.

### 3. Install dependencies

```powershell
.\.venv\Scripts\python.exe -m pip install --upgrade pip
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
```

### 4. Run the application

```powershell
.\.venv\Scripts\python.exe -m streamlit run app.py
```

Streamlit will provide a local URL to open the application in your browser.

## Data sources and status

Choose an input mode in the sidebar:

- **Demo device records:** Built-in synthetic device summaries, labelled `Demo Mode`.
- **Upload device-summary CSV:** Existing CSV workflow. An uploaded file is a snapshot and is shown as `Disconnected`; it is not a live source.
- **Upload JSONL / RFC 5424 logs:** Import a UTF-8 event batch. The app displays accepted, rejected, and duplicate counts. The status is `Disconnected` for a recent uploaded batch and `Stale` if its latest event is older than the configured age.
- **Replay bundled sample events:** Reproducible synthetic JSONL events, labelled `Demo Mode`.

`Connected sources` remains zero: GhostSignal does not implement a network receiver, background poller, or vendor API client. The dashboard does not infer a connection from an upload or successful page load. Streamlit Community Cloud cannot directly reach a private LAN router/firewall. No listener, firewall port, token, or credential is required by this file-import implementation. Do not expose an unauthenticated syslog or HTTP listener to make a private device reachable.

### Structured event schema

The JSONL adapter accepts one JSON object per line. The following fields are required:

| Field | Meaning |
|---|---|
| `timestamp` | ISO 8601 event timestamp; naive timestamps are interpreted as UTC |
| `source` | Name of the reporting source |
| `device` | Device identifier used for grouping |
| `event_type` | Event category; connection aggregation recognizes `connection`, `network_connection`, and `firewall_connection` |

Optional normalized fields are `event_id`, `source_ip`, `destination_ip`, `source_port`, `destination_port`, `protocol`, `action`, `direction` (`inbound` or `outbound` for aggregation), `bytes_in`, and `bytes_out`. Addresses, ports, timestamps, and integer byte counts are validated. Missing optionals remain unavailable. The app keeps only this recognized connection metadata; it does not retain arbitrary JSON payload fields. Identical IDs are deduplicated within the imported batch; conflicting records with the same ID are rejected. There is no persistent event store or cross-upload deduplication. Events are sorted by normalized timestamp, not arrival order.

RFC 5424 syslog is supported only when its message portion is a JSON object using these event fields. The syslog hostname supplies `source` and `device` when the JSON message omits them. This is an adapter format, not universal vendor syslog support. RFC 3164 and vendor-specific message parsing are not implemented.

The adapter extension point is `EventAdapter.parse(line) -> dict[str, Any]` in `collectors/structured_logs.py`. A vendor-specific adapter should map only documented connection metadata into a candidate mapping, then call the shared `normalize_event` validator; do not carry packet payloads or arbitrary vendor fields into the normalized event.

Example:

```json
{"event_id":"evt-001","timestamp":"2026-05-01T12:00:00Z","source":"edge-01","device":"workstation-01","source_ip":"192.168.1.10","destination_ip":"8.8.8.8","destination_port":443,"protocol":"tcp","event_type":"connection","action":"allowed","direction":"outbound","bytes_out":1200}
```

The JSON object can also be the message at the end of a supported RFC 5424 record:

```text
<34>1 2026-05-01T12:00:00Z edge-01 firewall - - - {"device":"workstation-01","event_type":"connection","action":"allowed"}
```

Uploads are capped at 5 MiB. Validation rejections show line numbers and reason, not the submitted line contents. Sample events are fictional documentation data and do not represent a real network.

### Event aggregation and scoring assumptions

Aggregation operates on the **entire uploaded batch per device**, not a rolling window. Rules and thresholds are unchanged:

- Failed connections count only explicit `failed`, `failure`, or `connection_failed` actions on recognized connection event types. `denied`, `blocked`, and `rejected` actions are not counted as failed connections.
- External connections count outbound records whose source address is within one of the configured internal CIDRs and destination address is outside all configured networks. This counts valid connection-event records regardless of outcome, not proven unique sessions. The default CIDRs cover RFC 1918 IPv4 ranges; adjust them for the network being analysed.
- Outgoing bytes are summed only for outbound connection records when each outbound record provides `bytes_out`. If required information is absent, that scoring input stays unavailable.
- `unusual_port` is evaluated only when a destination-port list is configured and all connection records have a destination port. The list is a local analyst configuration, not a built-in threat-intelligence feed.

Unavailable aggregate inputs are reported as missing and do not trigger rules. A score of zero is not proof of safety; scores prioritize review and do not estimate compromise probability.

### Using real source logs

Export a connection-metadata log from the router, firewall, or monitoring product as JSONL in the documented schema, then select **Upload JSONL / RFC 5424 logs** and choose that file. For standard syslog, first configure the product to emit RFC 5424 with a JSON message containing the schema fields. Map vendor-native action names and event types only after checking that vendor's documentation. The product vendor/model, field mapping, and export procedure are not known or configured by this repository.

This is a manual batch-import path, not an always-on collector-to-dashboard transport. Batch health is recalculated when the page processes the selected input; ingestion timestamps and events are not persisted across sessions. For a public Cloud deployment with ongoing private-network telemetry, run a collector inside the private network and forward to an authenticated outbound HTTPS ingestion service; that gateway and its authentication are not implemented here. Do not point a router at a public UDP/TCP listener or assume Streamlit itself is an ingestion API.

## Architecture

- `collectors/structured_logs.py`: JSONL and RFC 5424-with-JSON parsing, schema validation, normalized event IDs, deduplication, and rejection reporting.
- `services/event_aggregation.py`: batch aggregation and conservative source-freshness status.
- `services/scoring.py`: shared CSV/event scoring, filtering, and investigation-report formatting.
- `sample_events.ndjson`: synthetic event replay fixture.
- `tests/`: deterministic unit tests for ingestion, aggregation, scoring, filtering, and export.

No new dependencies or credentials are needed for event import.

## CSV Format

The uploaded CSV must contain these headers:

```csv
device,failed_connections,external_connections,unusual_port,bytes_out
Laptop-01,2,5,0,500000
```

- `device`: Device identifier.
- `failed_connections`: Number of failed connections.
- `external_connections`: Number of external connections.
- `unusual_port`: `1` if the record flags unusual port activity; otherwise `0`.
- `bytes_out`: Outgoing data volume in bytes, not megabytes.

## Demonstration Scoring Rules

| Configured indicator | Points |
|---|---:|
| Failed connections ≥ 10 | +30 |
| External connections ≥ 20 | +25 |
| Unusual port indicator = 1 | +25 |
| Outgoing data > 5,000,000 bytes | +20 |

The maximum score is 100. Scores are used to prioritise review, not to establish that a device is compromised.

## Limitations

GhostSignal is a demonstration MVP. The uploaded event timeline reflects only the supplied file; the separate traffic chart remains simulated. The app does not inspect live network traffic, use machine learning, connect directly to a router/firewall, or prove that a device has been compromised.

The scoring thresholds and weights are illustrative choices and require validation against labelled data before operational use. Vendor API adapters, RFC 3164 parsing, continuous collection/refresh, an authenticated forwarding gateway, persistent ingestion state, and production source-health monitoring remain unimplemented. Before a public live demo, select the router/firewall vendor and model, document its event export/API, map its action/outcome semantics, deploy an authenticated private-network collector/gateway, and verify that actual events flow through it. Never use the demo replay as evidence that a real source is connected.