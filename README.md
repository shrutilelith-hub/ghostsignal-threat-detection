# GhostSignal

**Explainable Device-Activity Triage | Demonstration Prototype**

GhostSignal is a Streamlit-based prototype that analyses supplied device-activity records, assigns rule-based risk scores, and explains which configured indicators contributed to each score.

## Features

- **Explainable risk scoring:** Shows the points contributed by each triggered rule.
- **Device investigation:** Displays device activity indicators and a review recommendation.
- **Data validation:** Identifies records containing invalid or missing numeric values.
- **Simulated traffic visualisation:** Displays illustrative traffic against a simulated historical baseline.
- **CSV-based analysis:** Analyses uploaded activity records using a defined set of required columns.

## Technology Stack

- Python
- Streamlit
- Pandas
- CSV data

## Requirements

- Python 3.11, 3.12, or 3.13 recommended
- Internet connection for first-time package installation

## Getting Started

### 1. Clone the repository

```bash
git clone https://github.com/shrutilelith-hub/ghostsignal-threat-detection
cd ghostsignal
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

GhostSignal is a demonstration MVP. It uses fixed scoring rules and synthetic traffic data. It does not inspect live network traffic, use machine learning, or prove that a device has been compromised.

The scoring thresholds and weights are illustrative choices and require validation against labelled data before operational use.