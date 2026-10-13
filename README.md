# GhostSignal starter

A single-file Streamlit demo for explainable device-activity triage.

## Requirements
- Python 3.11, 3.12, or 3.13 recommended
- Internet connection for first-time package installation

## Windows PowerShell setup
Open PowerShell in this folder and run:

```powershell
py -3.13 -m venv .venv
.\.venv\Scripts\python.exe -m pip install --upgrade pip
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe -m streamlit run app.py
```

If `py -3.13` is unavailable, try `py -3.12` or `py -3.11` instead.

## CSV columns
Required headers:
`device,failed_connections,external_connections,unusual_port,bytes_out`

`unusual_port` should be 1 when the test record flags unusual port activity, otherwise 0.
`bytes_out` is a byte count, not megabytes.

## Important limitation
This MVP uses fixed rules and synthetic data. It does not inspect live network traffic, use machine learning, or prove compromise. Thresholds and weights are demonstration choices and need validation against labelled data before operational use.
