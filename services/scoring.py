"""Shared rule-based scoring, filtering, and export helpers."""

from __future__ import annotations

import pandas as pd


REQUIRED = ["device", "failed_connections", "external_connections", "unusual_port", "bytes_out"]
NUMERIC_FIELDS = ["failed_connections", "external_connections", "unusual_port", "bytes_out"]


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
    return df.sort_values(
        ["priority_score", "device"],
        ascending=[False, True],
        na_position="last",
        kind="stable",
    ).reset_index(drop=True)


def filter_records(
    results: pd.DataFrame,
    search_text: str,
    classification: str,
) -> pd.DataFrame:
    """Filter scored records by literal, case-insensitive device-name text and class."""
    matches = pd.Series(True, index=results.index)
    if search_text:
        matches &= results["device"].str.contains(search_text, case=False, regex=False, na=False)
    if classification != "All classifications":
        matches &= results["status"].eq(classification)
    return results.loc[matches]


def build_investigation_report(results: pd.DataFrame, raw: pd.DataFrame) -> pd.DataFrame:
    """Create public report columns without exporting internal implementation fields."""
    source_rows = raw.iloc[results["_record_id"].astype(int).tolist()]
    report = pd.DataFrame({
        "Device": results["device"].tolist(),
        "Priority score": results["priority_score"].tolist(),
        "Risk classification": results["status"].tolist(),
        "Failed connections": source_rows["failed_connections"].tolist(),
        "External connections": source_rows["external_connections"].tolist(),
        "Unusual port indicator": source_rows["unusual_port"].tolist(),
        "Outgoing bytes": source_rows["bytes_out"].tolist(),
        "Evidence explaining triggered rules": [
            "; ".join(
                f"{name} (+{points}): {explanation}"
                for name, explanation, points in rules
            ) or "No configured scoring rule triggered"
            for rules in results["triggered_rules"]
        ],
        "Invalid or missing fields": [
            ", ".join(fields) if fields else "None"
            for fields in results["invalid_fields"]
        ],
    })
    return report
