"""Validation and normalization for JSON event lines and RFC 5424 JSON syslog."""

from __future__ import annotations

import hashlib
import ipaddress
import json
import re
from datetime import datetime, timezone
from typing import Any, Protocol


SYSLOG_PATTERN = re.compile(
    r"^<(?P<priority>\d{1,3})>1 (?P<timestamp>\S+) (?P<host>\S+) "
    r"(?P<app>\S+) (?P<procid>\S+) (?P<msgid>\S+) "
    r"(?P<structured_data>-|\[.*\])(?: (?P<message>.*))?$"
)
OPTIONAL_TEXT_FIELDS = ("protocol", "action", "direction")
OPTIONAL_IP_FIELDS = ("source_ip", "destination_ip")
OPTIONAL_PORT_FIELDS = ("source_port", "destination_port")
OPTIONAL_BYTE_FIELDS = ("bytes_in", "bytes_out")
ALIAS_EVENT_TYPES = {
    "connection_failed": "connection_failed",
    "connection_failure": "connection_failed",
    "failed_connection": "connection_failed",
    "failed_connections": "connection_failed",
    "connection_denied": "connection_denied",
    "connection_rejected": "connection_denied",
    "external_connection": "external_connection",
    "external_connections": "external_connection",
    "unusual_port": "unusual_port",
    "port_anomaly": "unusual_port",
    "connection_allowed": "connection_allowed",
    "connection_success": "connection_allowed",
    "allowed_connection": "connection_allowed",
}
KNOWN_CONNECTION_ACTIONS = {
    "allowed",
    "accepted",
    "established",
    "success",
    "succeeded",
    "failed",
    "failure",
    "connection_failed",
    "denied",
    "blocked",
    "drop",
    "rejected",
    "reject",
}
FAILED_CONNECTION_ACTIONS = {"failed", "failure", "connection_failed"}
EVENT_FIELDS = (
    "event_id",
    "timestamp",
    "source",
    "device",
    "source_ip",
    "destination_ip",
    "source_port",
    "destination_port",
    "protocol",
    "event_type",
    "action",
    "direction",
    "bytes_in",
    "bytes_out",
    "failed_connections",
    "external_connections",
    "unusual_port",
    "raw_event",
)


def _required_text(record: dict[str, Any], field: str) -> str:
    value = record.get(field)
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field} must be a non-empty string")
    if len(value.strip()) > 256:
        raise ValueError(f"{field} exceeds 256 characters")
    return value.strip()


def _optional_text(record: dict[str, Any], field: str) -> str | None:
    value = record.get(field)
    if value is None or value == "":
        return None
    if not isinstance(value, str) or len(value.strip()) > 256:
        raise ValueError(f"{field} must be a string of at most 256 characters")
    return value.strip() or None


def _optional_ip(record: dict[str, Any], field: str) -> str | None:
    value = record.get(field)
    if value is None or value == "":
        return None
    if not isinstance(value, str):
        raise ValueError(f"{field} must be an IP address string")
    try:
        return str(ipaddress.ip_address(value))
    except ValueError as exc:
        raise ValueError(f"{field} is not a valid IP address") from exc


def _optional_integer(record: dict[str, Any], field: str, maximum: int) -> int | None:
    value = record.get(field)
    if value is None or value == "":
        return None
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= maximum:
        raise ValueError(f"{field} must be an integer from 0 to {maximum}")
    return value


def normalize_event(record: dict[str, Any]) -> dict[str, Any]:
    """Validate one canonical event and retain only recognized connection metadata."""
    timestamp_value = record.get("timestamp")
    if not isinstance(timestamp_value, str) or not timestamp_value.strip():
        raise ValueError("timestamp must be an ISO 8601 string")
    try:
        timestamp = datetime.fromisoformat(timestamp_value.strip().replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("timestamp must be a valid ISO 8601 value") from exc
    if timestamp.tzinfo is None:
        timestamp = timestamp.replace(tzinfo=timezone.utc)
    timestamp_text = timestamp.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")

    raw_event_type = _required_text(record, "event_type")
    event_type = ALIAS_EVENT_TYPES.get(raw_event_type.casefold(), raw_event_type.casefold())
    event = {
        "timestamp": timestamp_text,
        "source": _required_text(record, "source"),
        "device": _required_text(record, "device"),
        "source_ip": _optional_ip(record, "source_ip"),
        "destination_ip": _optional_ip(record, "destination_ip"),
        "source_port": _optional_integer(record, "source_port", 65535),
        "destination_port": _optional_integer(record, "destination_port", 65535),
        "protocol": _optional_text(record, "protocol"),
        "event_type": event_type,
        "action": _optional_text(record, "action"),
        "direction": _optional_text(record, "direction"),
        "bytes_in": _optional_integer(record, "bytes_in", 2**63 - 1),
        "bytes_out": _optional_integer(record, "bytes_out", 2**63 - 1),
        "failed_connections": _optional_integer(record, "failed_connections", 2**63 - 1),
        "external_connections": _optional_integer(record, "external_connections", 2**63 - 1),
        "unusual_port": _optional_integer(record, "unusual_port", 1),
    }
    if event["failed_connections"] is None:
        if event_type == "connection_failed":
            event["failed_connections"] = 1
        elif event_type in {"connection_allowed", "connection_denied"}:
            event["failed_connections"] = 0
        elif (
            event_type in {"connection", "network_connection", "firewall_connection"}
            and event["action"] is not None
            and event["action"].casefold() in KNOWN_CONNECTION_ACTIONS
        ):
            event["failed_connections"] = int(event["action"].casefold() in FAILED_CONNECTION_ACTIONS)
    if event["external_connections"] is None and event_type == "external_connection":
        event["external_connections"] = 1
    if event["unusual_port"] is None and event_type == "unusual_port":
        event["unusual_port"] = 1

    supplied_id = record.get("event_id")
    if supplied_id is not None and (
        not isinstance(supplied_id, str) or not supplied_id.strip() or len(supplied_id) > 128
    ):
        raise ValueError("event_id must be a non-empty string of at most 128 characters")
    fingerprint = json.dumps(event, sort_keys=True, separators=(",", ":")).encode("utf-8")
    event["event_id"] = supplied_id.strip() if supplied_id is not None else hashlib.sha256(fingerprint).hexdigest()
    event["raw_event"] = {key: event[key] for key in EVENT_FIELDS if key != "raw_event"}
    return event


class EventAdapter(Protocol):
    """Adapter contract: parse one source line into a candidate event mapping."""

    def parse(self, line: str) -> dict[str, Any]:
        """Return a candidate event; normalize_event applies shared schema validation."""
        ...


class JsonLinesAdapter:
    """Parse one JSON object from a JSONL line."""

    def parse(self, line: str) -> dict[str, Any]:
        try:
            record = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ValueError("line is not valid JSON") from exc
        if not isinstance(record, dict):
            raise ValueError("JSON event must be an object")
        return record


class Rfc5424JsonAdapter:
    """Parse RFC 5424 records whose message field is a JSON object."""

    def parse(self, line: str) -> dict[str, Any]:
        match = SYSLOG_PATTERN.match(line)
        if match is None:
            raise ValueError("not a supported RFC 5424 syslog record")
        if int(match.group("priority")) > 191:
            raise ValueError("RFC 5424 priority must be from 0 to 191")
        message = match.group("message")
        if not message:
            raise ValueError("RFC 5424 syslog message must contain a JSON event object")
        try:
            record = json.loads(message)
        except json.JSONDecodeError as exc:
            raise ValueError("RFC 5424 syslog message is not valid JSON") from exc
        if not isinstance(record, dict):
            raise ValueError("RFC 5424 syslog message must be a JSON object")
        record.setdefault("timestamp", match.group("timestamp"))
        record.setdefault("source", match.group("host"))
        record.setdefault("device", match.group("host"))
        return record


def parse_event_line(line: str) -> dict[str, Any]:
    """Parse a JSON object line or RFC 5424 line whose message is a JSON object."""
    if line.lstrip().startswith("{"):
        adapter: EventAdapter = JsonLinesAdapter()
    else:
        adapter = Rfc5424JsonAdapter()
    return normalize_event(adapter.parse(line))


def ingest_event_text(text: str) -> tuple[list[dict[str, Any]], list[str], int]:
    """Parse a batch, deduplicate it, and report rejected line numbers without raw contents."""
    events_by_id: dict[str, dict[str, Any]] = {}
    rejected: list[str] = []
    duplicate_count = 0
    for line_number, line in enumerate(text.splitlines(), start=1):
        if not line.strip():
            continue
        try:
            event = parse_event_line(line)
        except ValueError as exc:
            rejected.append(f"Line {line_number}: {exc}")
            continue
        previous = events_by_id.get(event["event_id"])
        if previous is None:
            events_by_id[event["event_id"]] = event
        elif previous == event:
            duplicate_count += 1
        else:
            rejected.append(f"Line {line_number}: event_id conflicts with an earlier event")
    events = sorted(
        events_by_id.values(),
        key=lambda item: (item["timestamp"], item["event_id"]),
    )
    return events, rejected, duplicate_count
