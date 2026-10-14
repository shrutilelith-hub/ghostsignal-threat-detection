"""Conservative device-level aggregation for a finite batch of normalized events."""

from __future__ import annotations

import ipaddress
from collections import defaultdict
from datetime import datetime
from typing import Any


GENERIC_CONNECTION_TYPES = {"connection", "network_connection", "firewall_connection"}
KNOWN_OUTCOMES = {
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
FAILED_OUTCOMES = {"failed", "failure", "connection_failed"}
__all__ = [
    "aggregate_device_events",
    "count_scoring_usable_events",
    "uploaded_batch_status",
]


def uploaded_batch_status(
    has_batch: bool,
    latest_event_at: datetime | None,
    now: datetime,
    stale_after_minutes: int,
) -> str:
    """Report batch state without ever treating a file upload as a live connection."""
    if not has_batch:
        return "Configuration Required"
    if latest_event_at is not None and (
        now - latest_event_at
    ).total_seconds() > stale_after_minutes * 60:
        return "Stale"
    return "Disconnected"


def aggregate_device_events(
    events: list[dict[str, Any]],
    internal_networks: list[str],
    unusual_ports: set[int],
) -> list[dict[str, Any]]:
    """Aggregate one uploaded batch; unavailable scoring inputs remain None."""
    networks = [ipaddress.ip_network(network, strict=False) for network in internal_networks]
    by_device: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for event in events:
        by_device[event["device"]].append(event)

    summaries = []
    for device, device_events in sorted(by_device.items(), key=lambda item: item[0].casefold()):
        connections = [
            event for event in device_events
            if event["event_type"].casefold() in GENERIC_CONNECTION_TYPES
        ]

        failed_values = []
        failed_incomplete = False
        for event in device_events:
            event_type = event["event_type"].casefold()
            if event["failed_connections"] is not None:
                failed_values.append(event["failed_connections"])
            elif event_type in GENERIC_CONNECTION_TYPES:
                outcome = event["action"].casefold() if event["action"] else None
                if outcome in KNOWN_OUTCOMES:
                    failed_values.append(int(outcome in FAILED_OUTCOMES))
                else:
                    failed_incomplete = True
        failed_connections = (
            sum(failed_values) if failed_values and not failed_incomplete else None
        )

        external_values = []
        external_incomplete = False
        for event in device_events:
            event_type = event["event_type"].casefold()
            if event["external_connections"] is not None:
                external_values.append(event["external_connections"])
            elif event_type in GENERIC_CONNECTION_TYPES:
                if (
                    networks
                    and event["source_ip"] is not None
                    and event["destination_ip"] is not None
                ):
                    external_values.append(int(
                        any(
                            ipaddress.ip_address(event["source_ip"]) in network
                            for network in networks
                        )
                        and not any(
                            ipaddress.ip_address(event["destination_ip"]) in network
                            for network in networks
                        )
                    ))
                else:
                    external_incomplete = True
        external_connections = (
            sum(external_values) if external_values and not external_incomplete else None
        )

        directions = [event["direction"].casefold() if event["direction"] else None for event in connections]
        outbound_events = [
            event for event, direction in zip(connections, directions)
            if direction == "outbound"
        ]
        generic_bytes_complete = (
            connections
            and all(direction in {"inbound", "outbound"} for direction in directions)
            and all(event["bytes_out"] is not None for event in outbound_events)
        )
        direct_byte_events = [
            event for event in device_events
            if event["event_type"].casefold() not in GENERIC_CONNECTION_TYPES
        ]
        direct_bytes_complete = all(event["bytes_out"] is not None for event in direct_byte_events)
        if connections and generic_bytes_complete and direct_bytes_complete:
            bytes_out = sum(event["bytes_out"] for event in outbound_events) + sum(
                event["bytes_out"] for event in direct_byte_events
            )
        elif connections:
            bytes_out = None
        else:
            bytes_out = (
                sum(event["bytes_out"] for event in device_events)
                if device_events and all(event["bytes_out"] is not None for event in device_events)
                else None
            )

        unusual_values = []
        unusual_incomplete = False
        for event in device_events:
            event_type = event["event_type"].casefold()
            if event["unusual_port"] is not None:
                unusual_values.append(event["unusual_port"])
            elif event_type in GENERIC_CONNECTION_TYPES:
                if unusual_ports and event["destination_port"] is not None:
                    unusual_values.append(int(event["destination_port"] in unusual_ports))
                else:
                    unusual_incomplete = True
        unusual_port = (
            int(any(value == 1 for value in unusual_values))
            if unusual_values and not unusual_incomplete
            else None
        )

        summaries.append({
            "device": device,
            "failed_connections": failed_connections,
            "external_connections": external_connections,
            "unusual_port": unusual_port,
            "bytes_out": bytes_out,
            "event_count": len(device_events),
            "last_seen": max(event["timestamp"] for event in device_events),
            "sources": sorted({event["source"] for event in device_events}),
            "events": device_events,
        })
    return summaries


def count_scoring_usable_events(
    events: list[dict[str, Any]],
    internal_networks: list[str],
    unusual_ports: set[int],
) -> int:
    """Count accepted events that contain or can derive at least one scoring input."""
    networks = [ipaddress.ip_network(network, strict=False) for network in internal_networks]
    usable = 0
    for event in events:
        if any(
            event[field] is not None
            for field in (
                "failed_connections",
                "external_connections",
                "unusual_port",
            )
        ):
            usable += 1
            continue

        event_type = event["event_type"].casefold()
        if event_type not in GENERIC_CONNECTION_TYPES:
            if event["bytes_out"] is not None:
                usable += 1
            continue
        has_external_inputs = (
            networks
            and event["source_ip"] is not None
            and event["destination_ip"] is not None
        )
        has_unusual_port_inputs = bool(
            unusual_ports and event["destination_port"] is not None
        )
        has_outgoing_byte_inputs = (
            event["direction"] == "inbound"
            or (
                event["direction"] == "outbound"
                and event["bytes_out"] is not None
            )
        )
        if (
            has_external_inputs
            or has_unusual_port_inputs
            or has_outgoing_byte_inputs
        ):
            usable += 1
    return usable
