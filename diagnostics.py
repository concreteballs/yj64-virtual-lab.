"""Privacy-safe diagnostic event filtering for YJ-64.

Only bounded operational metadata is retained. Message bodies, model output,
exception text, tracebacks, credentials, and arbitrary fields are never stored.
"""
from __future__ import annotations

import re
from typing import Any, Mapping

_SAFE_STRING_FIELDS = {
    "process_name", "provider", "model", "route_id", "operation_id",
    "request_id", "error_type", "status", "archive_schema",
}
_SAFE_INTEGER_FIELDS = {
    "pid", "history_count", "common_history_count", "private_history_count",
    "prompt_length", "response_length", "input_length", "output_length",
    "file_count", "file_size", "size_bytes", "status_code", "http_status",
    "retry_count", "attempt", "elapsed_ms", "duration_ms", "line_number",
}
_SAFE_BOOLEAN_FIELDS = {
    "configured", "explicit_user_action", "focused", "success",
    "all_archives_verified", "private", "error_present",
}
_PROMPT_FIELDS = {"prompt", "message", "request", "request_message", "input", "content"}
_RESPONSE_FIELDS = {"response", "output", "result"}
_ERROR_FIELDS = {"error", "exception", "traceback", "message_error"}
_SAFE_TOKEN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:/-]{0,95}$")
_PARTICIPANT = re.compile(r"^(Owner|Participant [1-9][0-9]*)$")


def _safe_string(field: str, value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    value = value.strip()
    if not value or len(value) > 96:
        return None
    if field == "participant":
        return value if _PARTICIPANT.fullmatch(value) else None
    if field == "mode":
        return value if value in {"text", "agent"} else None
    if field == "provider":
        return value if _SAFE_TOKEN.fullmatch(value) else None
    return value if _SAFE_TOKEN.fullmatch(value) else None


def sanitize_event_data(event: str, data: Mapping[str, Any] | None) -> dict[str, Any]:
    """Return a strict metadata-only representation of an event payload."""
    if not isinstance(data, Mapping):
        return {}

    safe: dict[str, Any] = {}
    prompt_length = None
    response_length = None
    error_present = False

    for raw_key, value in data.items():
        key = str(raw_key).strip().lower()

        if key in _PROMPT_FIELDS and isinstance(value, (str, bytes, bytearray)):
            prompt_length = len(value)
            continue
        if key in _RESPONSE_FIELDS and isinstance(value, (str, bytes, bytearray)):
            response_length = len(value)
            continue
        if key in _ERROR_FIELDS:
            error_present = value is not None
            continue

        if key in _SAFE_STRING_FIELDS or key in {"participant", "mode"}:
            cleaned = _safe_string(key, value)
            if cleaned is not None:
                safe[key] = cleaned
            continue

        if key in _SAFE_INTEGER_FIELDS:
            if isinstance(value, int) and not isinstance(value, bool) and 0 <= value <= 2**63 - 1:
                safe[key] = value
            continue

        if key in _SAFE_BOOLEAN_FIELDS and isinstance(value, bool):
            safe[key] = value

    if prompt_length is not None:
        safe["prompt_length"] = prompt_length
    if response_length is not None:
        safe["response_length"] = response_length
    if error_present:
        safe["error_present"] = True
    return safe
