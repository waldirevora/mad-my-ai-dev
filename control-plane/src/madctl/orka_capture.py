"""D4 experiment: correlate a simulated response with a review result.

This module is not wired into Orka or a real provider. The injected
transport, context, and endpoint policy are simulated trust inputs.
It does not authenticate TLS, protect signing keys, persist evidence,
enforce one-time use, or authorize a merge.
"""
from __future__ import annotations

import json
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any

from .canonical import canonical_sha256, sha256_bytes
from .errors import EvidenceError, IndeterminateExternalResult


_CONTEXT_FIELDS = frozenset({
    "provider",
    "endpoint",
    "model",
    "execution_identity",
    "review_run_id",
    "gate",
    "review_generation",
})

_RESPONSE_FIELDS = frozenset({
    "id",
    "status",
    "output_text",
})

_MAX_RESPONSE_BYTES = 262_144


@dataclass(frozen=True)
class ObservedReview:
    capture: dict[str, Any]
    response_sha256: str


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise EvidenceError("duplicate JSON property in observed response")
        result[key] = value
    return result


def _reject_constant(value: str) -> None:
    raise EvidenceError(f"invalid JSON constant: {value}")


def _parse_json(value: bytes | str) -> Any:
    try:
        return json.loads(
            value,
            object_pairs_hook=_unique_object,
            parse_constant=_reject_constant,
        )
    except (ValueError, UnicodeDecodeError) as exc:
        raise EvidenceError("invalid observed JSON") from exc


def capture_simulated_review(
    *,
    context: Mapping[str, Any],
    allowed_endpoints: frozenset[str],
    transport: Callable[[], bytes],
    presented_result: dict[str, Any],
) -> ObservedReview:
    """Compare a presented result to bytes returned by a mock transport.

    Context and endpoint policy must be independently provisioned.
    This prototype cannot verify that those inputs are truly protected.
    """
    if type(context) is not dict or set(context) != _CONTEXT_FIELDS:
        raise EvidenceError("invalid trusted capture context")

    for field in _CONTEXT_FIELDS - {"review_generation"}:
        value = context[field]
        if type(value) is not str or not 0 < len(value) <= 255:
            raise EvidenceError(f"invalid capture context field: {field}")

    generation = context["review_generation"]
    if type(generation) is not int or generation < 1:
        raise EvidenceError("invalid review generation")

    if context["gate"] not in {"code-review", "security-review"}:
        raise EvidenceError("invalid review gate")

    if (
        type(allowed_endpoints) is not frozenset
        or context["endpoint"] not in allowed_endpoints
        or not context["endpoint"].startswith("https://")
    ):
        raise EvidenceError("capture endpoint is not allowed")

    if type(presented_result) is not dict:
        raise EvidenceError("invalid presented review result")

    try:
        raw_response = transport()
    except Exception as exc:
        raise IndeterminateExternalResult(
            "simulated transport outcome requires reconciliation"
        ) from exc

    if (
        type(raw_response) is not bytes
        or not 0 < len(raw_response) <= _MAX_RESPONSE_BYTES
    ):
        raise EvidenceError("invalid observed response bytes")

    response = _parse_json(raw_response)

    # This envelope is a test fixture, not a real provider API schema.
    if type(response) is not dict or set(response) != _RESPONSE_FIELDS:
        raise EvidenceError("invalid simulated response envelope")

    response_id = response["id"]
    if type(response_id) is not str or not 0 < len(response_id) <= 256:
        raise EvidenceError("missing observed response ID")

    if response["status"] != "completed":
        raise EvidenceError("observed response is not terminal success")

    output_text = response["output_text"]
    if type(output_text) is not str or not output_text:
        raise EvidenceError("missing observed review text")

    result = _parse_json(output_text)
    if type(result) is not dict:
        raise EvidenceError("observed review result must be an object")

    observed_digest = canonical_sha256(result)

    if observed_digest != canonical_sha256(presented_result):
        raise EvidenceError("presented result differs from observed response")

    capture = {
        "kind": "mad.orka.simulated-capture.v0",
        "provider": context["provider"],
        "endpoint": context["endpoint"],
        "model": context["model"],
        "execution_identity": context["execution_identity"],
        "response_id": response_id,
        "review_run_id": context["review_run_id"],
        "gate": context["gate"],
        "review_generation": generation,
        "result_sha256": observed_digest,
        "terminal_state": "success",
    }

    return ObservedReview(
        capture=capture,
        response_sha256=sha256_bytes(raw_response),
    )
