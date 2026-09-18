"""RFC 9457 problem details responses.

Every error the API returns is one of these, with `application/problem+json`
and the member set from `components.schemas.Problem` in spec/openapi.yaml:
type, title, status, and optionally detail and rule.
"""

from __future__ import annotations

from typing import Any

from django.http import JsonResponse

PROBLEM_CONTENT_TYPE = "application/problem+json"

# Registry of problem types. The URI is stable and dereferenceable next to the
# spec; the title is the human-readable summary RFC 9457 asks for.
TITLES: dict[str, str] = {
    "invalid-json": "Request body is not JSON",
    "schema-violation": "Request body does not match the schema",
    "filter-rule": "An observation breaks a filter rule",
    "unknown-key": "Unknown ingest key",
    "retired-key": "Ingest key is retired",
    "undecryptable": "Envelope could not be decrypted",
    "unknown-network": "Unknown network",
    "rate-limited": "Too many requests",
    "claim-not-verified": "Challenge code was not seen on that network",
    "method-not-allowed": "Method not allowed",
    "not-found": "Not found",
}

TYPE_BASE = "https://wifishare.github.io/spec/problems/"


def problem(
    slug: str,
    status: int,
    *,
    detail: str | None = None,
    rule: str | None = None,
    headers: dict[str, str] | None = None,
) -> JsonResponse:
    body: dict[str, Any] = {
        "type": f"{TYPE_BASE}{slug}",
        "title": TITLES.get(slug, slug.replace("-", " ").capitalize()),
        "status": status,
    }
    if detail is not None:
        body["detail"] = detail
    if rule is not None:
        body["rule"] = rule

    response = JsonResponse(body, status=status, content_type=PROBLEM_CONTENT_TYPE)
    for name, value in (headers or {}).items():
        response[name] = value
    return response
