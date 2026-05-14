"""AccuKnox finding-dashboard lookup for existing verdict reuse."""
from __future__ import annotations

import logging
import os

import httpx

from .schema import Verdict

log = logging.getLogger(__name__)

_SEVERITY_MAP = {
    "low": "low",
    "medium": "medium",
    "high": "high",
    "critical": "critical",
}


def _map_severity(raw: str | None) -> str:
    if not raw:
        return "low"
    return _SEVERITY_MAP.get(raw.lower(), "low")


def _build_params(fingerprint: str, repo_id: str | None = None) -> dict:
    params: dict = {
        "page": 1,
        "page_size": 1,
        "depth": 3,
        "vulnerability__data_type": "sg",
        "ordering": "-last_seen",
        "status": "Active",
        "ignored": "False",
        "misc__fingerprint": fingerprint,
    }
    resolved_repo_id = repo_id or os.environ.get("ACCUKNOX_REPO_ID", "")
    if resolved_repo_id:
        params["asset__resource_id"] = resolved_repo_id
    return params


def _parse_verdict(data: dict) -> Verdict | None:
    results = data.get("results", {})
    items = results.get("data", []) if isinstance(results, dict) else []
    item = items[0] if items else None
    if not item:
        return None
    is_fp = bool(item.get("misc__is_false_positive", False))
    return Verdict(
        verdict="false_positive" if is_fp else "true_positive",
        is_security_vulnerability=not is_fp,
        severity=_map_severity(item.get("misc__final_severity")),
        confidence="high",
        reason=item.get("misc__validation_reason") or "Previously validated finding from AccuKnox.",
    )


async def lookup_existing_verdict_async(
    client: httpx.AsyncClient,
    fingerprint: str,
    base_url: str,
    token: str,
    repo_id: str | None = None,
) -> Verdict | None:
    """Async variant — reuses a shared AsyncClient for connection pooling."""
    try:
        resp = await client.get(
            f"{base_url}/api/v1/finding-dashboard",
            params=_build_params(fingerprint, repo_id=repo_id),
            headers={"Authorization": f"Bearer {token}"},
            timeout=30,
        )
        resp.raise_for_status()
        return _parse_verdict(resp.json())
    except httpx.HTTPStatusError as exc:
        log.warning("AccuKnox HTTP %s for fingerprint %s: %s", exc.response.status_code, fingerprint, exc)
    except httpx.HTTPError as exc:
        log.warning("AccuKnox HTTP error for fingerprint %s: %s", fingerprint, exc)
    except Exception as exc:
        log.warning("AccuKnox lookup failed for fingerprint %s: %s", fingerprint, exc)
    return None


def lookup_existing_verdict(fingerprint: str, repo_id: str | None = None) -> Verdict | None:
    """Synchronous fallback — used when called outside an async context."""
    base_url = os.environ.get("ACCUKNOX_BASE_URL", "").rstrip("/")
    token = os.environ.get("ACCUKNOX_BEARER_TOKEN", "")
    if not base_url or not token:
        return None
    try:
        resp = httpx.get(
            f"{base_url}/api/v1/finding-dashboard",
            params=_build_params(fingerprint, repo_id=repo_id),
            headers={"Authorization": f"Bearer {token}"},
            timeout=30,
        )
        resp.raise_for_status()
        return _parse_verdict(resp.json())
    except httpx.HTTPStatusError as exc:
        log.warning("AccuKnox HTTP %s for fingerprint %s: %s", exc.response.status_code, fingerprint, exc)
    except httpx.HTTPError as exc:
        log.warning("AccuKnox HTTP error for fingerprint %s: %s", fingerprint, exc)
    except Exception as exc:
        log.warning("AccuKnox lookup failed for fingerprint %s: %s", fingerprint, exc)
    return None
