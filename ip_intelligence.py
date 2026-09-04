"""Safe, best-effort IP geolocation for the Streamlit dashboard."""

from __future__ import annotations

import ipaddress
import json
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import Request, urlopen


USER_AGENT = "EmailThreatIntelligence/1.0"


def _request_json(url: str, timeout: float = 4.0) -> dict[str, Any]:
    """Fetch one JSON object over HTTPS without adding a third-party dependency."""
    request = Request(url, headers={"Accept": "application/json", "User-Agent": USER_AGENT})
    with urlopen(request, timeout=timeout) as response:
        payload = json.loads(response.read().decode("utf-8"))
    if not isinstance(payload, dict):
        raise ValueError("Geolocation service returned an unexpected response.")
    return payload


def _failed(message: str) -> dict[str, Any]:
    return {"success": False, "message": message}


def get_ip_geolocation(ip_address: str) -> dict[str, Any]:
    """Return normalized approximate location data for a public IPv4/IPv6 address.

    ipapi.co is used first; ipwho.is is a no-key HTTPS fallback.  Failures are
    returned as data so an unavailable service never stops email analysis.
    """
    try:
        address = ipaddress.ip_address(ip_address)
    except ValueError:
        return _failed("Invalid IP address; geolocation was not performed.")

    if not address.is_global:
        return _failed("Private, reserved, or non-public IP address; geolocation was not performed.")

    ip = quote(str(address), safe="")
    failures: list[str] = []

    try:
        payload = _request_json(f"https://ipapi.co/{ip}/json/")
        if not payload.get("error") and payload.get("ip", str(address)):
            return {
                "success": True,
                "provider": "ipapi.co",
                "country": payload.get("country_name") or payload.get("country"),
                "region": payload.get("region"),
                "city": payload.get("city"),
                "latitude": payload.get("latitude"),
                "longitude": payload.get("longitude"),
                "isp": payload.get("org"),
                "organization": payload.get("org"),
                "asn": payload.get("asn"),
            }
        failures.append(str(payload.get("reason") or payload.get("error") or "ipapi.co could not complete the lookup"))
    except HTTPError as error:
        failures.append("ipapi.co rate limit reached" if error.code == 429 else f"ipapi.co returned HTTP {error.code}")
    except (URLError, TimeoutError, ValueError, json.JSONDecodeError):
        failures.append("ipapi.co was unavailable or returned invalid data")

    try:
        payload = _request_json(f"https://ipwho.is/{ip}")
        if payload.get("success", True):
            connection = payload.get("connection") or {}
            return {
                "success": True,
                "provider": "ipwho.is",
                "country": payload.get("country"),
                "region": payload.get("region"),
                "city": payload.get("city"),
                "latitude": payload.get("latitude"),
                "longitude": payload.get("longitude"),
                "isp": connection.get("isp"),
                "organization": connection.get("org"),
                "asn": connection.get("asn"),
            }
        failures.append(str(payload.get("message") or "ipwho.is could not complete the lookup"))
    except HTTPError as error:
        failures.append(f"ipwho.is returned HTTP {error.code}")
    except (URLError, TimeoutError, ValueError, json.JSONDecodeError):
        failures.append("ipwho.is was unavailable or returned invalid data")

    return _failed("Geolocation is temporarily unavailable: " + "; ".join(failures))
