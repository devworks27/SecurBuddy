"""Live IOC reputation lookups against AbuseIPDB and VirusTotal.

Every lookup degrades gracefully: a missing key, a rate limit, an outage, or an
address that public feeds have never heard of all produce a structured result
rather than an exception.
"""

import asyncio
import base64
import logging
from typing import Any, Awaitable, TypeVar

import httpx

from config import (
    HTTP_TIMEOUT_SECONDS,
    MAX_IP_CHECKS,
    MAX_URL_CHECKS,
    settings,
)
from detector import documentation_label

logger = logging.getLogger("securbuddy")

ABUSEIPDB_CHECK = "https://api.abuseipdb.com/api/v2/check"
VIRUSTOTAL_URL_LOOKUP = "https://www.virustotal.com/api/v3/urls/"
VIRUSTOTAL_IP_LOOKUP = "https://www.virustotal.com/api/v3/ip_addresses/"

T = TypeVar("T")


class ReputationService:
    """Shared async HTTP client plus the two provider adapters."""

    def __init__(self) -> None:
        self.client = httpx.AsyncClient(
            timeout=HTTP_TIMEOUT_SECONDS,
            follow_redirects=False,
            headers={"User-Agent": "SecurBuddy/1.0 (defensive security triage tool)"},
        )

    async def aclose(self) -> None:
        await self.client.aclose()

    # ---------------------------------------------------------------- IP

    async def check_ip(self, ip: str) -> dict[str, Any]:
        """AbuseIPDB verdict for one IP address."""
        result: dict[str, Any] = {"ip": ip, "source": "abuseipdb"}

        reserved = documentation_label(ip)
        if reserved:
            result.update(
                {
                    "status": "reserved_range",
                    "abuse_confidence_score": None,
                    "is_tor": False,
                    "isp": None,
                    "country_code": None,
                    "total_reports": None,
                    "usage_type": "Reserved",
                    "summary": f"{ip} sits in a reserved range ({reserved}). It is not a routable "
                    "public address, so threat feeds carry no reputation data for it. The verdict "
                    "above rests on content analysis alone.",
                }
            )
            return result

        key = settings.abuseipdb_api_key
        if not key:
            result.update({"status": "skipped", "summary": "ABUSEIPDB_API_KEY is not configured."})
            return result

        try:
            response = await self.client.get(
                ABUSEIPDB_CHECK,
                params={"ipAddress": ip, "maxAgeInDays": 90},
                headers={"Key": key, "Accept": "application/json"},
            )
        except httpx.HTTPError as exc:
            result.update({"status": "error", "summary": f"AbuseIPDB request failed: {exc}"})
            return result

        if response.status_code == 429:
            result.update({"status": "rate_limited", "summary": "AbuseIPDB rate limit reached."})
            return result
        if response.status_code != 200:
            result.update({"status": "error", "summary": f"AbuseIPDB returned HTTP {response.status_code}."})
            return result

        try:
            data = response.json().get("data", {})
            score = data.get("abuseConfidenceScore")
            score = int(score) if isinstance(score, (int, float)) else None
            is_tor = bool(data.get("isTor"))
            isp = data.get("isp") or "Unknown"
            country = data.get("countryCode") or "??"
            reports = data.get("totalReports")
            reports = int(reports) if isinstance(reports, (int, float)) else 0
            usage = data.get("usageType") or "Unknown"
        except (ValueError, AttributeError) as exc:
            result.update({"status": "error", "summary": f"Could not parse AbuseIPDB response: {exc}"})
            return result

        if is_tor:
            summary = f"Tor exit node operated by {isp} ({country}). {reports} abuse reports on record."
        elif score is not None and score >= 80:
            summary = f"Known abuser: {score}% abuse confidence across {reports} reports ({isp}, {country})."
        elif score is not None and score >= 30:
            summary = f"Possibly abusive: {score}% abuse confidence across {reports} reports ({isp}, {country})."
        elif score is not None:
            summary = f"No significant abuse reported ({score}% confidence, {usage}, {isp})."

        result.update(
            {
                "status": "ok",
                "abuse_confidence_score": score,
                "is_tor": is_tor,
                "isp": isp,
                "country_code": country,
                "total_reports": reports,
                "usage_type": usage,
                "domain": data.get("domain"),
                "summary": summary,
                "is_public": bool(data.get("isPublic")),
            }
        )
        return result

    # --------------------------------------------------------------- URL

    async def check_url(self, url: str) -> dict[str, Any]:
        """VirusTotal verdict for one URL."""
        result: dict[str, Any] = {"url": url, "source": "virustotal"}
        key = settings.virustotal_api_key
        if not key:
            result.update({"status": "skipped", "summary": "VIRUSTOTAL_API_KEY is not configured."})
            return result

        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        try:
            response = await self.client.get(
                VIRUSTOTAL_URL_LOOKUP + url_id,
                headers={"x-apikey": key},
            )
        except httpx.HTTPError as exc:
            result.update({"status": "error", "summary": f"VirusTotal request failed: {exc}"})
            return result

        if response.status_code == 404:
            result.update(
                {
                    "status": "unknown",
                    "verdict": "unknown",
                    "malicious": 0,
                    "suspicious": 0,
                    "malicious_ratio": None,
                    "summary": "VirusTotal has no record of this URL. It was most likely never "
                    "submitted for scanning, which is common for brand-new phishing domains. "
                    "Unknown is not the same as safe.",
                }
            )
            return result
        if response.status_code == 429:
            result.update({"status": "rate_limited", "summary": "VirusTotal rate limit reached."})
            return result
        if response.status_code != 200:
            result.update({"status": "error", "summary": f"VirusTotal returned HTTP {response.status_code}."})
            return result

        try:
            attributes = response.json()["data"]["attributes"]
            stats = attributes.get("last_analysis_stats") or {}
        except (ValueError, KeyError, TypeError) as exc:
            result.update({"status": "error", "summary": f"Could not parse VirusTotal response: {exc}"})
            return result

        malicious = int(stats.get("malicious", 0) or 0)
        suspicious = int(stats.get("suspicious", 0) or 0)
        harmless = int(stats.get("harmless", 0) or 0)
        undetected = int(stats.get("undetected", 0) or 0)
        total = malicious + suspicious + harmless + undetected

        if malicious > 0:
            verdict = "malicious"
            summary = f"{malicious} of {total} security vendors flag this URL as malicious."
        elif suspicious > 0:
            verdict = "suspicious"
            summary = f"{suspicious} of {total} vendors rate this URL as suspicious."
        else:
            verdict = "unrated"
            summary = "No vendor has flagged this URL, though it may simply be unknown to VirusTotal."

        result.update(
            {
                "status": "ok",
                "verdict": verdict,
                "malicious": malicious,
                "suspicious": suspicious,
                "harmless": harmless,
                "undetected": undetected,
                "malicious_ratio": round(malicious / total, 2) if total else None,
                "permalink": attributes.get("permalink"),
                "summary": summary,
            }
        )
        return result

    # ------------------------------------------------------------ enrich

    async def enrich(self, iocs: dict[str, list[str]]) -> dict[str, Any]:
        """Look up every extracted IOC, honouring the free-tier query caps."""
        ip_reports = await self._gather(
            [self.check_ip(ip) for ip in iocs.get("ips", [])[:MAX_IP_CHECKS]]
        )
        url_reports = await self._gather(
            [self.check_url(url) for url in iocs.get("urls", [])[:MAX_URL_CHECKS]]
        )
        return {
            "ip_reports": ip_reports,
            "url_reports": url_reports,
            "skipped_ips": iocs.get("ips", [])[MAX_IP_CHECKS:],
            "skipped_urls": iocs.get("urls", [])[MAX_URL_CHECKS:],
        }

    @staticmethod
    async def _gather(coroutines: list[Awaitable[T]]) -> list[T]:
        """Await every lookup concurrently, converting failures into None."""
        if not coroutines:
            return []
        results = await asyncio.gather(*coroutines, return_exceptions=True)
        clean: list[T] = []
        for result in results:
            if isinstance(result, BaseException):
                logger.warning("Reputation lookup failed: %s", result)
                continue
            clean.append(result)
        return clean