"""Geographic and ASN intelligence for scored proxy servers.

Primary source is the free ip-api.com JSON endpoint (no key required,
rate-limited to 45 req/min). A MaxMind GeoLite2 `.mmdb` file is used as
an offline fallback when the online lookup fails or is rate-limited,
matching the operational pattern already used in production.
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from pathlib import Path

import aiohttp

from src.logging_config import get_logger

logger = get_logger(__name__)

# Country/flag pairs for the handful of common exit locations we format nicely.
_COUNTRY_FLAGS = {
    "DE": "🇩🇪", "NL": "🇳🇱", "FR": "🇫🇷", "GB": "🇬🇧", "US": "🇺🇸",
    "FI": "🇫🇮", "SE": "🇸🇪", "TR": "🇹🇷", "AE": "🇦🇪", "SG": "🇸🇬",
    "JP": "🇯🇵", "CA": "🇨🇦", "IR": "🇮🇷", "RU": "🇷🇺", "CH": "🇨🇭",
    "PL": "🇵🇱", "IT": "🇮🇹", "ES": "🇪🇸", "HK": "🇭🇰", "AT": "🇦🇹",
}

# ASNs / org name fragments known to belong to Iranian mobile/fixed ISPs.
# Configs whose exit IP resolves to one of these are almost never useful
# for circumvention, since the "proxy" would already be inside the
# filtered network.
_IRANIAN_ISP_MARKERS = (
    "mci", "hamrahaval", "irancell", "mtn irancell", "tci",
    "telecommunication company of iran", "rightel", "shatel", "asiatech",
    "parsonline", "pars online", "ir mci",
)


@dataclass
class GeoInfo:
    country_code: str = "XX"
    country_name: str = "Unknown"
    city: str = ""
    lat: float = 0.0
    lon: float = 0.0
    asn: str = ""
    isp: str = ""
    is_iranian_isp: bool = False

    @property
    def flag(self) -> str:
        return _COUNTRY_FLAGS.get(self.country_code, "🌐")


def haversine_km(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    """Great-circle distance in kilometers between two lat/lon points."""
    r = 6371.0
    phi1, phi2 = math.radians(lat1), math.radians(lat2)
    dphi = math.radians(lat2 - lat1)
    dlambda = math.radians(lon2 - lon1)
    a = math.sin(dphi / 2) ** 2 + math.cos(phi1) * math.cos(phi2) * math.sin(dlambda / 2) ** 2
    return 2 * r * math.asin(math.sqrt(a))


def _looks_iranian(isp: str, org: str) -> bool:
    haystack = f"{isp} {org}".lower()
    return any(marker in haystack for marker in _IRANIAN_ISP_MARKERS)


async def lookup_online(session: aiohttp.ClientSession, host: str) -> GeoInfo | None:
    """Query ip-api.com for geo/ASN data. Returns None on failure."""
    url = f"http://ip-api.com/json/{host}?fields=status,country,countryCode,city,lat,lon,isp,org,as"
    try:
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=5)) as resp:
            data = await resp.json(content_type=None)
    except (aiohttp.ClientError, TimeoutError) as exc:
        logger.debug("geo_online_lookup_failed", host=host, error=str(exc))
        return None

    if data.get("status") != "success":
        return None

    isp = str(data.get("isp", ""))
    org = str(data.get("org", ""))
    return GeoInfo(
        country_code=str(data.get("countryCode", "XX")),
        country_name=str(data.get("country", "Unknown")),
        city=str(data.get("city", "")),
        lat=float(data.get("lat", 0.0)),
        lon=float(data.get("lon", 0.0)),
        asn=str(data.get("as", "")),
        isp=isp,
        is_iranian_isp=_looks_iranian(isp, org),
    )


class OfflineGeoResolver:
    """Fallback resolver using a local MaxMind GeoLite2 database."""

    def __init__(self, db_path: str) -> None:
        self._db_path = Path(db_path)
        self._reader = None
        if self._db_path.exists():
            try:
                import geoip2.database

                self._reader = geoip2.database.Reader(str(self._db_path))
            except Exception as exc:  # pragma: no cover - optional dependency path
                logger.warning("geoip_db_load_failed", path=str(self._db_path), error=str(exc))

    def lookup(self, host: str) -> GeoInfo | None:
        if self._reader is None:
            return None
        try:
            resp = self._reader.city(host)
        except Exception:
            return None
        return GeoInfo(
            country_code=resp.country.iso_code or "XX",
            country_name=resp.country.name or "Unknown",
            city=resp.city.name or "",
            lat=float(resp.location.latitude or 0.0),
            lon=float(resp.location.longitude or 0.0),
        )


async def resolve_geo(
    session: aiohttp.ClientSession, host: str, offline_resolver: OfflineGeoResolver | None = None
) -> GeoInfo:
    """Resolve geo info for a host, preferring the online API with offline fallback."""
    info = await lookup_online(session, host)
    if info is not None:
        return info
    if offline_resolver is not None:
        offline = offline_resolver.lookup(host)
        if offline is not None:
            return offline
    return GeoInfo()
