import ipaddress
import json
import time
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import urlopen


BASE_DIR = Path(__file__).resolve().parent.parent
CACHE_PATH = BASE_DIR / "results" / "live_logs" / "geo_cache.json"
API_URL = "https://api.country.is/"
API_FIELDS = "city,continent,subdivision,location,asn"


def _ensure_cache_dir():
    CACHE_PATH.parent.mkdir(parents=True, exist_ok=True)


def load_geo_cache():
    _ensure_cache_dir()
    if not CACHE_PATH.exists():
        return {}

    try:
        with CACHE_PATH.open("r", encoding="utf-8") as handle:
            return json.load(handle)
    except (OSError, json.JSONDecodeError):
        return {}


def save_geo_cache(cache):
    _ensure_cache_dir()
    with CACHE_PATH.open("w", encoding="utf-8") as handle:
        json.dump(cache, handle, ensure_ascii=True, indent=2, sort_keys=True)


def is_public_ip(value):
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return False

    return (
        not address.is_private
        and not address.is_loopback
        and not address.is_multicast
        and not address.is_reserved
        and not address.is_unspecified
    )


def _fetch_geo_from_api(ip_address):
    query = urlencode({"fields": API_FIELDS})
    request_url = f"{API_URL}{ip_address}?{query}"

    with urlopen(request_url, timeout=5) as response:
        payload = json.loads(response.read().decode("utf-8"))

    location = payload.get("location") or {}
    asn = payload.get("asn") or {}

    latitude = location.get("latitude")
    longitude = location.get("longitude")

    if latitude is None or longitude is None:
        return None

    return {
        "ip": ip_address,
        "city": payload.get("city"),
        "country": payload.get("country"),
        "country_code": payload.get("country_code"),
        "continent": payload.get("continent"),
        "region": payload.get("subdivision"),
        "latitude": latitude,
        "longitude": longitude,
        "asn": asn.get("asn"),
        "org": asn.get("name"),
    }


def geolocate_ip(ip_address, cache=None):
    if not ip_address or not is_public_ip(ip_address):
        return None

    geo_cache = cache if cache is not None else load_geo_cache()

    if ip_address in geo_cache:
        return geo_cache[ip_address]

    try:
        geo_data = _fetch_geo_from_api(ip_address)
    except (HTTPError, URLError, TimeoutError, OSError, json.JSONDecodeError):
        return None

    if not geo_data:
        return None

    geo_cache[ip_address] = geo_data
    save_geo_cache(geo_cache)

    # The free country.is endpoint is documented with infrastructure rate limiting.
    time.sleep(0.12)
    return geo_data
