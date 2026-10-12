import re
from urllib.parse import urlparse


SUSPICIOUS_KEYWORDS = [
    "verify",
    "urgent",
    "secure",
    "confirm",
    "update",
    "login",
    "password",
    "reset",
    "click",
    "claim",
    "reward",
    "suspended",
    "limited",
    "immediately",
    "final",
    "action required",
    "account",
]


def extract_urls(text):
    if not text:
        return []

    pattern = r"https?://[^\s<>'\"]+|www\.[^\s<>'\"]+"
    return re.findall(pattern, text, flags=re.IGNORECASE)


def _count_special_characters(value):
    specials = set("!@#$%^&*()_+=-[]{}|\\:;\"'<>?,./~`")
    return sum(1 for ch in value if ch in specials)


def _has_ip_address(url):
    try:
        parsed = urlparse(url)
        host = parsed.hostname or ""
        return bool(re.match(r"^(\d{1,3}\.){3}\d{1,3}$", host))
    except Exception:
        return False


def analyze_url_features(text):
    urls = extract_urls(text)
    url_details = []
    suspicious_keyword_hits = []

    for url in urls:
        parsed = urlparse(url)
        scheme = parsed.scheme.lower() if parsed.scheme else "unknown"
        hostname = parsed.hostname or ""
        host_length = len(hostname)
        dot_count = url.count(".")
        special_count = _count_special_characters(url)
        has_ip = _has_ip_address(url)

        keyword_hits = []
        lowered = url.lower()
        for keyword in SUSPICIOUS_KEYWORDS:
            if keyword in lowered:
                keyword_hits.append(keyword)

        if keyword_hits:
            suspicious_keyword_hits.extend(keyword_hits)

        url_details.append(
            {
                "url": url,
                "scheme": scheme,
                "length": len(url),
                "host_length": host_length,
                "dot_count": dot_count,
                "special_character_count": special_count,
                "uses_ip_address": has_ip,
                "uses_http": scheme == "http",
                "uses_https": scheme == "https",
                "suspicious_keywords": keyword_hits,
            }
        )

    return {
        "count": len(urls),
        "urls": url_details,
        "summary": {
            "total_length": sum(item["length"] for item in url_details),
            "average_length": round(sum(item["length"] for item in url_details) / len(url_details), 2) if url_details else 0,
            "total_dots": sum(item["dot_count"] for item in url_details),
            "total_special_characters": sum(item["special_character_count"] for item in url_details),
            "has_ip_address": any(item["uses_ip_address"] for item in url_details),
            "uses_http": any(item["uses_http"] for item in url_details),
            "uses_https": any(item["uses_https"] for item in url_details),
            "suspicious_keywords": sorted(set(suspicious_keyword_hits)),
        },
    }
