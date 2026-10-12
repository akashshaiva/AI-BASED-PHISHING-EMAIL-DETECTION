import re
from email.utils import parseaddr


def _normalize_email(value):
    if value is None:
        return ""
    cleaned = str(value).strip()
    if not cleaned:
        return ""
    return parseaddr(cleaned)[1] or cleaned.lower()


def _coerce_text(value):
    if value is None:
        return ""
    if isinstance(value, (list, tuple)):
        return " ".join(str(item) for item in value if item is not None)
    return str(value).strip()


def _domain_from_email(email):
    email = _normalize_email(email)
    if not email or "@" not in email:
        return ""
    return email.split("@", 1)[1].strip().lower()


def _parse_auth_result_value(auth_text, key):
    auth_text = _coerce_text(auth_text)
    if not auth_text:
        return {"status": "not_found", "details": "No authentication result available."}

    pattern = rf"{key}\s*=\s*([a-zA-Z]+)"
    match = re.search(pattern, auth_text, flags=re.IGNORECASE)
    if match:
        status = match.group(1).lower()
        return {"status": status, "details": auth_text.strip()}

    return {"status": "not_found", "details": "Authentication result not present."}


def _parse_received_headers(received_headers):
    if not received_headers:
        return []

    if isinstance(received_headers, str):
        received_headers = [received_headers]

    parsed = []
    for header in received_headers:
        if not header or not isinstance(header, str):
            continue

        record = {
            "raw": header.strip(),
            "from": "",
            "by": "",
            "with": "",
            "protocol": "",
            "id": "",
        }

        for key in ["from", "by", "with", "proto", "id"]:
            match = re.search(rf"\b{key}=(?:\[)?([^;\s]+)(?:\])?", header, flags=re.IGNORECASE)
            if match:
                record[key] = match.group(1).strip()

        if "by" in record and record["by"]:
            record["suspicious"] = record["by"].lower() in {"unknown", "localhost"}
        else:
            record["suspicious"] = False

        parsed.append(record)

    return parsed


def analyze_email_headers(headers):
    if not headers:
        return {
            "headers_present": False,
            "indicator_count": 0,
            "indicators": [],
            "summary": {
                "risk_level": "none",
                "notes": "No email header data was provided for analysis.",
            },
            "auth_results": {},
            "received_headers": [],
        }

    if not isinstance(headers, dict):
        return {
            "headers_present": False,
            "indicator_count": 0,
            "indicators": [],
            "summary": {"risk_level": "none", "notes": "Header payload is not a dictionary."},
            "auth_results": {},
            "received_headers": [],
        }

    normalized = {}
    for key, value in headers.items():
        normalized[str(key).lower()] = value

    sender = _normalize_email(normalized.get("from"))
    reply_to = _normalize_email(normalized.get("reply-to"))
    return_path = _normalize_email(normalized.get("return-path"))
    auth_results = _coerce_text(
        normalized.get("authentication-results") or normalized.get("authenticationresults") or ""
    )
    received_headers = normalized.get("received") or normalized.get("received_headers") or []
    if isinstance(received_headers, str):
        received_headers = [received_headers]
    elif not isinstance(received_headers, list):
        received_headers = [received_headers] if received_headers is not None else []

    indicators = []
    mismatch_count = 0

    if sender and reply_to and sender != reply_to:
        mismatch_count += 1
        indicators.append(
            {
                "type": "from_reply_to_mismatch",
                "status": "warning",
                "details": f"From address '{sender}' does not match Reply-To '{reply_to}'.",
            }
        )

    if sender and return_path:
        sender_domain = _domain_from_email(sender)
        return_domain = _domain_from_email(return_path)
        if sender_domain and return_domain and sender_domain != return_domain:
            mismatch_count += 1
            indicators.append(
                {
                    "type": "return_path_mismatch",
                    "status": "warning",
                    "details": f"Return-Path domain '{return_domain}' differs from sender domain '{sender_domain}'.",
                }
            )

    auth_summary = {
        "spf": _parse_auth_result_value(auth_results, "spf"),
        "dkim": _parse_auth_result_value(auth_results, "dkim"),
        "dmarc": _parse_auth_result_value(auth_results, "dmarc"),
    }

    if auth_results:
        indicators.append(
            {
                "type": "authentication_results_present",
                "status": "info",
                "details": "Authentication-Results header is present and was inspected for SPF, DKIM, and DMARC values.",
            }
        )

    parsed_received = _parse_received_headers(received_headers)
    suspicious_received = []
    for item in parsed_received:
        if item.get("suspicious"):
            suspicious_received.append(item)

    if suspicious_received:
        indicators.append(
            {
                "type": "unusual_received_header",
                "status": "warning",
                "details": "One or more Received headers contain suspicious or unusual route indicators.",
                "items": suspicious_received,
            }
        )

    risk_level = "low"
    if indicators:
        warning_types = {item["status"] for item in indicators if item.get("status") in {"warning", "high"}}
        if "warning" in warning_types or mismatch_count > 0:
            risk_level = "medium"
        if len(indicators) >= 3:
            risk_level = "high"

    result = {
        "headers_present": True,
        "indicator_count": len(indicators),
        "indicators": indicators,
        "summary": {
            "risk_level": risk_level,
            "from_reply_to_mismatch": bool(sender and reply_to and sender != reply_to),
            "return_path_mismatch": bool(sender and return_path and _domain_from_email(sender) and _domain_from_email(return_path) and _domain_from_email(sender) != _domain_from_email(return_path)),
            "authentication_results_present": bool(auth_results),
            "received_header_count": len(parsed_received),
            "notes": "Header results are suspicious indicators only and are not proof of phishing on their own.",
        },
        "auth_results": auth_summary,
        "received_headers": parsed_received,
    }

    return result
