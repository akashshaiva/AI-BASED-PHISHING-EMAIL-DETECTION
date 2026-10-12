import re
from email import policy
from email.parser import BytesParser
from email.utils import parseaddr
from html import unescape


HEADER_FIELDS = [
    "From",
    "To",
    "Subject",
    "Reply-To",
    "Return-Path",
    "Authentication-Results",
]


def _decode_part(part):
    if part is None:
        return ""

    if part.get_content_disposition() == "attachment":
        return ""

    payload = part.get_payload(decode=True)
    if payload is None:
        payload = part.get_payload()

    if isinstance(payload, bytes):
        charset = part.get_content_charset() or "utf-8"
        try:
            return payload.decode(charset, errors="replace")
        except Exception:
            return payload.decode("utf-8", errors="replace")

    if isinstance(payload, str):
        return payload

    return str(payload or "")


def _strip_html(html_text):
    if not html_text:
        return ""

    text = re.sub(r"<script.*?</script>", " ", html_text, flags=re.IGNORECASE | re.DOTALL)
    text = re.sub(r"<style.*?</style>", " ", text, flags=re.IGNORECASE | re.DOTALL)
    text = re.sub(r"<[^>]+>", " ", text)
    text = unescape(text)
    text = re.sub(r"\s+", " ", text)
    return text.strip()


def _extract_text_from_message(message):
    plain_text = []
    html_text = ""

    if message.is_multipart():
        for part in message.walk():
            if part.is_multipart() or part.get_content_disposition() == "attachment":
                continue

            content_type = part.get_content_type()
            content = _decode_part(part)
            if not content:
                continue

            if content_type == "text/plain":
                plain_text.append(content)
            elif content_type == "text/html" and not html_text:
                html_text = content
    else:
        plain_text.append(_decode_part(message))

    text_body = "\n".join(plain_text).strip()
    html_body = _strip_html(html_text).strip() if html_text else ""
    return text_body, html_body


def _extract_urls_from_text(text):
    if not text:
        return []
    pattern = r"https?://[^\s<>'\"]+|www\.[^\s<>'\"]+"
    return re.findall(pattern, text, flags=re.IGNORECASE)


def _fallback_header_parse(file_bytes):
    try:
        text = file_bytes.decode("utf-8", errors="replace")
    except Exception:
        text = str(file_bytes, errors="replace")

    fallback = {}
    sections = text.split("\n\n", 1)
    header_block = sections[0] if sections else text
    for line in header_block.splitlines():
        if ":" not in line:
            continue
        key, _, value = line.partition(":")
        key = key.strip()
        value = value.strip()
        if key in {"From", "To", "Subject", "Reply-To", "Return-Path", "Authentication-Results"}:
            fallback[key] = value
    return fallback


def _clean_address(value):
    if not value:
        return ""
    parsed = parseaddr(str(value))
    return parsed[1] or str(value).strip()


def parse_eml(file_bytes):
    if not isinstance(file_bytes, (bytes, bytearray)):
        raise TypeError("The email file content must be bytes.")

    message = BytesParser(policy=policy.default).parsebytes(file_bytes)
    extracted = {}
    for field in HEADER_FIELDS:
        value = message.get(field)
        extracted[field] = value if value is not None else None

    fallback_headers = _fallback_header_parse(file_bytes)
    for field in HEADER_FIELDS:
        if extracted.get(field) is None and fallback_headers.get(field):
            extracted[field] = fallback_headers.get(field)

    extracted["From"] = _clean_address(extracted.get("From"))
    extracted["To"] = _clean_address(extracted.get("To"))
    extracted["Reply-To"] = _clean_address(extracted.get("Reply-To"))
    extracted["Return-Path"] = _clean_address(extracted.get("Return-Path"))
    extracted["Authentication-Results"] = extracted.get("Authentication-Results") or ""

    text_body, html_body = _extract_text_from_message(message)

    if not text_body.strip() and html_body:
        text_body = html_body

    extracted["body"] = text_body.strip().lstrip("\ufeff")
    extracted["html_body"] = html_body

    url_sources = "\n".join(filter(None, [text_body, html_body]))
    extracted["urls"] = _extract_urls_from_text(url_sources)

    return extracted
