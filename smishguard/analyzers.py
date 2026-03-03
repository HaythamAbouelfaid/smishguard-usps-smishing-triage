from __future__ import annotations

import re
from dataclasses import dataclass, asdict
from typing import Any, Dict, List, Optional, Tuple

import phonenumbers
import tldextract


URL_RE = re.compile(
    r"(?P<url>(?:https?://)?(?:www\.)?[a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,}(?:/[^\s]*)?)",
    re.IGNORECASE,
)

ATTACH_RE = re.compile(r"(?P<fn>[A-Za-z0-9_\-]+\.(?:pdf|docx?|xlsx?|zip|rar|7z|exe|js))", re.IGNORECASE)


@dataclass
class TriageResult:
    from_number: Optional[str]
    message: str
    attachment: Optional[str]
    urls: List[str]
    domains: List[str]
    extracted_phones: List[str]
    score: int
    risk: str
    reasons: List[str]

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def normalize_phone(raw: str) -> Optional[str]:
    raw = raw.strip()
    if not raw:
        return None
    try:
        num = phonenumbers.parse(raw, None)
        if phonenumbers.is_possible_number(num) and phonenumbers.is_valid_number(num):
            return phonenumbers.format_number(num, phonenumbers.PhoneNumberFormat.E164)
    except Exception:
        return None
    # If invalid, still return a cleaned version for IOC purposes
    cleaned = re.sub(r"[^\d\+]", "", raw)
    return cleaned if cleaned else None


def extract_phones(text: str) -> List[str]:
    phones = set()
    for match in re.findall(r"(\+?\d[\d\-\(\) ]{7,}\d)", text):
        p = normalize_phone(match)
        if p:
            phones.add(p)
    return sorted(phones)


def extract_urls(text: str) -> List[str]:
    urls = []
    for m in URL_RE.finditer(text):
        u = m.group("url")
        # Skip obvious false positives like "1 of 1" etc.
        if len(u) < 8:
            continue
        urls.append(u)
    # De-duplicate preserving order
    seen = set()
    out = []
    for u in urls:
        key = u.lower()
        if key not in seen:
            seen.add(key)
            out.append(u)
    return out


def domain_of(url: str) -> str:
    # Ensure tldextract treats it as URL
    if not url.lower().startswith(("http://", "https://")):
        url = "http://" + url
    ext = tldextract.extract(url)
    if not ext.suffix:
        return ""
    return ".".join([p for p in [ext.domain, ext.suffix] if p])


def looks_like_brand_impersonation(text: str, brand: str) -> bool:
    t = text.lower()
    b = brand.lower()
    # USPS variants commonly used
    if b == "usps":
        return any(k in t for k in ["usps", "u.s. postal", "united states postal", "postal service"])
    return b in t


def is_urgent_delivery_lure(text: str) -> bool:
    t = text.lower()
    keywords = [
        "urgent notice",
        "unable to deliver",
        "delivery failed",
        "incomplete",
        "damaged",
        "shipping label",
        "reschedule",
        "redelivery",
        "click here",
        "check attachment",
    ]
    hits = sum(1 for k in keywords if k in t)
    return hits >= 2


def is_suspicious_attachment(filename: Optional[str]) -> bool:
    if not filename:
        return False
    fn = filename.lower()
    # Any unexpected attachment in SMS is suspicious; PDFs are common lures
    return bool(re.search(r"\.(pdf|docx?|xlsx?|zip|rar|7z)$", fn))


def is_domain_lookalike(domain: str, allowed: List[str]) -> bool:
    d = domain.lower()
    if d in allowed:
        return False
    # naive lookalike: contains allowed domain as substring but isn't exact
    for a in allowed:
        a = a.lower()
        if a in d and d != a:
            return True
    # common tricks: extra hyphen/word around brand
    if "usps" in d and d != "usps.com":
        return True
    return False


def score_message(
    message: str,
    urls: List[str],
    domains: List[str],
    attachment: Optional[str],
    from_number: Optional[str],
) -> Tuple[int, List[str]]:
    score = 0
    reasons: List[str] = []

    if from_number:
        score += 5
        reasons.append("Sender phone number present (SMS phishing commonly uses random numbers).")

    if looks_like_brand_impersonation(message, "USPS"):
        score += 25
        reasons.append("Brand impersonation indicators: USPS / postal service.")

    if is_urgent_delivery_lure(message):
        score += 25
        reasons.append("Urgent delivery/language lure detected (e.g., unable to deliver + call-to-action).")

    if urls:
        score += 20
        reasons.append("Contains URL(s) in message (common credential/payment harvesting pattern).")

    if attachment:
        score += 15
        reasons.append("Contains attachment/filename reference (high risk in SMS).")

    if is_suspicious_attachment(attachment):
        score += 10
        reasons.append("Attachment type commonly used in lures (PDF/Office/archives).")

    # Domain checks
    allowed = ["usps.com"]
    for d in domains:
        if d.lower() not in allowed:
            score += 10
            reasons.append(f"Domain not in allowlist: {d}.")
        if is_domain_lookalike(d, allowed):
            score += 15
            reasons.append(f"Possible lookalike domain pattern: {d}.")

    # Cap to 100
    score = min(score, 100)
    return score, reasons


def risk_bucket(score: int) -> str:
    if score >= 70:
        return "HIGH"
    if score >= 40:
        return "MEDIUM"
    return "LOW"


def triage_sms(message: str, from_number: Optional[str] = None, attachment: Optional[str] = None) -> TriageResult:
    urls = extract_urls(message)
    domains = sorted({domain_of(u) for u in urls if domain_of(u)})
    phones = extract_phones(message)
    if from_number:
        n = normalize_phone(from_number)
        if n and n not in phones:
            phones = [n] + phones

    score, reasons = score_message(message, urls, domains, attachment, from_number)
    return TriageResult(
        from_number=normalize_phone(from_number) if from_number else None,
        message=message,
        attachment=attachment,
        urls=urls,
        domains=domains,
        extracted_phones=phones,
        score=score,
        risk=risk_bucket(score),
        reasons=reasons,
    )
