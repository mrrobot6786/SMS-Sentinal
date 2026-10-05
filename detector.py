import re
from urllib.parse import urlparse

URGENT = [
    "urgent", "immediately", "act now", "right now", "final warning",
    "within 24 hours", "today", "as soon as possible", "last chance"
]

CREDENTIALS = [
    "password", "passcode", "otp", "one time password", "verification code",
    "pin", "cvv", "card number", "login", "verify your account", "security code"
]

MONEY = [
    "pay", "payment", "transfer", "send money", "fee", "refund",
    "prize", "cash", "omr", "usd", "money", "unlock", "fine"
]

THREATS = [
    "suspended", "blocked", "closed", "arrest", "police", "legal action",
    "lose access", "account will be deleted", "penalty"
]

IMPERSONATION = [
    "bank", "government", "police", "delivery", "paypal", "microsoft",
    "apple", "instagram", "whatsapp", "school", "admin", "support"
]

def _contains(text, phrases):
    low = text.lower()
    return [p for p in phrases if p in low]

def _urls(text):
    return re.findall(r'https?://[^\s]+|www\.[^\s]+', text, flags=re.I)

def investigate(text):
    low = text.lower()
    findings = []
    categories = []
    signals = []
    score = 0

    def add(title, detail, icon, points, category, signal):
        nonlocal score
        score += points
        findings.append({"title": title, "detail": detail, "icon": icon})
        categories.append(category)
        signals.append(signal)

    urgent = _contains(text, URGENT)
    creds = _contains(text, CREDENTIALS)
    money = _contains(text, MONEY)
    threats = _contains(text, THREATS)
    impersonation = _contains(text, IMPERSONATION)
    urls = _urls(text)

    if urgent:
        add("Urgency / pressure", f"Detected pressure language: {', '.join(urgent[:3])}.",
            "🚨", 18, "social engineering", "urgency")

    if creds:
        add("Sensitive information request",
            f"Credential-related language detected: {', '.join(creds[:4])}.",
            "🔑", 28, "credential theft", "credential request")

    if money:
        add("Financial request",
            f"Money/payment language detected: {', '.join(money[:4])}.",
            "💰", 20, "financial risk", "money request")

    if threats:
        add("Threat / consequence",
            f"Threatening or consequence language detected: {', '.join(threats[:4])}.",
            "⚠️", 16, "social engineering", "threat")

    if impersonation:
        add("Possible impersonation",
            f"Authority/brand terms detected: {', '.join(impersonation[:4])}.",
            "🎭", 8, "impersonation", "authority/brand")

    if urls:
        suspicious_url = False
        details = []
        for raw in urls:
            clean = raw.rstrip(".,!?)]}")
            try:
                u = urlparse(clean if "://" in clean else "http://" + clean)
                host = (u.hostname or "").lower()
                if u.scheme == "http":
                    suspicious_url = True
                    details.append(f"{host}: unencrypted HTTP")
                if "@" in clean:
                    suspicious_url = True
                    details.append(f"{host}: contains @")
                if len(host.split(".")) >= 4:
                    suspicious_url = True
                    details.append(f"{host}: unusually deep subdomain")
                if any(x in host for x in ["login", "verify", "secure", "account", "update"]):
                    details.append(f"{host}: credential-themed domain")
            except Exception:
                suspicious_url = True
                details.append(clean)

        points = 18 if suspicious_url else 8
        add("Link detected",
            "; ".join(details) if details else f"{len(urls)} URL(s) detected.",
            "🔗", points, "link risk", "URL analysis")

    # Extra heuristic: excessive exclamation marks / all caps
    exclam = text.count("!")
    caps_words = re.findall(r'\b[A-Z]{4,}\b', text)
    if exclam >= 3 or len(caps_words) >= 3:
        add("Aggressive formatting",
            "Excessive capitalization or exclamation marks can be used to create pressure.",
            "📣", 6, "social engineering", "aggressive formatting")

    score = min(score, 100)

    if not findings:
        summary = (
            "We found no strong warning signals in the supplied text. "
            "That does not prove the message is safe; it only means this rule set "
            "did not detect obvious indicators."
        )
        recommendation = "Still verify unexpected messages through an official source."
    elif score >= 70:
        summary = (
            "Several independent warning signals overlap. The combination of "
            "pressure, sensitive requests, money-related language, threats, or suspicious "
            "links is strongly associated with social-engineering scams."
        )
        recommendation = "Do not click links or share passwords, OTPs, PINs, or payment details. Verify through the organization's official website/app."
    elif score >= 40:
        summary = (
            "We found multiple warning signals, but the evidence is not strong enough "
            "to call the message fraudulent with confidence."
        )
        recommendation = "Treat the message cautiously and verify the sender independently."
    else:
        summary = (
            "Only a small number of warning signals were found. The message may be legitimate, "
            "but automated analysis cannot establish authenticity."
        )
        recommendation = "If the request is unexpected, verify it through an independent channel."

    return {
        "score": score,
        "findings": findings,
        "summary": summary,
        "recommendation": recommendation,
        "urls": urls,
        "categories": sorted(set(categories)),
        "signals": signals
    }
