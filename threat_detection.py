# ============================================================
# THREAT DETECTION MODULE
# SIH 26106 - Email Threat Intelligence Platform
# ============================================================

import re
from urllib.parse import urlparse


# ============================================================
# 1. SUSPICIOUS WORDS / PHRASES
# ============================================================

URGENT_WORDS = [
    "urgent",
    "immediately",
    "act now",
    "action required",
    "final warning",
    "last warning",
    "important notice",
    "within 24 hours",
    "account suspended",
    "account will be closed"
]


CREDENTIAL_WORDS = [
    "password",
    "username",
    "login",
    "sign in",
    "verify your account",
    "confirm your identity",
    "security code",
    "otp",
    "one time password"
]


FINANCIAL_WORDS = [
    "bank account",
    "credit card",
    "debit card",
    "payment",
    "transaction",
    "refund",
    "invoice",
    "upi",
    "money",
    "payment failed"
]


SUSPICIOUS_ACTIONS = [
    "click here",
    "click the link",
    "open the attachment",
    "download the file",
    "verify now",
    "confirm now",
    "update your information"
]


# ============================================================
# 2. SUSPICIOUS FILE EXTENSIONS
# ============================================================

SUSPICIOUS_EXTENSIONS = [
    ".exe",
    ".scr",
    ".bat",
    ".cmd",
    ".js",
    ".vbs",
    ".ps1",
    ".msi"
]


# ============================================================
# 3. EXTRACT URLs FROM EMAIL
# ============================================================

def extract_urls(text):

    if not text:
        return []

    pattern = r'https?://[^\s<>"\']+'

    urls = re.findall(pattern, text)

    return urls


# ============================================================
# 4. CHECK URLS
# ============================================================

def analyze_urls(text):

    urls = extract_urls(text)

    suspicious_urls = []

    for url in urls:

        try:

            parsed = urlparse(url)

            domain = parsed.netloc.lower()

            # Remove port number
            domain = domain.split(":")[0]

            # Check for IP address instead of domain
            ip_pattern = r"^\d{1,3}(\.\d{1,3}){3}$"

            if re.match(ip_pattern, domain):

                suspicious_urls.append({
                    "url": url,
                    "reason": "URL uses an IP address instead of a domain"
                })

            # Check for URL shortening services
            shortened_domains = [
                "bit.ly",
                "tinyurl.com",
                "t.co",
                "is.gd",
                "cutt.ly"
            ]

            if domain in shortened_domains:

                suspicious_urls.append({
                    "url": url,
                    "reason": "URL uses a shortening service"
                })

            # Check for @ symbol
            if "@" in url:

                suspicious_urls.append({
                    "url": url,
                    "reason": "URL contains @ symbol"
                })

            # Check excessive subdomains
            if domain.count(".") >= 3:

                suspicious_urls.append({
                    "url": url,
                    "reason": "URL contains multiple subdomains"
                })

        except Exception:

            suspicious_urls.append({
                "url": url,
                "reason": "URL could not be parsed"
            })

    return urls, suspicious_urls


# ============================================================
# 5. CHECK SUSPICIOUS WORDS
# ============================================================

def find_suspicious_words(text):

    if not text:
        return []

    text = text.lower()

    findings = []

    # -------------------------------
    # Urgency
    # -------------------------------

    for word in URGENT_WORDS:

        if word in text:

            findings.append({
                "category": "Urgency",
                "indicator": word,
                "points": 5
            })


    # -------------------------------
    # Credential harvesting
    # -------------------------------

    for word in CREDENTIAL_WORDS:

        if word in text:

            findings.append({
                "category": "Credential Request",
                "indicator": word,
                "points": 8
            })


    # -------------------------------
    # Financial content
    # -------------------------------

    for word in FINANCIAL_WORDS:

        if word in text:

            findings.append({
                "category": "Financial Content",
                "indicator": word,
                "points": 5
            })


    # -------------------------------
    # Suspicious actions
    # -------------------------------

    for word in SUSPICIOUS_ACTIONS:

        if word in text:

            findings.append({
                "category": "Suspicious Action",
                "indicator": word,
                "points": 7
            })


    return findings


# ============================================================
# 6. CHECK ATTACHMENTS
# ============================================================

def analyze_attachments(attachments):

    findings = []

    if not attachments:
        return findings

    for attachment in attachments:

        # Convert to string so the function can
        # work with simple filenames.
        filename = str(attachment).lower()

        for extension in SUSPICIOUS_EXTENSIONS:

            if filename.endswith(extension):

                findings.append({
                    "category": "Suspicious Attachment",
                    "indicator": filename,
                    "reason": f"Potentially dangerous file type: {extension}",
                    "points": 15
                })

    return findings


# ============================================================
# 7. CHECK SENDER
# ============================================================

def analyze_sender(sender):

    findings = []

    if not sender:

        return findings

    sender = sender.lower()

    # Extract email address
    match = re.search(
        r'[\w\.-]+@[\w\.-]+\.\w+',
        sender
    )

    if not match:
        return findings

    email_address = match.group()

    domain = email_address.split("@")[1]

    # Free email providers
    free_email_domains = [
        "gmail.com",
        "yahoo.com",
        "outlook.com",
        "hotmail.com",
        "proton.me"
    ]

    if domain in free_email_domains:

        findings.append({
            "category": "Sender",
            "indicator": f"Sender uses free email provider: {domain}",
            "points": 2
        })

    return findings


# ============================================================
# 8. CHECK FOR EXCESSIVE CAPITALIZATION
# ============================================================

def analyze_capitalization(text):

    findings = []

    if not text:
        return findings

    letters = [
        char for char in text
        if char.isalpha()
    ]

    if len(letters) < 20:
        return findings

    uppercase = [
        char for char in letters
        if char.isupper()
    ]

    uppercase_ratio = len(uppercase) / len(letters)

    if uppercase_ratio > 0.50:

        findings.append({
            "category": "Writing Pattern",
            "indicator": "Excessive use of uppercase letters",
            "points": 5
        })

    return findings


# ============================================================
# 9. CALCULATE VERDICT
# ============================================================

def calculate_verdict(score):

    if score >= 70:

        return "MALICIOUS"

    elif score >= 40:

        return "SUSPICIOUS"

    elif score >= 20:

        return "LOW RISK"

    else:

        return "SAFE"


# ============================================================
# 10. MAIN THREAT ANALYSIS FUNCTION
# ============================================================

def analyze_email(email_data):

    """
    Main function used by app.py.

    Input:
        email_data dictionary produced by email_parser.py

    Output:
        dictionary containing:
        - risk score
        - verdict
        - indicators
        - URLs
        - suspicious URLs
        - category scores
    """

    score = 0

    all_findings = []


    # ========================================================
    # GET EMAIL INFORMATION
    # ========================================================

    sender = email_data.get("sender", "")
    subject = email_data.get("subject", "")
    body = email_data.get("body", "")

    attachments = email_data.get(
        "attachments",
        []
    )


    # Combine subject and body
    full_text = (
        str(subject)
        + " "
        + str(body)
    )


    # ========================================================
    # ANALYZE SUSPICIOUS WORDS
    # ========================================================

    word_findings = find_suspicious_words(
        full_text
    )

    all_findings.extend(
        word_findings
    )


    # ========================================================
    # ANALYZE URLs
    # ========================================================

    urls, suspicious_urls = analyze_urls(
        full_text
    )

    for finding in suspicious_urls:

        all_findings.append({
            "category": "Suspicious URL",
            "indicator": finding["url"],
            "reason": finding["reason"],
            "points": 15
        })


    # ========================================================
    # ANALYZE ATTACHMENTS
    # ========================================================

    attachment_findings = analyze_attachments(
        attachments
    )

    all_findings.extend(
        attachment_findings
    )


    # ========================================================
    # ANALYZE SENDER
    # ========================================================

    sender_findings = analyze_sender(
        sender
    )

    all_findings.extend(
        sender_findings
    )


    # ========================================================
    # ANALYZE WRITING STYLE
    # ========================================================

    capitalization_findings = analyze_capitalization(
        full_text
    )

    all_findings.extend(
        capitalization_findings
    )


    # ========================================================
    # CALCULATE TOTAL SCORE
    # ========================================================

    for finding in all_findings:

        score += finding.get(
            "points",
            0
        )


    # ========================================================
    # LIMIT SCORE TO 100
    # ========================================================

    if score > 100:

        score = 100


    # ========================================================
    # GET FINAL VERDICT
    # ========================================================

    verdict = calculate_verdict(
        score
    )


    # ========================================================
    # CATEGORY SCORES
    # ========================================================

    category_scores = {}

    for finding in all_findings:

        category = finding.get(
            "category",
            "Other"
        )

        points = finding.get(
            "points",
            0
        )

        if category not in category_scores:

            category_scores[category] = 0

        category_scores[category] += points


    # ========================================================
    # RETURN EVERYTHING
    # ========================================================

    return {

        "score": score,

        "verdict": verdict,

        "indicators": all_findings,

        "urls": urls,

        "suspicious_urls": suspicious_urls,

        "category_scores": category_scores

    }