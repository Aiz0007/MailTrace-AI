# ============================================================
# FORENSICS MODULE
# SIH 26106 - Email Threat Intelligence Platform
# ============================================================

from datetime import datetime
import re


# ============================================================
# 1. CREATE BASIC EMAIL METADATA
# ============================================================

def extract_metadata(email_data):
    """
    Extract important metadata from the parsed email.
    """

    metadata = {

        "sender": email_data.get(
            "sender",
            "Unknown"
        ),

        "receiver": email_data.get(
            "receiver",
            "Unknown"
        ),

        "subject": email_data.get(
            "subject",
            "No Subject"
        ),

        "date": email_data.get(
            "date",
            "Unknown"
        )

    }

    return metadata


# ============================================================
# 2. EXTRACT EMAIL ADDRESSES
# ============================================================

def extract_email_addresses(text):
    """
    Find email addresses inside the supplied text.
    """

    if not text:
        return []

    pattern = r'[\w\.-]+@[\w\.-]+\.\w+'

    addresses = re.findall(
        pattern,
        text
    )

    return list(set(addresses))


# ============================================================
# 3. CREATE FORENSIC TIMELINE
# ============================================================

def create_timeline(
    email_data,
    threat_data
):
    """
    Creates a simplified forensic investigation timeline.
    """

    timeline = []

    # --------------------------------------------------------
    # Event 1
    # --------------------------------------------------------

    timeline.append({

        "step": 1,

        "event": "Email received",

        "description":
            "Email was submitted for forensic analysis.",

        "status": "INFO"

    })


    # --------------------------------------------------------
    # Event 2
    # --------------------------------------------------------

    timeline.append({

        "step": 2,

        "event": "Email headers analyzed",

        "description":
            "Sender, receiver, subject and date information were extracted.",

        "status": "INFO"

    })


    # --------------------------------------------------------
    # Event 3
    # --------------------------------------------------------

    timeline.append({

        "step": 3,

        "event": "Email content analyzed",

        "description":
            "Email body and subject were scanned for suspicious indicators.",

        "status": "INFO"

    })


    # --------------------------------------------------------
    # Event 4
    # --------------------------------------------------------

    urls = threat_data.get(
        "urls",
        []
    )

    if urls:

        timeline.append({

            "step": 4,

            "event": "URLs detected",

            "description":
                f"{len(urls)} URL(s) were found in the email.",

            "status": "WARNING"

        })

    else:

        timeline.append({

            "step": 4,

            "event": "URL analysis completed",

            "description":
                "No URLs were detected.",

            "status": "INFO"

        })


    # --------------------------------------------------------
    # Event 5
    # --------------------------------------------------------

    suspicious_urls = threat_data.get(
        "suspicious_urls",
        []
    )

    if suspicious_urls:

        timeline.append({

            "step": 5,

            "event": "Suspicious URL detected",

            "description":
                f"{len(suspicious_urls)} suspicious URL(s) identified.",

            "status": "ALERT"

        })


    # --------------------------------------------------------
    # Event 6
    # --------------------------------------------------------

    indicators = threat_data.get(
        "indicators",
        []
    )

    if indicators:

        timeline.append({

            "step": 6,

            "event": "Threat indicators detected",

            "description":
                f"{len(indicators)} indicator(s) identified.",

            "status": "ALERT"

        })

    else:

        timeline.append({

            "step": 6,

            "event": "Threat indicator scan completed",

            "description":
                "No suspicious indicators were detected.",

            "status": "INFO"

        })


    # --------------------------------------------------------
    # Event 7
    # --------------------------------------------------------

    timeline.append({

        "step": 7,

        "event": "Risk assessment completed",

        "description":
            f"Final verdict: {threat_data.get('verdict', 'Unknown')}",

        "status": "COMPLETE"

    })


    return timeline


# ============================================================
# 4. BUILD INDICATOR REPORT
# ============================================================

def build_indicator_report(threat_data):
    """
    Converts threat indicators into a cleaner forensic report.
    """

    indicators = threat_data.get(
        "indicators",
        []
    )

    report = []

    for indicator in indicators:

        category = indicator.get(
            "category",
            "Unknown"
        )

        name = indicator.get(
            "indicator",
            "Unknown"
        )

        points = indicator.get(
            "points",
            0
        )

        reason = indicator.get(
            "reason",
            "Suspicious indicator detected."
        )

        report.append({

            "category": category,

            "indicator": name,

            "risk_points": points,

            "reason": reason

        })

    return report


# ============================================================
# 5. ANALYZE EMAIL SIZE
# ============================================================

def analyze_email_size(email_data):
    """
    Estimates the size of the email body.
    """

    body = email_data.get(
        "body",
        ""
    )

    if not body:

        return {

            "characters": 0,

            "classification": "EMPTY"

        }


    character_count = len(
        body
    )


    if character_count < 100:

        classification = "SHORT"

    elif character_count < 5000:

        classification = "NORMAL"

    else:

        classification = "LONG"


    return {

        "characters": character_count,

        "classification": classification

    }


# ============================================================
# 6. ATTACHMENT FORENSICS
# ============================================================

def analyze_attachments(email_data):
    """
    Collect attachment information.

    This does NOT execute or open attachments.
    """

    attachments = email_data.get(
        "attachments",
        []
    )

    results = []


    for attachment in attachments:

        filename = str(
            attachment
        )

        extension = ""

        if "." in filename:

            extension = filename.rsplit(
                ".",
                1
            )[1].lower()


        results.append({

            "filename": filename,

            "extension": extension,

            "status": "Attachment detected"

        })


    return results


# ============================================================
# 7. EXTRACT INVESTIGATION INDICATORS
# ============================================================

def extract_indicators(
    email_data,
    threat_data
):
    """
    Creates a list of useful forensic indicators.
    """

    indicators = []


    # --------------------------------------------------------
    # Sender
    # --------------------------------------------------------

    sender = email_data.get(
        "sender"
    )

    if sender:

        indicators.append({

            "type": "EMAIL",

            "value": sender,

            "source": "Sender"

        })


    # --------------------------------------------------------
    # URLs
    # --------------------------------------------------------

    urls = threat_data.get(
        "urls",
        []
    )

    for url in urls:

        indicators.append({

            "type": "URL",

            "value": url,

            "source": "Email Body"

        })


    # --------------------------------------------------------
    # Suspicious URLs
    # --------------------------------------------------------

    suspicious_urls = threat_data.get(
        "suspicious_urls",
        []
    )

    for item in suspicious_urls:

        indicators.append({

            "type": "SUSPICIOUS_URL",

            "value": item.get(
                "url",
                "Unknown"
            ),

            "source": item.get(
                "reason",
                "URL analysis"
            )

        })


    return indicators


# ============================================================
# 8. DETERMINE SEVERITY
# ============================================================

def determine_severity(score):

    if score >= 70:

        return "CRITICAL"

    elif score >= 40:

        return "HIGH"

    elif score >= 20:

        return "MEDIUM"

    elif score > 0:

        return "LOW"

    else:

        return "NONE"


# ============================================================
# 9. CREATE INVESTIGATION SUMMARY
# ============================================================

def create_summary(
    email_data,
    threat_data
):
    """
    Creates a high-level forensic investigation summary.
    """

    score = threat_data.get(
        "score",
        0
    )

    verdict = threat_data.get(
        "verdict",
        "UNKNOWN"
    )

    indicators = threat_data.get(
        "indicators",
        []
    )

    urls = threat_data.get(
        "urls",
        []
    )

    suspicious_urls = threat_data.get(
        "suspicious_urls",
        []
    )


    severity = determine_severity(
        score
    )


    summary = {

        "verdict": verdict,

        "risk_score": score,

        "severity": severity,

        "total_indicators":
            len(indicators),

        "total_urls":
            len(urls),

        "suspicious_urls":
            len(suspicious_urls)

    }


    return summary


# ============================================================
# 10. MAIN FORENSIC ANALYSIS FUNCTION
# ============================================================

def perform_forensic_analysis(
    email_data,
    threat_data
):
    """
    Main function used by app.py.

    Combines all forensic functions into
    one investigation report.
    """

    # --------------------------------------------------------
    # Metadata
    # --------------------------------------------------------

    metadata = extract_metadata(
        email_data
    )


    # --------------------------------------------------------
    # Timeline
    # --------------------------------------------------------

    timeline = create_timeline(
        email_data,
        threat_data
    )


    # --------------------------------------------------------
    # Indicators
    # --------------------------------------------------------

    indicator_report = build_indicator_report(
        threat_data
    )


    # --------------------------------------------------------
    # Email size
    # --------------------------------------------------------

    email_size = analyze_email_size(
        email_data
    )


    # --------------------------------------------------------
    # Attachments
    # --------------------------------------------------------

    attachments = analyze_attachments(
        email_data
    )


    # --------------------------------------------------------
    # Investigation indicators
    # --------------------------------------------------------

    extracted_indicators = extract_indicators(
        email_data,
        threat_data
    )


    # --------------------------------------------------------
    # Summary
    # --------------------------------------------------------

    summary = create_summary(
        email_data,
        threat_data
    )


    # --------------------------------------------------------
    # Final forensic report
    # --------------------------------------------------------

    forensic_report = {

        "metadata": metadata,

        "timeline": timeline,

        "indicator_report": indicator_report,

        "email_size": email_size,

        "attachments": attachments,

        "extracted_indicators":
            extracted_indicators,

        "summary": summary

    }


    return forensic_report