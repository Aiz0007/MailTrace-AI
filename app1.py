# ============================================================
# MAILTRACE AI
# SIH 26106
# AI-POWERED EMAIL THREAT DETECTION & FORENSIC INTELLIGENCE
# ============================================================

import streamlit as st

from email_parser import parse_email
from threat_detection import analyze_email
from forensics import perform_forensic_analysis
from ip_intelligence import get_ip_geolocation


# ============================================================
# PAGE CONFIG
# ============================================================

st.set_page_config(
    page_title="MailTrace AI",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)


# ============================================================
# CUSTOM CSS
# ============================================================

st.markdown(
    """
<style>

/* =========================================================
   GLOBAL
   ========================================================= */

.stApp {
    background:
        radial-gradient(
            circle at 5% 5%,
            rgba(99, 102, 241, 0.20),
            transparent 25%
        ),
        radial-gradient(
            circle at 95% 10%,
            rgba(6, 182, 212, 0.18),
            transparent 25%
        ),
        radial-gradient(
            circle at 50% 100%,
            rgba(168, 85, 247, 0.15),
            transparent 30%
        ),
        #070b17;

    color: #f8fafc;
}

.block-container {
    padding-top: 2rem;
    padding-bottom: 3rem;
    max-width: 1450px;
}


/* =========================================================
   SIDEBAR
   ========================================================= */

section[data-testid="stSidebar"] {
    background:
        linear-gradient(
            180deg,
            #080c1a 0%,
            #0e1326 50%,
            #080b16 100%
        );

    border-right: 1px solid rgba(99, 102, 241, 0.25);
}


/* =========================================================
   BRAND
   ========================================================= */

.brand {
    font-size: 3.5rem;
    font-weight: 900;
    letter-spacing: -2px;

    background:
        linear-gradient(
            90deg,
            #22d3ee,
            #6366f1,
            #a855f7,
            #ec4899
        );

    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
}

.tagline {
    color: #94a3b8;
    font-size: 1.05rem;
    margin-top: -5px;
    margin-bottom: 25px;
}


/* =========================================================
   HERO
   ========================================================= */

.hero {
    padding: 30px;

    border-radius: 24px;

    background:
        linear-gradient(
            135deg,
            rgba(30, 41, 90, 0.92),
            rgba(15, 23, 42, 0.96)
        );

    border: 1px solid rgba(99, 102, 241, 0.35);

    box-shadow:
        0 20px 60px rgba(0,0,0,0.35),
        inset 0 1px 0 rgba(255,255,255,0.05);

    margin-bottom: 25px;
}

.hero-title {
    font-size: 2rem;
    font-weight: 900;
    color: #f8fafc;
    margin-bottom: 8px;
}

.hero-text {
    color: #cbd5e1;
    font-size: 1rem;
    line-height: 1.7;
}


/* =========================================================
   SECTION TITLES
   ========================================================= */

.section-title {
    font-size: 1.55rem;
    font-weight: 850;
    color: #f8fafc;
    margin-top: 30px;
    margin-bottom: 7px;
}

.section-subtitle {
    color: #94a3b8;
    margin-bottom: 18px;
}


/* =========================================================
   METRIC CARDS
   ========================================================= */

.metric-card {
    padding: 22px;
    border-radius: 20px;
    min-height: 125px;

    border: 1px solid rgba(255,255,255,0.08);

    box-shadow:
        0 12px 35px rgba(0,0,0,0.25);
}

.metric-blue {
    background:
        linear-gradient(
            135deg,
            rgba(14,165,233,0.22),
            rgba(15,23,42,0.90)
        );

    border-color: rgba(14,165,233,0.35);
}

.metric-purple {
    background:
        linear-gradient(
            135deg,
            rgba(168,85,247,0.23),
            rgba(15,23,42,0.90)
        );

    border-color: rgba(168,85,247,0.35);
}

.metric-green {
    background:
        linear-gradient(
            135deg,
            rgba(34,197,94,0.20),
            rgba(15,23,42,0.90)
        );

    border-color: rgba(34,197,94,0.35);
}

.metric-red {
    background:
        linear-gradient(
            135deg,
            rgba(239,68,68,0.22),
            rgba(15,23,42,0.90)
        );

    border-color: rgba(239,68,68,0.4);
}

.metric-label {
    color: #94a3b8;
    font-size: 0.78rem;
    text-transform: uppercase;
    letter-spacing: 1px;
}

.metric-value {
    font-size: 2rem;
    font-weight: 900;
    margin-top: 8px;
    color: #f8fafc;
}


/* =========================================================
   INFORMATION CARDS
   ========================================================= */

.info-card {
    background: rgba(15,23,42,0.90);

    border: 1px solid rgba(148,163,184,0.14);

    border-radius: 18px;

    padding: 20px;

    margin-bottom: 15px;

    box-shadow:
        0 10px 30px rgba(0,0,0,0.18);
}

.info-label {
    color: #64748b;
    font-size: 0.75rem;
    text-transform: uppercase;
    letter-spacing: 1px;
}

.info-value {
    color: #e2e8f0;
    font-size: 1rem;
    word-break: break-word;
}


/* =========================================================
   THREAT CARDS
   ========================================================= */

.threat-danger {
    background:
        linear-gradient(
            135deg,
            rgba(127,29,29,0.75),
            rgba(30,10,20,0.90)
        );

    border: 1px solid rgba(248,113,113,0.5);

    border-radius: 22px;

    padding: 25px;

    box-shadow:
        0 0 40px rgba(239,68,68,0.12);
}

.threat-warning {
    background:
        linear-gradient(
            135deg,
            rgba(120,53,15,0.75),
            rgba(30,20,10,0.90)
        );

    border: 1px solid rgba(251,191,36,0.5);

    border-radius: 22px;

    padding: 25px;
}

.threat-safe {
    background:
        linear-gradient(
            135deg,
            rgba(20,83,45,0.75),
            rgba(8,30,20,0.90)
        );

    border: 1px solid rgba(74,222,128,0.5);

    border-radius: 22px;

    padding: 25px;
}

.threat-score {
    font-size: 4rem;
    font-weight: 900;
    line-height: 1;
}


/* =========================================================
   EVIDENCE
   ========================================================= */

.evidence-card {
    background: rgba(15,23,42,0.92);

    border-radius: 16px;

    padding: 17px;

    border-left: 4px solid #f59e0b;

    margin-bottom: 12px;
}

.evidence-name {
    font-weight: 800;
    color: #f8fafc;
}

.evidence-reason {
    color: #94a3b8;
    font-size: 0.9rem;
    margin-top: 6px;
}

.evidence-points {
    color: #fbbf24;
    font-weight: 900;
    float: right;
}


/* =========================================================
   IP CARDS
   ========================================================= */

.ip-card {
    background:
        linear-gradient(
            135deg,
            rgba(15,23,42,0.98),
            rgba(22,32,65,0.92)
        );

    border: 1px solid rgba(34,211,238,0.22);

    border-radius: 20px;

    padding: 22px;

    margin-bottom: 10px;
}

.ip-address {
    font-size: 1.5rem;
    font-weight: 900;
    color: #67e8f9;
}

.ip-badge {
    display: inline-block;

    padding: 5px 12px;

    border-radius: 999px;

    font-size: 0.72rem;

    font-weight: 800;

    background: rgba(34,211,238,0.12);

    color: #67e8f9;

    border: 1px solid rgba(34,211,238,0.25);
}


/* =========================================================
   TIMELINE
   ========================================================= */

.timeline-card {
    background: rgba(15,23,42,0.88);

    border-radius: 16px;

    padding: 18px 22px;

    margin-bottom: 10px;

    border-left: 4px solid #6366f1;
}

.timeline-step {
    color: #a5b4fc;

    font-weight: 800;

    font-size: 0.75rem;

    text-transform: uppercase;
}

.timeline-event {
    color: #f8fafc;

    font-size: 1.05rem;

    font-weight: 800;

    margin: 4px 0;
}

.timeline-description {
    color: #94a3b8;
}


/* =========================================================
   UPLOADER
   ========================================================= */

[data-testid="stFileUploader"] {
    background: rgba(15,23,42,0.70);

    border: 2px dashed rgba(99,102,241,0.50);

    border-radius: 20px;

    padding: 10px;
}


/* =========================================================
   BUTTON
   ========================================================= */

.stButton > button {
    border-radius: 14px;

    font-weight: 900;

    min-height: 54px;

    border: 1px solid rgba(129,140,248,0.5);

    background:
        linear-gradient(
            90deg,
            #4f46e5,
            #7c3aed,
            #9333ea
        );

    color: white;

    box-shadow:
        0 10px 30px rgba(99,102,241,0.25);
}

.stButton > button:hover {
    border-color: #c4b5fd;
}


/* =========================================================
   FOOTER
   ========================================================= */

.footer {
    text-align: center;

    color: #64748b;

    padding: 35px 0 10px 0;

    font-size: 0.85rem;
}

</style>
""",
    unsafe_allow_html=True
)


# ============================================================
# HELPER FUNCTIONS
# ============================================================

def safe_value(value, default="Unknown"):
    """
    Prevent None / empty values from making
    the dashboard look broken.
    """

    if value is None:
        return default

    value = str(value).strip()

    if not value:
        return default

    return value


def show_metric_card(label, value, card_class):
    """
    IMPORTANT:
    Custom HTML is rendered using st.html()
    instead of st.markdown().
    """

    st.html(
        f"""
        <div class="metric-card {card_class}">

            <div class="metric-label">
                {label}
            </div>

            <div class="metric-value">
                {value}
            </div>

        </div>
        """
    )


def show_section_title(title, subtitle=None):

    st.html(
        f"""
        <div class="section-title">
            {title}
        </div>
        """
    )

    if subtitle:

        st.html(
            f"""
            <div class="section-subtitle">
                {subtitle}
            </div>
            """
        )


def get_threat_style(verdict):

    verdict_upper = str(verdict).upper()

    if "MALICIOUS" in verdict_upper:

        return "threat-danger", "🔴"

    elif "SUSPICIOUS" in verdict_upper:

        return "threat-warning", "🟠"

    elif "LOW RISK" in verdict_upper:

        return "threat-warning", "🟡"

    else:

        return "threat-safe", "🟢"


# ============================================================
# SIDEBAR
# ============================================================

with st.sidebar:

    st.html(
        """
        <div style="
            text-align:center;
            padding:15px 0 25px 0;
        ">

            <div style="
                font-size:3rem;
            ">
                🛡️
            </div>

            <div style="
                font-size:1.7rem;
                font-weight:900;
                color:#67e8f9;
            ">
                MailTrace AI
            </div>

            <div style="
                color:#94a3b8;
                font-size:0.85rem;
            ">
                Email Forensics Platform
            </div>

        </div>
        """
    )

    st.markdown("---")

    st.markdown("### 🔍 Investigation")

    st.write(
        "Upload an `.eml` file to begin a complete "
        "email threat and forensic analysis."
    )

    st.markdown("---")

    st.markdown("### 🧩 Analysis Pipeline")

    st.markdown(
        """
        **01** 📧 Email Parsing

        **02** 🛡️ Threat Detection

        **03** 🌐 IP Intelligence

        **04** 🔎 Forensic Correlation

        **05** 📊 Investigation Report
        """
    )

    st.markdown("---")

    st.info(
        "MailTrace AI • SIH 26106 Prototype"
    )


# ============================================================
# MAIN HEADER
# ============================================================

st.html(
    """
    <div class="brand">
        MailTrace AI
    </div>

    <div class="tagline">
        🛡️ AI-Powered Email Threat Detection
        &nbsp;•&nbsp;
        🌐 Infrastructure Intelligence
        &nbsp;•&nbsp;
        🕵️ Digital Forensics
    </div>
    """
)


# ============================================================
# HERO
# ============================================================

st.html(
    """
    <div class="hero">

        <div class="hero-title">
            🕵️ Turn an Email Into a Forensic Investigation
        </div>

        <div class="hero-text">
            MailTrace AI analyzes email metadata,
            routing headers, URLs, attachments,
            authentication signals and observable
            network infrastructure to build an
            evidence-backed threat assessment.
        </div>

    </div>
    """
)


# ============================================================
# UPLOAD SECTION
# ============================================================

show_section_title(
    "📧 Submit Email Evidence",
    "Upload the original .eml message whenever possible."
)


uploaded_file = st.file_uploader(
    "Choose an email file",
    type=["eml"],
    label_visibility="collapsed"
)


# ============================================================
# WAITING SCREEN
# ============================================================

if uploaded_file is None:

    st.html(
        """
        <div class="info-card"
             style="text-align:center;">

            <div style="
                font-size:3.5rem;
                margin-bottom:10px;
            ">
                📨
            </div>

            <div style="
                font-size:1.3rem;
                font-weight:900;
                color:#f8fafc;
            ">
                Awaiting Evidence
            </div>

            <div style="
                color:#94a3b8;
                margin-top:8px;
            ">
                Upload an .eml file above to begin
                the MailTrace investigation.
            </div>

        </div>
        """
    )

    st.html(
        """
        <div class="footer">
            🛡️ MailTrace AI • SIH 26106
        </div>
        """
    )

    st.stop()


# ============================================================
# FILE INFORMATION
# ============================================================

file_size = uploaded_file.size / 1024


st.html(
    f"""
    <div class="info-card">

        <div class="info-label">
            Evidence File
        </div>

        <div class="info-value">
            📄 {safe_value(uploaded_file.name)}
        </div>

        <div style="
            color:#64748b;
            margin-top:8px;
        ">
            Size: {file_size:.2f} KB
        </div>

    </div>
    """
)


# ============================================================
# ANALYZE BUTTON
# ============================================================

if st.button(
    "🚀 START MAILTRACE INVESTIGATION",
    use_container_width=True
):

    # ========================================================
    # STEP 1 — PARSE EMAIL
    # ========================================================

    with st.spinner(
        "📧 Parsing email evidence..."
    ):

        try:

            email_data = parse_email(
                uploaded_file
            )

        except Exception as error:

            st.error(
                f"❌ Email parsing failed: {error}"
            )

            st.stop()


    # ========================================================
    # STEP 2 — THREAT DETECTION
    # ========================================================

    with st.spinner(
        "🛡️ Running threat detection engine..."
    ):

        try:

            threat_data = analyze_email(
                email_data
            )

        except Exception as error:

            st.error(
                f"❌ Threat analysis failed: {error}"
            )

            st.stop()


    # ========================================================
    # STEP 3 — IP INTELLIGENCE
    # ========================================================

    with st.spinner(
        "🌐 Investigating observable infrastructure..."
    ):

        try:

            received_ips = email_data.get(
                "received_ips",
                []
            )

            public_ips = email_data.get(
                "public_ips",
                []
            )

            private_ips = email_data.get(
                "private_ips",
                []
            )

            other_ips = email_data.get(
                "other_ips",
                []
            )


            ip_data = {

                "ips_found": received_ips,

                "total_ips": len(
                    received_ips
                ),

                "summary": {

                    "public": len(
                        public_ips
                    ),

                    "private": len(
                        private_ips
                    ),

                    "other": len(
                        other_ips
                    )

                },

                "results": []

            }


            for ip in received_ips:

                if ip in public_ips:

                    classification = "Public"

                    is_public = True

                    try:

                        geolocation = (
                            get_ip_geolocation(ip)
                        )

                    except Exception as geo_error:

                        geolocation = {

                            "success": False,

                            "message":
                                "Geolocation lookup failed: "
                                f"{geo_error}"

                        }


                elif ip in private_ips:

                    classification = "Private"

                    is_public = False

                    geolocation = {

                        "success": False,

                        "message":
                            "Private IP address. "
                            "Public geolocation is not applicable."

                    }


                else:

                    classification = "Other"

                    is_public = False

                    geolocation = {

                        "success": False,

                        "message":
                            "Reserved or non-public IP address."

                    }


                ip_data["results"].append(

                    {
                        "ip": ip,

                        "classification":
                            classification,

                        "is_public":
                            is_public,

                        "geolocation":
                            geolocation
                    }

                )


        except Exception as error:

            st.warning(
                f"⚠️ IP intelligence could not be completed: "
                f"{error}"
            )

            ip_data = {

                "ips_found": [],

                "total_ips": 0,

                "summary": {},

                "results": []

            }


    # ========================================================
    # STEP 4 — FORENSIC ANALYSIS
    # ========================================================

    with st.spinner(
        "🔎 Building forensic report..."
    ):

        try:

            forensic_data = perform_forensic_analysis(
                email_data,
                threat_data
            )

        except Exception as error:

            st.error(
                f"❌ Forensic analysis failed: {error}"
            )

            st.stop()


    # ========================================================
    # COMPLETE
    # ========================================================

    st.success(
        "✅ MailTrace investigation completed!"
    )


    # ========================================================
    # MAIN DATA
    # ========================================================

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


    # ========================================================
    # THREAT ASSESSMENT
    # ========================================================

    show_section_title(
        "🚨 Threat Assessment",
        "MailTrace AI's automated risk assessment."
    )


    threat_class, threat_icon = get_threat_style(
        verdict
    )


    st.html(
        f"""
        <div class="{threat_class}">

            <div style="
                display:flex;
                justify-content:space-between;
                align-items:center;
                flex-wrap:wrap;
                gap:25px;
            ">

                <div>

                    <div style="
                        color:#94a3b8;
                        text-transform:uppercase;
                        letter-spacing:2px;
                        font-size:0.8rem;
                    ">
                        Current Verdict
                    </div>

                    <div style="
                        font-size:2.2rem;
                        font-weight:900;
                        margin-top:5px;
                    ">
                        {threat_icon}
                        {safe_value(verdict)}
                    </div>

                    <div style="
                        color:#cbd5e1;
                        margin-top:8px;
                    ">
                        Evidence-backed automated assessment
                    </div>

                </div>


                <div style="
                    text-align:center;
                    min-width:160px;
                ">

                    <div class="threat-score">
                        {score}
                    </div>

                    <div style="
                        color:#94a3b8;
                        font-size:0.8rem;
                        letter-spacing:1px;
                    ">
                        RISK SCORE / 100
                    </div>

                </div>

            </div>

        </div>
        """
    )


    st.write("")


    # ========================================================
    # TOP METRICS
    # ========================================================

    public_count = len(
        email_data.get(
            "public_ips",
            []
        )
    )

    attachment_count = len(
        email_data.get(
            "attachments",
            []
        )
    )


    col1, col2, col3, col4 = st.columns(4)


    with col1:

        show_metric_card(
            "Risk Score",
            f"{score}/100",
            "metric-red"
        )


    with col2:

        show_metric_card(
            "Threat Indicators",
            len(indicators),
            "metric-purple"
        )


    with col3:

        show_metric_card(
            "Public IPs",
            public_count,
            "metric-blue"
        )


    with col4:

        show_metric_card(
            "Attachments",
            attachment_count,
            "metric-green"
        )


    # ========================================================
    # EMAIL INTELLIGENCE
    # ========================================================

    show_section_title(
        "📧 Email Intelligence",
        "Identity and metadata extracted from the message."
    )


    metadata = forensic_data.get(
        "metadata",
        {}
    )


    sender = safe_value(
        metadata.get(
            "sender",
            email_data.get(
                "sender",
                ""
            )
        )
    )

    receiver = safe_value(
        metadata.get(
            "receiver",
            email_data.get(
                "receiver",
                ""
            )
        )
    )

    subject = safe_value(
        metadata.get(
            "subject",
            email_data.get(
                "subject",
                ""
            )
        )
    )

    date = safe_value(
        metadata.get(
            "date",
            email_data.get(
                "date",
                ""
            )
        )
    )


    col1, col2 = st.columns(2)


    with col1:

        st.html(
            f"""
            <div class="info-card">

                <div class="info-label">
                    Sender
                </div>

                <div class="info-value">
                    📤 {sender}
                </div>

                <br>

                <div class="info-label">
                    Receiver
                </div>

                <div class="info-value">
                    📥 {receiver}
                </div>

            </div>
            """
        )


    with col2:

        st.html(
            f"""
            <div class="info-card">

                <div class="info-label">
                    Subject
                </div>

                <div class="info-value">
                    📨 {subject}
                </div>

                <br>

                <div class="info-label">
                    Date
                </div>

                <div class="info-value">
                    🕒 {date}
                </div>

            </div>
            """
        )


    # ========================================================
    # THREAT INDICATORS
    # ========================================================

    show_section_title(
        "🧠 Why Was This Email Flagged?",
        "Explainable evidence behind the risk score."
    )


    if not indicators:

        st.html(
            """
            <div class="threat-safe">
                🟢 No suspicious threat indicators
                were returned by the detection engine.
            </div>
            """
        )

    else:

        for indicator in indicators:

            category = safe_value(
                indicator.get(
                    "category",
                    "Unknown"
                )
            )

            name = safe_value(
                indicator.get(
                    "indicator",
                    "Unknown"
                )
            )

            points = indicator.get(
                "points",
                0
            )

            reason = safe_value(
                indicator.get(
                    "reason",
                    "No explanation available."
                )
            )


            st.html(
                f"""
                <div class="evidence-card">

                    <span class="evidence-points">
                        +{points}
                    </span>

                    <div class="evidence-name">
                        ⚠️ {category} — {name}
                    </div>

                    <div class="evidence-reason">
                        {reason}
                    </div>

                </div>
                """
            )


    # ========================================================
    # URL INTELLIGENCE
    # ========================================================

    show_section_title(
        "🔗 URL Intelligence",
        "Links discovered inside the email."
    )


    col1, col2 = st.columns(2)


    with col1:

        show_metric_card(
            "URLs Detected",
            len(urls),
            "metric-blue"
        )


    with col2:

        show_metric_card(
            "Suspicious URLs",
            len(suspicious_urls),
            "metric-red"
        )


    st.write("")


    if not urls:

        st.info(
            "No URLs were detected."
        )

    else:

        for url in urls:

            is_suspicious = False

            suspicious_reason = ""


            for item in suspicious_urls:

                if isinstance(item, dict):

                    if item.get(
                        "url",
                        ""
                    ) == url:

                        is_suspicious = True

                        suspicious_reason = item.get(
                            "reason",
                            "Suspicious URL"
                        )

                        break

                elif str(item) == str(url):

                    is_suspicious = True

                    suspicious_reason = (
                        "Flagged by threat detection"
                    )

                    break


            if is_suspicious:

                st.html(
                    f"""
                    <div class="evidence-card"
                         style="
                            border-left-color:#ef4444;
                         ">

                        <div class="evidence-name">
                            🔴 Suspicious URL
                        </div>

                        <div style="
                            color:#fca5a5;
                            word-break:break-all;
                            margin-top:8px;
                        ">
                            {safe_value(url)}
                        </div>

                        <div class="evidence-reason">
                            {safe_value(suspicious_reason)}
                        </div>

                    </div>
                    """
                )

            else:

                st.html(
                    f"""
                    <div class="info-card">

                        <div style="
                            color:#67e8f9;
                            word-break:break-all;
                        ">
                            🔗 {safe_value(url)}
                        </div>

                    </div>
                    """
                )


    # ========================================================
    # IP INTELLIGENCE
    # ========================================================

    show_section_title(
        "🌐 Infrastructure Intelligence",
        "Observable IP addresses extracted from email routing headers."
    )


    ip_summary = ip_data.get(
        "summary",
        {}
    )


    col1, col2, col3 = st.columns(3)


    with col1:

        show_metric_card(
            "IPs Observed",
            ip_data.get(
                "total_ips",
                0
            ),
            "metric-blue"
        )


    with col2:

        show_metric_card(
            "Public",
            ip_summary.get(
                "public",
                0
            ),
            "metric-purple"
        )


    with col3:

        show_metric_card(
            "Private",
            ip_summary.get(
                "private",
                0
            ),
            "metric-green"
        )


    st.write("")


    ip_results = ip_data.get(
        "results",
        []
    )


    if not ip_results:

        st.html(
            """
            <div class="info-card"
                 style="text-align:center;">

                <div style="
                    font-size:2.5rem;
                ">
                    🌐
                </div>

                <div style="
                    font-weight:800;
                    margin-top:8px;
                ">
                    No Observable IP Addresses
                </div>

                <div style="
                    color:#94a3b8;
                    margin-top:5px;
                ">
                    No usable IP addresses were extracted
                    from the available routing headers.
                </div>

            </div>
            """
        )


    else:

        for result in ip_results:

            ip = safe_value(
                result.get(
                    "ip",
                    ""
                )
            )

            classification = safe_value(
                result.get(
                    "classification",
                    "Unknown"
                )
            )

            geo = result.get(
                "geolocation"
            ) or {}


            st.html(
                f"""
                <div class="ip-card">

                    <div style="
                        display:flex;
                        justify-content:space-between;
                        align-items:center;
                        flex-wrap:wrap;
                        gap:10px;
                    ">

                        <div class="ip-address">
                            🌐 {ip}
                        </div>

                        <div class="ip-badge">
                            {classification.upper()}
                        </div>

                    </div>

                </div>
                """
            )


            if geo.get(
                "success",
                False
            ):

                col1, col2, col3, col4 = st.columns(4)


                with col1:

                    st.metric(
                        "Country",
                        safe_value(
                            geo.get(
                                "country"
                            )
                        )
                    )


                with col2:

                    st.metric(
                        "Region",
                        safe_value(
                            geo.get(
                                "region"
                            )
                        )
                    )


                with col3:

                    st.metric(
                        "City",
                        safe_value(
                            geo.get(
                                "city"
                            )
                        )
                    )


                with col4:

                    st.metric(
                        "ISP",
                        safe_value(
                            geo.get(
                                "isp"
                            )
                        )
                    )


                organization = safe_value(
                    geo.get(
                        "organization"
                    )
                )

                asn = safe_value(
                    geo.get(
                        "asn"
                    )
                )


                st.html(
                    f"""
                    <div class="info-card">

                        <b>🏢 Organization:</b>
                        {organization}

                        &nbsp;&nbsp;&nbsp;

                        <b>🔢 ASN:</b>
                        {asn}

                    </div>
                    """
                )


                latitude = geo.get(
                    "latitude"
                )

                longitude = geo.get(
                    "longitude"
                )


                if (
                    latitude is not None
                    and
                    longitude is not None
                ):

                    st.caption(
                        f"📍 Approximate network coordinates: "
                        f"{latitude}, {longitude}"
                    )


            else:

                message = safe_value(
                    geo.get(
                        "message",
                        "No geolocation information available."
                    )
                )


                st.info(
                    message
                )


    # ========================================================
    # FORENSIC SUMMARY
    # ========================================================

    show_section_title(
        "🔎 Forensic Intelligence",
        "Correlated evidence generated from the investigation."
    )


    summary = forensic_data.get(
        "summary",
        {}
    )


    col1, col2, col3, col4 = st.columns(4)


    with col1:

        show_metric_card(
            "Forensic Risk",
            summary.get(
                "risk_score",
                0
            ),
            "metric-red"
        )


    with col2:

        show_metric_card(
            "Severity",
            safe_value(
                summary.get(
                    "severity"
                )
            ),
            "metric-purple"
        )


    with col3:

        show_metric_card(
            "Indicators",
            summary.get(
                "total_indicators",
                0
            ),
            "metric-blue"
        )


    with col4:

        show_metric_card(
            "Suspicious URLs",
            summary.get(
                "suspicious_urls",
                0
            ),
            "metric-red"
        )


    # ========================================================
    # FORENSIC TIMELINE
    # ========================================================

    show_section_title(
        "🕵️ Investigation Timeline",
        "How MailTrace AI processed the available evidence."
    )


    timeline = forensic_data.get(
        "timeline",
        []
    )


    if not timeline:

        st.info(
            "No forensic timeline was generated."
        )

    else:

        for event in timeline:

            step = safe_value(
                event.get(
                    "step",
                    ""
                )
            )

            event_name = safe_value(
                event.get(
                    "event",
                    "Unknown Event"
                )
            )

            description = safe_value(
                event.get(
                    "description",
                    ""
                )
            )

            status = str(
                event.get(
                    "status",
                    "INFO"
                )
            ).upper()


            border = "#6366f1"

            icon = "🔵"


            if status == "ALERT":

                border = "#ef4444"

                icon = "🔴"

            elif status == "WARNING":

                border = "#f59e0b"

                icon = "🟠"

            elif status == "SUCCESS":

                border = "#22c55e"

                icon = "🟢"


            st.html(
                f"""
                <div class="timeline-card"
                     style="
                        border-left-color:{border};
                     ">

                    <div class="timeline-step">
                        {icon} {step}
                    </div>

                    <div class="timeline-event">
                        {event_name}
                    </div>

                    <div class="timeline-description">
                        {description}
                    </div>

                </div>
                """
            )


    # ========================================================
    # ATTACHMENTS
    # ========================================================

    show_section_title(
        "📎 Attachment Intelligence",
        "Attachment metadata extracted without executing files."
    )


    attachments = forensic_data.get(
        "attachments",
        []
    )


    if not attachments:

        st.html(
            """
            <div class="threat-safe">
                🟢 No attachments detected.
            </div>
            """
        )

    else:

        for attachment in attachments:

            filename = safe_value(
                attachment.get(
                    "filename",
                    "Unknown"
                )
            )

            extension = safe_value(
                attachment.get(
                    "extension",
                    attachment.get(
                        "content_type",
                        "Unknown"
                    )
                )
            )

            size = attachment.get(
                "size",
                0
            )


            st.html(
                f"""
                <div class="evidence-card">

                    <div class="evidence-name">
                        📎 {filename}
                    </div>

                    <div class="evidence-reason">
                        Type: {extension}
                        &nbsp; • &nbsp;
                        Size: {size} bytes
                    </div>

                </div>
                """
            )


    # ========================================================
    # EMAIL STATISTICS
    # ========================================================

    show_section_title(
        "📊 Email Statistics"
    )


    email_size = forensic_data.get(
        "email_size",
        {}
    )


    col1, col2 = st.columns(2)


    with col1:

        show_metric_card(
            "Body Characters",
            email_size.get(
                "characters",
                0
            ),
            "metric-blue"
        )


    with col2:

        show_metric_card(
            "Body Classification",
            safe_value(
                email_size.get(
                    "classification"
                )
            ),
            "metric-purple"
        )


    # ========================================================
    # EXTRACTED INDICATORS
    # ========================================================

    show_section_title(
        "🔬 Evidence Repository",
        "Indicators extracted for further investigation."
    )


    extracted = forensic_data.get(
        "extracted_indicators",
        []
    )


    if not extracted:

        st.info(
            "No additional investigation indicators extracted."
        )

    else:

        for item in extracted:

            indicator_type = safe_value(
                item.get(
                    "type",
                    "UNKNOWN"
                )
            )

            value = safe_value(
                item.get(
                    "value",
                    "Unknown"
                )
            )

            source = safe_value(
                item.get(
                    "source",
                    "Unknown"
                )
            )


            with st.expander(
                f"🔎 {indicator_type}"
            ):

                st.code(
                    value
                )

                st.caption(
                    f"Evidence source: {source}"
                )


    # ========================================================
    # FINAL VERDICT
    # ========================================================

    st.markdown("---")


    verdict_upper = str(
        verdict
    ).upper()


    if "MALICIOUS" in verdict_upper:

        st.html(
            """
            <div class="threat-danger"
                 style="text-align:center;">

                <div style="
                    font-size:3rem;
                ">
                    🚨
                </div>

                <div style="
                    font-size:1.6rem;
                    font-weight:900;
                ">
                    THREAT DETECTED
                </div>

                <div style="
                    color:#fecaca;
                    margin-top:8px;
                ">
                    MailTrace AI identified risk indicators
                    requiring investigation.
                </div>

            </div>
            """
        )


    elif "SUSPICIOUS" in verdict_upper:

        st.html(
            """
            <div class="threat-warning"
                 style="text-align:center;">

                <div style="
                    font-size:3rem;
                ">
                    ⚠️
                </div>

                <div style="
                    font-size:1.6rem;
                    font-weight:900;
                ">
                    INVESTIGATION RECOMMENDED
                </div>

                <div style="
                    color:#fde68a;
                    margin-top:8px;
                ">
                    Suspicious characteristics were
                    identified in the submitted email.
                </div>

            </div>
            """
        )


    else:

        st.html(
            """
            <div class="threat-safe"
                 style="text-align:center;">

                <div style="
                    font-size:3rem;
                ">
                    🟢
                </div>

                <div style="
                    font-size:1.6rem;
                    font-weight:900;
                ">
                    NO HIGH-RISK THREAT DETECTED
                </div>

                <div style="
                    color:#bbf7d0;
                    margin-top:8px;
                ">
                    No high-risk indicators were returned
                    by the current detection engine.
                </div>

            </div>
            """
        )


# ============================================================
# FOOTER
# ============================================================

st.html(
    """
    <div class="footer">

        🛡️ <b>MailTrace AI</b>
        &nbsp;•&nbsp;
        SIH 26106
        &nbsp;•&nbsp;
        AI-Powered Email Threat Detection,
        Geolocation & Forensic Intelligence

        <br><br>

        Prototype • IP geolocation represents
        approximate network location when available.

    </div>
    """
)