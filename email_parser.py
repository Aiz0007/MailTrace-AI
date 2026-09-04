# ============================================================
# EMAIL PARSER MODULE
# SIH 26106 - Email Threat Intelligence & Forensic Platform
# ============================================================
#
# PURPOSE:
#
# 1. Read .eml email files
# 2. Extract email metadata
# 3. Extract email headers
# 4. Extract Received headers
# 5. Extract IP addresses
# 6. Extract email body
# 7. Extract URLs
# 8. Extract attachment information
#
# ============================================================


# ------------------------------------------------------------
# BUILT-IN PYTHON MODULES
# ------------------------------------------------------------

from email import policy
from email.parser import BytesParser

import re
import ipaddress


# ============================================================
# 1. EXTRACT IPv4 ADDRESSES
# ============================================================

def extract_ipv4(text):
    """
    Find valid IPv4 addresses inside a piece of text.

    Example:

        "Received from mail.example.com (8.8.8.8)"

    returns:

        ["8.8.8.8"]
    """

    if not text:
        return []

    # Pattern that finds IPv4-looking addresses
    pattern = r"\b(?:\d{1,3}\.){3}\d{1,3}\b"

    possible_ips = re.findall(
        pattern,
        text
    )

    valid_ips = []

    for ip in possible_ips:

        try:

            # Check whether it is actually a valid IP
            ipaddress.IPv4Address(ip)

            if ip not in valid_ips:

                valid_ips.append(ip)

        except ValueError:

            # Ignore invalid IP addresses
            pass

    return valid_ips


# ============================================================
# 2. EXTRACT EMAIL BODY
# ============================================================

def extract_body(message):
    """
    Extract the readable body from an email.

    Preference:
        1. Plain text
        2. HTML
    """

    plain_text = ""
    html_text = ""

    # --------------------------------------------------------
    # Multipart email
    # --------------------------------------------------------

    if message.is_multipart():

        for part in message.walk():

            content_type = part.get_content_type()

            content_disposition = (
                part.get_content_disposition()
            )

            # Skip attachments
            if content_disposition == "attachment":
                continue


            # -----------------------------------------------
            # Plain text
            # -----------------------------------------------

            if content_type == "text/plain":

                try:

                    plain_text += (
                        part.get_content()
                    )

                except Exception:

                    pass


            # -----------------------------------------------
            # HTML
            # -----------------------------------------------

            elif content_type == "text/html":

                try:

                    html_text += (
                        part.get_content()
                    )

                except Exception:

                    pass


    # --------------------------------------------------------
    # Non-multipart email
    # --------------------------------------------------------

    else:

        content_type = message.get_content_type()

        try:

            content = message.get_content()

        except Exception:

            content = ""

        if content_type == "text/plain":

            plain_text = content

        elif content_type == "text/html":

            html_text = content


    # --------------------------------------------------------
    # Prefer plain text
    # --------------------------------------------------------

    if plain_text.strip():

        return plain_text.strip()


    # Otherwise return HTML
    return html_text.strip()


# ============================================================
# 3. EXTRACT ATTACHMENTS
# ============================================================

def extract_attachments(message):
    """
    Extract attachment filenames.

    IMPORTANT:
    This function only records attachment information.
    It does NOT open or execute attachments.
    """

    attachments = []

    for part in message.walk():

        disposition = (
            part.get_content_disposition()
        )

        if disposition == "attachment":

            filename = part.get_filename()

            if filename:

                attachments.append({
                    "filename": filename,
                    "content_type": part.get_content_type(),
                    "size": len(
                        part.get_payload(
                            decode=True
                        ) or b""
                    )
                })

    return attachments


# ============================================================
# 4. EXTRACT URLs
# ============================================================

def extract_urls(text):
    """
    Extract HTTP andHTTPS URLs from email body.
    """

    if not text:
        return []

    pattern = r'https?://[^\s<>"\']+'

    urls = re.findall(
        pattern,
        text
    )

    # Remove duplicates
    unique_urls = []

    for url in urls:

        if url not in unique_urls:

            unique_urls.append(url)

    return unique_urls


# ============================================================
# 5. EXTRACT RECEIVED HEADERS
# ============================================================

def extract_received_headers(message):
    """
    Extract all Received headers.

    Received headers are important in email forensics because
    they record the servers through which an email passed.
    """

    received_headers = []

    for header in message.get_all(
        "Received",
        []
    ):

        received_headers.append(
            header
        )

    return received_headers


# ============================================================
# 6. EXTRACT IPs FROM RECEIVED HEADERS
# ============================================================

def extract_received_ips(received_headers):
    """
    Extract IP addresses specifically from Received headers.
    """

    all_ips = []

    for header in received_headers:

        ips = extract_ipv4(
            header
        )

        for ip in ips:

            if ip not in all_ips:

                all_ips.append(ip)

    return all_ips


# ============================================================
# 7. FIND PUBLIC IPs
# ============================================================

def find_public_ips(ips):
    """
    Separate public/global IP addresses from private/local ones.
    """

    public_ips = []

    private_ips = []

    other_ips = []


    for ip in ips:

        try:

            address = ipaddress.ip_address(
                ip
            )


            if address.is_global:

                public_ips.append(ip)

            elif address.is_private:

                private_ips.append(ip)

            else:

                other_ips.append(ip)


        except ValueError:

            other_ips.append(ip)


    return {
        "public": public_ips,
        "private": private_ips,
        "other": other_ips
    }


# ============================================================
# 8. GET ALL HEADERS
# ============================================================

def extract_headers(message):
    """
    Convert all email headers into a dictionary.

    Note:
    Some headers can appear multiple times, so repeated
    headers are stored as a list.
    """

    headers = {}

    for key, value in message.items():

        if key in headers:

            # If header already exists,
            # convert it into a list.

            if isinstance(
                headers[key],
                list
            ):

                headers[key].append(
                    value
                )

            else:

                headers[key] = [
                    headers[key],
                    value
                ]

        else:

            headers[key] = value


    return headers


# ============================================================
# 9. EXTRACT AUTHENTICATION HEADERS
# ============================================================

def extract_authentication_results(message):
    """
    Extract authentication-related headers.

    These can later be used for SPF/DKIM/DMARC analysis.
    """

    authentication = {}


    # --------------------------------------------------------
    # Authentication-Results
    # --------------------------------------------------------

    auth_results = message.get_all(
        "Authentication-Results",
        []
    )

    authentication[
        "authentication_results"
    ] = auth_results


    # --------------------------------------------------------
    # Received-SPF
    # --------------------------------------------------------

    received_spf = message.get_all(
        "Received-SPF",
        []
    )

    authentication[
        "received_spf"
    ] = received_spf


    # --------------------------------------------------------
    # DKIM-Signature
    # --------------------------------------------------------

    dkim = message.get_all(
        "DKIM-Signature",
        []
    )

    authentication[
        "dkim_signature"
    ] = dkim


    return authentication


# ============================================================
# 10. MAIN EMAIL PARSER
# ============================================================

def parse_email(file):
    """
    MAIN FUNCTION.

    Input:
        .eml file

    Output:
        Dictionary containing all extracted information.
    """

    # ========================================================
    # STEP 1 — READ EMAIL
    # ========================================================

    message = BytesParser(
        policy=policy.default
    ).parse(file)


    # ========================================================
    # STEP 2 — BASIC METADATA
    # ========================================================

    sender = message.get(
        "From",
        ""
    )

    receiver = message.get(
        "To",
        ""
    )

    subject = message.get(
        "Subject",
        ""
    )

    date = message.get(
        "Date",
        ""
    )

    message_id = message.get(
        "Message-ID",
        ""
    )


    # ========================================================
    # STEP 3 — BODY
    # ========================================================

    body = extract_body(
        message
    )


    # ========================================================
    # STEP 4 — URLs
    # ========================================================

    urls = extract_urls(
        body
    )


    # ========================================================
    # STEP 5 — ATTACHMENTS
    # ========================================================

    attachments = extract_attachments(
        message
    )


    # ========================================================
    # STEP 6 — ALL HEADERS
    # ========================================================

    headers = extract_headers(
        message
    )


    # ========================================================
    # STEP 7 — RECEIVED HEADERS
    # ========================================================

    received_headers = extract_received_headers(
        message
    )


    # ========================================================
    # STEP 8 — RECEIVED IPs
    # ========================================================

    received_ips = extract_received_ips(
        received_headers
    )


    # ========================================================
    # STEP 9 — CLASSIFY IPs
    # ========================================================

    ip_classification = find_public_ips(
        received_ips
    )


    # ========================================================
    # STEP 10 — AUTHENTICATION INFORMATION
    # ========================================================

    authentication = (
        extract_authentication_results(
            message
        )
    )


    # ========================================================
    # STEP 11 — RETURN EVERYTHING
    # ========================================================

    return {

        # ----------------------------------------------------
        # Basic information
        # ----------------------------------------------------

        "sender": sender,

        "receiver": receiver,

        "subject": subject,

        "date": date,

        "message_id": message_id,


        # ----------------------------------------------------
        # Body
        # ----------------------------------------------------

        "body": body,


        # ----------------------------------------------------
        # URLs
        # ----------------------------------------------------

        "urls": urls,


        # ----------------------------------------------------
        # Attachments
        # ----------------------------------------------------

        "attachments": attachments,


        # ----------------------------------------------------
        # Headers
        # ----------------------------------------------------

        "headers": headers,


        # ----------------------------------------------------
        # Received headers
        # ----------------------------------------------------

        "received_headers": received_headers,


        # ----------------------------------------------------
        # IP information
        # ----------------------------------------------------

        "received_ips": received_ips,

        "public_ips": ip_classification[
            "public"
        ],

        "private_ips": ip_classification[
            "private"
        ],

        "other_ips": ip_classification[
            "other"
        ],


        # ----------------------------------------------------
        # Authentication
        # ----------------------------------------------------

        "authentication": authentication

    }


# ============================================================
# 12. SIMPLE TEST
# ============================================================

if __name__ == "__main__":

    print(
        "============================================"
    )

    print(
        "       EMAIL PARSER TEST"
    )

    print(
        "============================================"
    )


    filename = input(
        "\nEnter path to .eml file: "
    )


    try:

        # Open email file in binary mode
        with open(
            filename,
            "rb"
        ) as file:

            result = parse_email(
                file
            )


        # ====================================================
        # DISPLAY RESULTS
        # ====================================================

        print(
            "\n========== BASIC INFORMATION =========="
        )

        print(
            "Sender:",
            result["sender"]
        )

        print(
            "Receiver:",
            result["receiver"]
        )

        print(
            "Subject:",
            result["subject"]
        )

        print(
            "Date:",
            result["date"]
        )

        print(
            "Message ID:",
            result["message_id"]
        )


        print(
            "\n========== RECEIVED HEADERS =========="
        )

        for header in result[
            "received_headers"
        ]:

            print(
                header
            )


        print(
            "\n========== IP ADDRESSES =========="
        )

        print(
            "All IPs:",
            result["received_ips"]
        )

        print(
            "Public IPs:",
            result["public_ips"]
        )

        print(
            "Private IPs:",
            result["private_ips"]
        )


        print(
            "\n========== URLs =========="
        )

        for url in result["urls"]:

            print(
                url
            )


        print(
            "\n========== ATTACHMENTS =========="
        )

        if result["attachments"]:

            for attachment in result[
                "attachments"
            ]:

                print(
                    "Filename:",
                    attachment["filename"]
                )

                print(
                    "Type:",
                    attachment["content_type"]
                )

                print(
                    "Size:",
                    attachment["size"],
                    "bytes"
                )

        else:

            print(
                "No attachments found."
            )


        print(
            "\n========== AUTHENTICATION =========="
        )

        print(
            result["authentication"]
        )


        print(
            "\n============================================"
        )

        print(
            "       PARSING COMPLETED"
        )

        print(
            "============================================"
        )


    except FileNotFoundError:

        print(
            "\n❌ File not found."
        )

        print(
            "Check the file path and try again."
        )


    except Exception as error:

        print(
            "\n❌ Error while parsing email:"
        )

        print(
            error
        )