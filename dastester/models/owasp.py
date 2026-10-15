"""OWASP Top 10 (2021) reference data and categorisation helpers."""

OWASP_TOP10 = {
    "A01": {
        "id": "A01:2021",
        "name": "Broken Access Control",
        "description": (
            "Restrictions on what authenticated users are allowed to do are "
            "often not properly enforced. Attackers can exploit these flaws "
            "to access unauthorised functionality or data."
        ),
        "reference": "https://owasp.org/Top10/A01_2021-Broken_Access_Control/",
    },
    "A02": {
        "id": "A02:2021",
        "name": "Cryptographic Failures",
        "description": (
            "Failures related to cryptography (or its absence) that lead to "
            "exposure of sensitive data in transit or at rest, including weak "
            "TLS configuration and missing transport security."
        ),
        "reference": "https://owasp.org/Top10/A02_2021-Cryptographic_Failures/",
    },
    "A03": {
        "id": "A03:2021",
        "name": "Injection",
        "description": (
            "User-supplied data is not validated, filtered, or sanitised, "
            "allowing hostile data to be interpreted as commands or queries "
            "(SQL, OS, LDAP, cross-site scripting, etc.)."
        ),
        "reference": "https://owasp.org/Top10/A03_2021-Injection/",
    },
    "A04": {
        "id": "A04:2021",
        "name": "Insecure Design",
        "description": (
            "Risks related to design and architectural flaws, including "
            "missing or ineffective control design and threat modelling gaps."
        ),
        "reference": "https://owasp.org/Top10/A04_2021-Insecure_Design/",
    },
    "A05": {
        "id": "A05:2021",
        "name": "Security Misconfiguration",
        "description": (
            "Missing appropriate security hardening, improperly configured "
            "permissions, verbose error messages, missing security headers, "
            "or unnecessary features enabled."
        ),
        "reference": "https://owasp.org/Top10/A05_2021-Security_Misconfiguration/",
    },
    "A06": {
        "id": "A06:2021",
        "name": "Vulnerable and Outdated Components",
        "description": (
            "Use of components with known vulnerabilities, unsupported or "
            "out-of-date software, including disclosed framework and server "
            "versions."
        ),
        "reference": "https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/",
    },
    "A07": {
        "id": "A07:2021",
        "name": "Identification and Authentication Failures",
        "description": (
            "Weaknesses in confirming user identity, authentication, and "
            "session management, including insecure session cookies."
        ),
        "reference": "https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/",
    },
    "A08": {
        "id": "A08:2021",
        "name": "Software and Data Integrity Failures",
        "description": (
            "Code and infrastructure that does not protect against integrity "
            "violations, such as insecure deserialisation or unverified "
            "resources loaded from untrusted sources."
        ),
        "reference": "https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/",
    },
    "A09": {
        "id": "A09:2021",
        "name": "Security Logging and Monitoring Failures",
        "description": (
            "Insufficient logging, detection, monitoring, and active response "
            "that allows attacks to progress undetected."
        ),
        "reference": "https://owasp.org/Top10/A09_2021-Security_Logging_and_Monitoring_Failures/",
    },
    "A10": {
        "id": "A10:2021",
        "name": "Server-Side Request Forgery (SSRF)",
        "description": (
            "Flaws that allow an attacker to coerce the server into making "
            "requests to unintended locations, often used to reach internal "
            "systems."
        ),
        "reference": "https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/",
    },
}


def owasp_meta(category_key):
    """Return the reference metadata for an OWASP category key (e.g. 'A05')."""
    return OWASP_TOP10.get(category_key, {
        "id": "N/A",
        "name": "Uncategorised",
        "description": "Finding not mapped to a specific OWASP Top 10 category.",
        "reference": "https://owasp.org/Top10/",
    })
