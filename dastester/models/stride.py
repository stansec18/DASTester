"""STRIDE threat-model reference data and helpers.

STRIDE classifies threats into six categories. DASTester maps each
finding to one or more STRIDE categories so that findings can be viewed
through a threat-modelling lens alongside the OWASP Top 10.
"""

STRIDE = {
    "S": {
        "code": "S",
        "name": "Spoofing",
        "property": "Authentication",
        "description": (
            "Illegitimately assuming the identity of another user, component, "
            "or system. Violates the authenticity property."
        ),
    },
    "T": {
        "code": "T",
        "name": "Tampering",
        "property": "Integrity",
        "description": (
            "Unauthorised modification of data or code, in transit or at "
            "rest. Violates the integrity property."
        ),
    },
    "R": {
        "code": "R",
        "name": "Repudiation",
        "property": "Non-repudiation",
        "description": (
            "Performing actions that cannot be traced or attributed, often "
            "due to insufficient logging. Violates non-repudiation."
        ),
    },
    "I": {
        "code": "I",
        "name": "Information Disclosure",
        "property": "Confidentiality",
        "description": (
            "Exposure of information to individuals who are not authorised to "
            "see it. Violates the confidentiality property."
        ),
    },
    "D": {
        "code": "D",
        "name": "Denial of Service",
        "property": "Availability",
        "description": (
            "Denying or degrading service to legitimate users. Violates the "
            "availability property."
        ),
    },
    "E": {
        "code": "E",
        "name": "Elevation of Privilege",
        "property": "Authorization",
        "description": (
            "Gaining capabilities or access rights beyond those granted. "
            "Violates the authorisation property."
        ),
    },
}


def stride_meta(code):
    """Return metadata for a STRIDE code (e.g. 'I')."""
    return STRIDE.get(code, {
        "code": "?",
        "name": "Unmapped",
        "property": "N/A",
        "description": "Finding not mapped to a specific STRIDE category.",
    })
