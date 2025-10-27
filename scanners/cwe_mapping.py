# ============================================================
# OWASP Top 10 (2021–2025) → CWE Mapping
# Source: OWASP Foundation (Official OWASP Top 10)
# Reference: https://owasp.org/Top10/
# Purpose: Correlates OWASP Top 10 categories with CWE identifiers
# For: Dynamic scans (e.g., Juice Shop + ZAP)
# Author: Tom D. (2025)
# ============================================================

OWASP_CWE_MAP = {
    "A01: Broken Access Control": [
        22, 23, 35, 59, 200, 201, 219, 264, 275, 276, 284, 285, 352, 359, 377, 402,
        425, 441, 497, 538, 540, 548, 552, 566, 601, 639, 651, 668, 706, 862, 863,
        913, 922, 1275
    ],

    "A02: Cryptographic Failures": [
        259, 261, 296, 310, 319, 321, 322, 323, 324, 325, 326, 327, 328, 329, 330,
        331, 335, 336, 337, 338, 340, 347, 523, 720, 757, 759, 760, 780, 818, 916
    ],

    "A03: Injection": [
        20, 74, 75, 77, 78, 79, 80, 83, 87, 88, 89, 90, 91, 93, 94, 95, 96, 97, 98,
        99, 113, 116, 184, 470, 471, 564, 610, 643, 644, 652, 917
    ],

    "A04: Insecure Design": [
        73, 183, 209, 213, 235, 256, 257, 266, 269, 280, 311, 312, 313, 316, 419,
        430, 434, 451, 472, 501, 522, 525, 539, 579, 598, 602, 642, 646, 650, 653,
        656, 657, 799, 807, 840, 841, 927, 1021, 1173
    ],

    "A05: Security Misconfiguration": [
        2, 11, 13, 15, 16, 260, 315, 520, 526, 537, 541, 547, 611, 614, 756, 776,
        942, 1004, 1032, 1174
    ],

    "A06: Vulnerable and Outdated Components": [
        937, 1035, 1104
    ],

    "A07: Identification and Authentication Failures": [
        255, 259, 287, 288, 290, 294, 295, 297, 300, 302, 304, 306, 307, 346, 384,
        521, 613, 620, 798, 940, 1216
    ],

    "A08: Software and Data Integrity Failures": [
        345, 353, 426, 494, 502, 565, 784, 829, 830, 915
    ],

    "A09: Security Logging and Monitoring Failures": [
        117, 223, 532, 778
    ],

    "A10: Server-Side Request Forgery (SSRF)": [
        918
    ]
}

# ---- Flatten all CWEs into one master list (for quick scan correlation) ----
ALL_CWES = sorted({cwe for cwes in OWASP_CWE_MAP.values() for cwe in cwes})

# ---- Human-readable CWE names (for reports / dashboards) ----
CWE_NAME_MAP = {
    # A01 – Broken Access Control
    22: "Improper Limitation of a Pathname to a Restricted Directory (Path Traversal)",
    23: "Relative Path Traversal",
    59: "Link Following",
    285: "Improper Authorization",
    352: "Cross-Site Request Forgery (CSRF)",
    425: "Forced Browsing / Direct Request",
    601: "Open Redirect",
    639: "Insecure Direct Object Reference (IDOR)",
    862: "Missing Authorization",
    863: "Incorrect Authorization",
    922: "Insecure Storage of Sensitive Information",

    # A02 – Cryptographic Failures
    259: "Use of Hard-coded Password",
    319: "Cleartext Transmission of Sensitive Information",
    326: "Inadequate Encryption Strength",
    327: "Use of a Broken or Risky Cryptographic Algorithm",
    330: "Use of Insufficiently Random Values",
    759: "Use of a One-Way Hash without Salt",
    760: "Use of a One-Way Hash with a Predictable Salt",
    916: "Use of Password Hash with Insufficient Computational Effort",

    # A03 – Injection
    74: "Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection')",
    77: "Command Injection",
    78: "OS Command Injection",
    79: "Cross-Site Scripting (XSS)",
    89: "SQL Injection",
    90: "LDAP Injection",
    94: "Code Injection",
    98: "Improper Control of Filename for Include/Require Statement",
    116: "Improper Encoding or Escaping of Output",
    184: "Incomplete Blacklist of Input Validation",
    917: "Improper Neutralization of Special Elements in Template Expression",

    # A04 – Insecure Design
    434: "Unrestricted Upload of File with Dangerous Type",
    451: "User Interface (UI) Misrepresentation of Critical Information",
    501: "Trust Boundary Violation",
    525: "Use of Web Browser Cache Containing Sensitive Information",
    602: "Client-Side Enforcement of Server-Side Security",
    799: "Improper Control of Interaction Frequency (Rate Limiting)",
    807: "Reliance on Untrusted Inputs in a Security Decision",
    840: "Business Logic Errors",

    # A05 – Security Misconfiguration
    611: "Improper Restriction of XML External Entity Reference (XXE)",
    942: "Improperly Configured Security Permissions for Key Resources",
    1032: "Incomplete or Inconsistent Security Configuration",
    1174: "Unexpected Internal State in Security Configuration",

    # A06 – Vulnerable & Outdated Components
    937: "Use of Obsolete API",
    1035: "Insufficient Module Isolation",
    1104: "Use of Unmaintained Third-Party Components",

    # A07 – Identification & Authentication Failures
    287: "Improper Authentication",
    295: "Improper Certificate Validation",
    306: "Missing Authentication for Critical Function",
    307: "Improper Restriction of Excessive Authentication Attempts",
    521: "Weak Password Requirements",
    613: "Insufficient Session Expiration",
    620: "Unverified Password Change",
    798: "Use of Hard-coded Credentials",
    940: "Improper Verification of Source of a Communication Channel",
    1216: "Missing Required Validation of Certificate with Host Mismatch",

    # A08 – Software and Data Integrity Failures
    345: "Insufficient Verification of Data Authenticity",
    426: "Untrusted Search Path",
    502: "Deserialization of Untrusted Data",
    829: "Inclusion of Functionality from Untrusted Control Sphere",
    915: "Improperly Controlled Modification of Dynamically-Determined Object Attributes",

    # A09 – Security Logging & Monitoring Failures
    117: "Improper Output Neutralization for Logs",
    223: "Omission of Security-Relevant Information in Logs",
    532: "Information Exposure Through Log Files",
    778: "Insufficient Logging",

    # A10 – Server-Side Request Forgery
    918: "Server-Side Request Forgery (SSRF)"
}