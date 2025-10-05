# ========== Master CWE Mapping ==========
# Source: OWASP Foundation (Official OWASP Top 10 2021–2025 Mapping)
# Reference: https://owasp.org/Top10/
# Extracted and compiled for Juice Shop Dynamic Scanner (ZAP)
# Purpose: Correlates OWASP Top 10 categories with CWE identifiers
# Author: Tom D. (2025)
# -------------------------------------------------------------

ALL_CWES = [
    # Broken Access Control
    22, 23, 35, 59, 200, 201, 219, 264, 275, 276, 284, 285, 352, 359, 377, 402,
    425, 441, 497, 538, 540, 548, 552, 566, 601, 639, 651, 668, 706, 862, 863,
    913, 922, 1275,

    # Cryptographic Failures
    259, 261, 296, 310, 319, 321, 322, 323, 324, 325, 326, 327, 328, 329, 330,
    331, 335, 336, 337, 338, 340, 347, 523, 720, 757, 759, 760, 780, 818, 916,

    # Injection
    20, 74, 75, 77, 78, 79, 80, 83, 87, 88, 89, 90, 91, 93, 94, 95, 96, 97, 98,
    99, 113, 116, 184, 470, 471, 564, 610, 643, 644, 652, 917,

    # Insecure Design
    73, 183, 209, 213, 235, 256, 257, 266, 269, 280, 311, 312, 313, 316, 419,
    430, 434, 451, 472, 501, 522, 525, 539, 579, 598, 602, 642, 646, 650, 653,
    656, 657, 799, 807, 840, 841, 927, 1021, 1173,

    # Security Misconfiguration
    2, 11, 13, 15, 16, 260, 315, 520, 526, 537, 541, 547, 611, 614, 756, 776,
    942, 1004, 1032, 1174,

    # Vulnerable & Outdated Components
    937, 1035, 1104,

    # Identification & Authentication Failures
    255, 259, 287, 288, 290, 294, 295, 297, 300, 302, 304, 306, 307, 346, 384,
    521, 613, 620, 798, 940, 1216,

    # Software and Data Integrity Failures
    345, 353, 426, 494, 502, 565, 784, 829, 830, 915,

    # Security Logging and Monitoring Failures
    117, 223, 532, 778,

    # Server-Side Request Forgery (SSRF)
    918
]

# Optional short-name mapping (displayed for readability in dashboards/reports)
CWE_NAME_MAP = {
    22: "Path Traversal",
    79: "Cross-Site Scripting (XSS)",
    89: "SQL Injection",
    319: "Cleartext Transmission of Sensitive Info",
    352: "Cross-Site Request Forgery (CSRF)",
    425: "Forced Browsing / Direct Request",
    601: "Open Redirect",
    918: "Server-Side Request Forgery (SSRF)",
    # Add more if needed; unknowns will print by CWE ID only.
}
