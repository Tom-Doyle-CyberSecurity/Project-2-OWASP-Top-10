# scanners/bandit_cwe_map.py
# Map Bandit rule IDs to CWE IDs. Expand as needed.
# Rule IDs from https://bandit.readthedocs.io/en/latest/plugins/index.html#complete-test-plugin-listing

BANDIT_TEST_TO_CWE = {
    "B105": 259,   # Hardcoded password
    "B303": 327,   # md5
    "B304": 338,   # insecure hash functions
    "B307": 94,    # eval()
    "B602": 78,    # subprocess with shell=True
    "B603": 78,    # subprocess with user input
    "B604": 78,    # subprocess with shell injection risk
    "B608": 798,   # SQL injection (approx)
}
