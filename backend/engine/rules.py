"""
rules.py - Define a list of regex patterns covering classic SQLi signatures.
Each pattern has a name, regex, severity weight, and category.
"""

SQLI_RULES = [
    {
        "name": "classic_tautology",
        "pattern": r"'\s*OR\s*'1'\s*=\s*'1|'\s*OR\s*1\s*=\s*1",
        "severity": 10,
        "category": "boolean-based"
    },
    {
        "name": "union_select",
        "pattern": r"UNION\s+(?:ALL\s+)?SELECT",
        "severity": 9,
        "category": "union-based"
    },
    {
        "name": "comment_sequence",
        "pattern": r"--|#|/\*",
        "severity": 4,
        "category": "generic"
    },
    {
        "name": "stacked_query",
        "pattern": r";\s*(?:DROP|DELETE|UPDATE|INSERT|CREATE|ALTER|TRUNCATE|EXEC|EXECUTE)",
        "severity": 10,
        "category": "stacked queries"
    },
    {
        "name": "time_based_sleep",
        "pattern": r"SLEEP\(\s*\d+\s*\)|WAITFOR\s+DELAY|BENCHMARK\(",
        "severity": 9,
        "category": "time-based blind"
    },
    {
        "name": "boolean_blind",
        "pattern": r"AND\s+\d+=\d+|OR\s+\d+=\d+",
        "severity": 6,
        "category": "boolean-based"
    },
    {
        "name": "error_based",
        "pattern": r"GROUP\s+BY|ORDER\s+BY|HAVING|INFORMATION_SCHEMA|CONCAT\(",
        "severity": 5,
        "category": "error-based"
    },
    {
        "name": "xp_cmdshell",
        "pattern": r"xp_cmdshell",
        "severity": 10,
        "category": "generic"
    },
    {
        "name": "hex_encoding",
        "pattern": r"0x[0-9a-fA-F]+",
        "severity": 5,
        "category": "generic"
    },
    {
        "name": "url_encoding_bypass",
        "pattern": r"%[0-9a-fA-F]{2}",
        "severity": 3,
        "category": "generic"
    }
]
