"""Metadata we add on top of Bandit's rules: category, CWE corrections, short recommendations.

Bandit's own `issue_cwe` is used by default. CWE_OVERRIDES lists the few rules where Bandit's
mapping is too generic for our reports (documented in Documents/Limitations.docx).
"""

# Category shown in the UI and used for filtering.
CATEGORY_BY_RULE = {
    "B101": "Code quality",
    "B102": "Code injection",
    "B103": "File permissions",
    "B104": "Network exposure",
    "B105": "Hardcoded secret",
    "B106": "Hardcoded secret",
    "B107": "Hardcoded secret",
    "B108": "Insecure temporary file",
    "B110": "Error handling",
    "B112": "Error handling",
    "B113": "Denial of service",
    "B201": "Debug mode",
    "B202": "Path traversal",
    "B301": "Unsafe deserialization",
    "B302": "Unsafe deserialization",
    "B303": "Weak cryptography",
    "B304": "Weak cryptography",
    "B305": "Weak cryptography",
    "B306": "Insecure temporary file",
    "B307": "Code injection",
    "B308": "Cross-site scripting",
    "B310": "Server-side request forgery",
    "B311": "Weak randomness",
    "B312": "Cleartext protocol",
    "B321": "Cleartext protocol",
    "B323": "TLS / certificate validation",
    "B324": "Weak cryptography",
    "B401": "Cleartext protocol",
    "B402": "Cleartext protocol",
    "B403": "Unsafe deserialization",
    "B404": "Command injection",
    "B501": "TLS / certificate validation",
    "B502": "TLS / certificate validation",
    "B503": "TLS / certificate validation",
    "B504": "TLS / certificate validation",
    "B505": "Weak cryptography",
    "B506": "Unsafe deserialization",
    "B507": "TLS / certificate validation",
    "B601": "Command injection",
    "B602": "Command injection",
    "B603": "Command injection",
    "B604": "Command injection",
    "B605": "Command injection",
    "B606": "Command injection",
    "B607": "Command injection",
    "B608": "SQL injection",
    "B609": "Command injection",
    "B610": "SQL injection",
    "B611": "SQL injection",
    "B701": "Cross-site scripting",
    "B702": "Cross-site scripting",
    "B703": "Cross-site scripting",
}

# XML parsing rules (B313-B320, B405-B411) all concern XML attacks.
for _rule in [f"B{n}" for n in range(313, 321)] + [f"B{n}" for n in range(405, 412)]:
    CATEGORY_BY_RULE[_rule] = "XML external entities"

# Bandit maps eval/exec to CWE-78 (OS command injection); CWE-95 (eval injection) is more precise.
# Bandit maps yaml.load to CWE-20 (input validation); CWE-502 (unsafe deserialization) is more precise.
# Bandit maps jinja2 autoescape=False to CWE-94 (code injection); CWE-79 (cross-site scripting) is more precise.
CWE_OVERRIDES = {
    "B102": 95,
    "B307": 95,
    "B506": 502,
    "B701": 79,
}

RECOMMENDATIONS = {
    "Code injection": "Never pass untrusted input to eval/exec. For literals use ast.literal_eval; "
                      "otherwise parse the input explicitly.",
    "Command injection": "Pass arguments as a list with shell=False, validate inputs against an allow-list, "
                         "and avoid building command strings from user data.",
    "SQL injection": "Use parameterized queries (cursor.execute(sql, params)) instead of building SQL with "
                     "string formatting or concatenation.",
    "Unsafe deserialization": "Do not unpickle/unmarshal untrusted data. Use a safe format such as JSON, or "
                              "yaml.safe_load for YAML.",
    "Hardcoded secret": "Load secrets from environment variables or a secrets manager; never commit them "
                        "to source code.",
    "Weak cryptography": "Use SHA-256 or stronger for integrity, a password hash (bcrypt/scrypt/argon2) for "
                         "passwords, and modern ciphers with adequate key sizes.",
    "Weak randomness": "Use the secrets module for tokens, passwords and other security-sensitive values.",
    "Insecure temporary file": "Use tempfile.NamedTemporaryFile or tempfile.mkstemp instead of predictable "
                               "paths or tempfile.mktemp.",
    "TLS / certificate validation": "Keep certificate verification enabled (verify=True) and use modern TLS "
                                    "versions.",
    "XML external entities": "Parse untrusted XML with defusedxml instead of the standard library parsers.",
    "Cross-site scripting": "Keep template auto-escaping enabled and avoid marking user data as safe.",
    "Network exposure": "Bind to a specific interface (for example 127.0.0.1) unless public exposure is "
                        "intended.",
    "Debug mode": "Disable debug mode in production; it can expose an interactive console.",
    "Cleartext protocol": "Use encrypted protocols (SSH, SFTP, HTTPS) instead of Telnet or FTP.",
    "Server-side request forgery": "Validate URL schemes and destinations before opening user-supplied URLs.",
    "Path traversal": "Check every archive member's path stays inside the target folder before extracting "
                      "(Python 3.12+: tar.extractall(path, filter=\"data\")).",
    "File permissions": "Grant the minimum file permissions needed; avoid world-writable modes.",
    "Error handling": "Handle or log specific exceptions instead of silently ignoring them.",
    "Denial of service": "Set an explicit timeout on network requests.",
    "Code quality": "Do not rely on assert for security checks; asserts are removed with python -O.",
}

# Rules raised from Medium to High when Bandit's confidence is HIGH: these let an attacker run
# code or commands directly if untrusted input reaches them.
ESCALATE_TO_HIGH = {"B102", "B301", "B302", "B307", "B506", "B602", "B605"}


def category_for(rule_id: str) -> str:
    return CATEGORY_BY_RULE.get(rule_id, "Other security issue")


def recommendation_for(category: str):
    return RECOMMENDATIONS.get(category)
