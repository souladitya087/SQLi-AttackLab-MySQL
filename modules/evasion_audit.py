"""Module 4: Advanced Filter Evasion, Second-Order SQLi & SAST Remediation.

Features:
1. Second-Order (Stored) SQL Injection demonstration (Safe write, dynamic read).
2. WAF & Signature Filter Evasion sandbox (spaces, keywords, quote stripping).
3. Static Application Security Testing (SAST) query linter & auto-fix generator.
4. OWASP A03:2021 / CWE-89 security compliance report generator.
"""

from decimal import Decimal
import re
import time
from typing import Any, Dict, List, Optional, Tuple
import pymysql
from database import get_db_connection, log_audit_query

# ---------------------------------------------------------
# 1. Second-Order (Stored) SQL Injection
# ---------------------------------------------------------

def save_user_profile(username: str, display_name: str, bio: str) -> Dict[str, Any]:
    """Saves user profile safely using parameterized INSERT (First Order: Safe Storage).

    Args:
        username: Account identifier.
        display_name: Public profile display name (potential stored payload).
        bio: Profile description.

    Returns:
        Dictionary with save status.
    """
    conn = None
    try:
        conn = get_db_connection()
        with conn.cursor() as cursor:
            query = """
                INSERT INTO `user_profiles` (`username`, `display_name`, `bio`)
                VALUES (%s, %s, %s)
                ON DUPLICATE KEY UPDATE `display_name` = VALUES(`display_name`), `bio` = VALUES(`bio`)
            """
            cursor.execute(query, (username, display_name, bio))
        return {
            "success": True,
            "message": f"Profile for '{username}' saved successfully into database (Storage Phase: Clean & Parameterized).",
            "stored_display_name": display_name
        }
    except Exception as e:
        return {"success": False, "error": str(e)}
    finally:
        if conn:
            conn.close()

def execute_profile_audit_report(
    target_username: str,
    mode: str = "vulnerable",
    client_ip: str = "127.0.0.1"
) -> Dict[str, Any]:
    """Executes the secondary report lookup that triggers stored second-order SQLi.

    Args:
        target_username: Profile account to audit.
        mode: Engine mode ('vulnerable' or 'secure').
        client_ip: Source IP for logging.

    Returns:
        Dictionary with executed queries, compromised records, and flag status.
    """
    start_time = time.time()
    result: Dict[str, Any] = {
        "success": False,
        "mode": mode,
        "target_username": target_username,
        "first_order_status": "Clean record read from `user_profiles`",
        "stored_value": "",
        "constructed_query": "",
        "results": [],
        "row_count": 0,
        "error": None,
        "bypassed": False,
        "flag": None,
        "execution_time_ms": 0.0,
        "explanation": ""
    }

    conn = None
    try:
        conn = get_db_connection()
        with conn.cursor() as cursor:
            # Step 1: Read the previously stored profile
            cursor.execute(
                "SELECT `username`, `display_name`, `bio` FROM `user_profiles` WHERE `username` = %s",
                (target_username,)
            )
            profile = cursor.fetchone()

            if not profile:
                result["error"] = f"No profile found for user '{target_username}'. Please create one first."
                return result

            stored_display_name = profile["display_name"]
            result["stored_value"] = stored_display_name

            # Step 2: Second Order Trigger Query
            if mode == "vulnerable":
                # Insecurely interpolating data that came FROM the database
                query = (
                    f"SELECT id, username, full_name, email, role, api_key "
                    f"FROM users WHERE username = '{stored_display_name}'"
                )
                result["constructed_query"] = query
                cursor.execute(query)
                raw_rows = cursor.fetchall()

                result["results"] = raw_rows
                result["row_count"] = len(raw_rows)
                result["success"] = True

                # Check if second order injection compromised an account or admin
                is_compromised = any(
                    r.get("role") == "admin" or r.get("username") != target_username
                    for r in raw_rows
                ) or any(sym in stored_display_name for sym in ["'", "--", "#", "/*", "UNION"])

                if is_compromised and len(raw_rows) > 0:
                    result["bypassed"] = True
                    result["flag"] = "FLAG{mysql_second_order_stored_sqli_pwned}"
                    result["explanation"] = (
                        "Second-Order SQL Injection Successful! Even though the initial INSERT was safely parameterized, "
                        "the backend blindly trusted the data when reading it back from the database and concatenated "
                        "it into the secondary credential lookup query."
                    )
                else:
                    result["explanation"] = "Query executed normally with the stored display name."

                log_audit_query(
                    "Module 4: Second-Order SQLi",
                    query,
                    False,
                    "SUCCESS" if raw_rows else "NO_ROWS",
                    None,
                    client_ip
                )

            else:
                # SECURE MODE: Parameterized secondary query
                query = "SELECT id, username, full_name, email, role, api_key FROM users WHERE username = %s"
                result["constructed_query"] = (
                    f"PREPARED: SELECT id, username, full_name, email, role, api_key FROM users "
                    f"WHERE username = ? [PARAMS: ({stored_display_name!r})]"
                )
                cursor.execute(query, (stored_display_name,))
                raw_rows = cursor.fetchall()

                result["results"] = raw_rows
                result["row_count"] = len(raw_rows)
                result["success"] = True
                result["bypassed"] = False
                result["explanation"] = (
                    "Prepared statements applied to the secondary query safely bound the stored string "
                    "as a literal parameter, completely preventing second-order execution."
                )

                log_audit_query(
                    "Module 4: Second-Order SQLi",
                    query,
                    True,
                    "SUCCESS" if raw_rows else "NO_ROWS",
                    None,
                    client_ip
                )

    except pymysql.MySQLError as err:
        code, msg = err.args
        result["error"] = f"MySQL Error [{code}]: {msg}"
        log_audit_query("Module 4: Second-Order SQLi", result.get("constructed_query", ""), mode == "secure", "MYSQL_ERROR", result["error"], client_ip)
    except Exception as e:
        result["error"] = str(e)
    finally:
        if conn:
            conn.close()

    result["execution_time_ms"] = round((time.time() - start_time) * 1000, 2)
    return result

# ---------------------------------------------------------
# 2. WAF & Filter Evasion Sandbox
# ---------------------------------------------------------

WAF_RULES = {
    "none": {
        "name": "No WAF Filtering",
        "description": "Direct pass-through without signature inspection.",
        "regex": None
    },
    "spaces": {
        "name": "Whitespace Blacklist Filter",
        "description": "Blocks ASCII space characters (\\s). Bypass using inline comments /**/ or tabs.",
        "regex": r"\s+"
    },
    "keywords": {
        "name": "Strict Keyword Filter (UNION / SELECT)",
        "description": "Blocks exact uppercase UNION and SELECT keywords. Bypass using mixed casing (uNiOn) or comment splitting (UNI/**/ON).",
        "regex": r"\b(UNION|SELECT)\b"
    },
    "quotes": {
        "name": "Single & Double Quote Stripper",
        "description": "Blocks literal quotation marks (' and \"). Bypass using hexadecimal literals (e.g. 0x61646d696e for 'admin').",
        "regex": r"['\"]"
    }
}

def execute_waf_sandbox_query(
    payload: str,
    filter_profile: str = "spaces",
    mode: str = "vulnerable",
    client_ip: str = "127.0.0.1"
) -> Dict[str, Any]:
    """Simulates WAF signature filtering and attempts execution in MySQL.

    Args:
        payload: Injected string or search term.
        filter_profile: Target filter rule ('none', 'spaces', 'keywords', 'quotes').
        mode: Engine mode ('vulnerable' or 'secure').
        client_ip: Source IP for logging.

    Returns:
        Dictionary with filter outcome, bypass status, MySQL results, and flags.
    """
    start_time = time.time()
    result: Dict[str, Any] = {
        "success": False,
        "mode": mode,
        "filter_profile": filter_profile,
        "filter_name": WAF_RULES.get(filter_profile, {}).get("name", "Unknown"),
        "input_payload": payload,
        "waf_blocked": False,
        "waf_matched_rule": None,
        "constructed_query": "",
        "results": [],
        "row_count": 0,
        "error": None,
        "bypassed": False,
        "flag": None,
        "execution_time_ms": 0.0,
        "explanation": ""
    }

    # Step 1: WAF Inspection
    rule = WAF_RULES.get(filter_profile, WAF_RULES["none"])
    if rule["regex"] and re.search(rule["regex"], payload):
        result["waf_blocked"] = True
        result["waf_matched_rule"] = f"Detected pattern matching: {rule['regex']}"
        result["explanation"] = f"WAF Blocked: {rule['description']}"
        log_audit_query("Module 4: WAF Sandbox", f"BLOCKED_PAYLOAD: {payload}", False, "WAF_BLOCKED", result["explanation"], client_ip)
        result["execution_time_ms"] = round((time.time() - start_time) * 1000, 2)
        return result

    # Step 2: Execution against MySQL if WAF allowed or bypassed
    conn = None
    try:
        conn = get_db_connection()
        with conn.cursor() as cursor:
            if mode == "vulnerable":
                # Insecure query with the allowed/bypassed payload
                if payload.startswith("0x"):
                    query = f"SELECT id, username, full_name, email, role, api_key FROM users WHERE username = {payload}"
                else:
                    query = f"SELECT id, username, full_name, email, role, api_key FROM users WHERE username = '{payload}'"

                result["constructed_query"] = query
                cursor.execute(query)
                raw_rows = cursor.fetchall()

                result["results"] = raw_rows
                result["row_count"] = len(raw_rows)
                result["success"] = True

                # Check if filter was evaded with an active injection construct
                evasion_techniques = [
                    filter_profile == "spaces" and ("/**/" in payload or "\t" in payload),
                    filter_profile == "keywords" and bool(re.search(r"union|select", payload, re.IGNORECASE)),
                    filter_profile == "quotes" and "0x" in payload
                ]

                if any(evasion_techniques) and len(raw_rows) > 0:
                    result["bypassed"] = True
                    result["flag"] = "FLAG{mysql_waf_filter_bypass_mastered}"
                    result["explanation"] = (
                        f"WAF Filter Evaded Successfully! The payload bypassed the {rule['name']} rule and executed "
                        "valid SQL syntax inside the MySQL engine, returning database records."
                    )
                else:
                    result["explanation"] = f"Query passed the WAF inspection and executed in MySQL (Rows returned: {len(raw_rows)})."

                log_audit_query("Module 4: WAF Sandbox", query, False, "SUCCESS", None, client_ip)

            else:
                # SECURE MODE: Parameterized query
                query = "SELECT id, username, full_name, email, role, api_key FROM users WHERE username = %s"
                result["constructed_query"] = f"PREPARED: SELECT id, username, full_name, email, role, api_key FROM users WHERE username = ? [PARAMS: ({payload!r})]"
                cursor.execute(query, (payload,))
                raw_rows = cursor.fetchall()

                result["results"] = raw_rows
                result["row_count"] = len(raw_rows)
                result["success"] = True
                result["explanation"] = (
                    "Prepared statements separate code compilation from data evaluation. "
                    "Regardless of WAF filters, parameterization provides airtight mathematical defense."
                )

                log_audit_query("Module 4: WAF Sandbox", query, True, "SUCCESS", None, client_ip)

    except pymysql.MySQLError as err:
        code, msg = err.args
        result["error"] = f"MySQL Error [{code}]: {msg}"
        log_audit_query("Module 4: WAF Sandbox", result.get("constructed_query", ""), mode == "secure", "MYSQL_ERROR", result["error"], client_ip)
    except Exception as e:
        result["error"] = str(e)
    finally:
        if conn:
            conn.close()

    result["execution_time_ms"] = round((time.time() - start_time) * 1000, 2)
    return result

# ---------------------------------------------------------
# 3. Static Code Analysis (SAST) Query Auditor
# ---------------------------------------------------------

VULN_PATTERNS = [
    {
        "type": "Python f-string Concatenation",
        "regex": r'f["\']\s*(?:SELECT|INSERT|UPDATE|DELETE).*?\{.+?\}.*?["\']',
        "severity": "CRITICAL",
        "cwe": "CWE-89: SQL Injection",
        "description": "User input is directly interpolated into a dynamic SQL string using Python f-strings."
    },
    {
        "type": "Legacy % Operator Formatting",
        "regex": r'["\']\s*(?:SELECT|INSERT|UPDATE|DELETE).*?%s.*?["\']\s*%\s*\(?.+?\)?',
        "severity": "CRITICAL",
        "cwe": "CWE-89: SQL Injection",
        "description": "SQL query uses string formatting (%) rather than parameterized query bindings."
    },
    {
        "type": "String Addition (+) Concatenation",
        "regex": r'["\']\s*(?:SELECT|INSERT|UPDATE|DELETE).*?["\']\s*\+\s*[a-zA-Z_]\w*',
        "severity": "HIGH",
        "cwe": "CWE-89: SQL Injection",
        "description": "SQL query concatenates untrusted string variables using the addition (+) operator."
    },
    {
        "type": "str.format() Interpolation",
        "regex": r'["\']\s*(?:SELECT|INSERT|UPDATE|DELETE).*?\{.*?\}\s*["\']\.format\(',
        "severity": "HIGH",
        "cwe": "CWE-89: SQL Injection",
        "description": "SQL query uses .format() interpolation without database driver parameter markers."
    }
]

def audit_sql_code(code_snippet: str) -> Dict[str, Any]:
    """Performs static pattern analysis on SQL and Python code snippets.

    Args:
        code_snippet: Source code text provided by the developer.

    Returns:
        Dictionary containing detected vulnerabilities, line numbers, and auto-fixes.
    """
    lines = code_snippet.splitlines()
    findings: List[Dict[str, Any]] = []

    for line_num, line in enumerate(lines, start=1):
        for rule in VULN_PATTERNS:
            match = re.search(rule["regex"], line, re.IGNORECASE)
            if match:
                findings.append({
                    "line_number": line_num,
                    "matched_code": line.strip(),
                    "vulnerability_type": rule["type"],
                    "severity": rule["severity"],
                    "cwe": rule["cwe"],
                    "description": rule["description"]
                })

    is_vulnerable = len(findings) > 0
    auto_remediated_code = generate_auto_fix(code_snippet) if is_vulnerable else code_snippet

    return {
        "is_vulnerable": is_vulnerable,
        "total_findings": len(findings),
        "findings": findings,
        "auto_remediated_code": auto_remediated_code,
        "scanned_lines": len(lines)
    }

def generate_auto_fix(code_snippet: str) -> str:
    """Generates parameterized auto-fix code snippet from vulnerable patterns.

    Args:
        code_snippet: Vulnerable input code.

    Returns:
        Remediated Python/SQL parameterized code.
    """
    fixed_lines = []
    for line in code_snippet.splitlines():
        # Check f-strings
        f_match = re.search(r'f["\'](SELECT.*?WHERE\s+\w+\s*=\s*)[\'"]?\{(\w+)\}[\'"]?(.*?)["\']', line, re.IGNORECASE)
        if f_match:
            prefix = f_match.group(1)
            var_name = f_match.group(2)
            suffix = f_match.group(3)
            fixed_line = (
                f'# [AUTO-REMEDIATED: Prepared Statement]\n'
                f'query = "{prefix}%s{suffix}"\n'
                f'cursor.execute(query, ({var_name},))'
            )
            fixed_lines.append(fixed_line)
            continue

        # Check plus concat
        plus_match = re.search(r'["\'](SELECT.*?WHERE\s+\w+\s*=\s*)[\'"]?\s*\+\s*(\w+)', line, re.IGNORECASE)
        if plus_match:
            prefix = plus_match.group(1)
            var_name = plus_match.group(2)
            fixed_line = (
                f'# [AUTO-REMEDIATED: Parameterized Binding]\n'
                f'query = "{prefix}%s"\n'
                f'cursor.execute(query, ({var_name},))'
            )
            fixed_lines.append(fixed_line)
            continue

        fixed_lines.append(line)

    return "\n".join(fixed_lines)

# ---------------------------------------------------------
# 4. Security Audit & Compliance Report Generator
# ---------------------------------------------------------

def generate_security_audit_report() -> Dict[str, Any]:
    """Compiles system-wide audit telemetry into an OWASP-compliant security report.

    Returns:
        Structured compliance assessment dictionary.
    """
    conn = None
    telemetry_summary = {
        "total_queries_logged": 0,
        "vulnerable_executions": 0,
        "parameterized_executions": 0,
        "mysql_errors_caught": 0,
        "waf_blocks": 0,
        "modules_tested": []
    }

    try:
        conn = get_db_connection()
        with conn.cursor() as cursor:
            cursor.execute("SELECT COUNT(*) AS total FROM `query_audit_logs`")
            row = cursor.fetchone()
            if row:
                telemetry_summary["total_queries_logged"] = row["total"]

            cursor.execute("SELECT COUNT(*) AS total FROM `query_audit_logs` WHERE is_parameterized = TRUE")
            row = cursor.fetchone()
            if row:
                telemetry_summary["parameterized_executions"] = row["total"]

            telemetry_summary["vulnerable_executions"] = (
                telemetry_summary["total_queries_logged"] - telemetry_summary["parameterized_executions"]
            )

            cursor.execute("SELECT COUNT(*) AS total FROM `query_audit_logs` WHERE execution_status = 'MYSQL_ERROR'")
            row = cursor.fetchone()
            if row:
                telemetry_summary["mysql_errors_caught"] = row["total"]

            cursor.execute("SELECT DISTINCT `lab_module` FROM `query_audit_logs`")
            modules = [m["lab_module"] for m in cursor.fetchall()]
            telemetry_summary["modules_tested"] = modules

    except Exception as e:
        print(f"[!] Report telemetry error: {e}")
    finally:
        if conn:
            conn.close()

    return {
        "assessment_title": "SQL Injection Assessment & Mitigation Verification Report",
        "standard_alignment": [
            "OWASP Top 10 - A03:2021 (Injection)",
            "CWE-89: Improper Neutralization of Special Elements used in an SQL Command",
            "PCI-DSS v4.0 Requirement 6.2.4 (Injection Flaw Mitigation)",
            "NIST SP 800-53 Rev. 5: SI-10 (Information Input Validation)"
        ],
        "telemetry": telemetry_summary,
        "posture_score": "PASS (Remediated)" if telemetry_summary["parameterized_executions"] > 0 else "AUDIT_REQUIRED",
        "generated_at": time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime()),
        "key_remediations": [
            "Mandate parameterized prepared statements across all data access layers.",
            "Enforce strict input allow-lists for structural parameters (table/column identifiers).",
            "Disable verbose MySQL engine error output to untrusted clients.",
            "Deploy defense-in-depth WAF rules with signature inspection and anomaly baselining."
        ]
    }
