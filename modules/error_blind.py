"""Module 3: Error-Based & Blind/Time-Based SQL Injection Attacks.

Provides educational demonstration of:
1. XPath syntax error exploitation via MySQL XML functions (EXTRACTVALUE, UPDATEXML).
2. Boolean-based blind inference utilizing character slicing (SUBSTRING, ASCII) and truth oracles.
3. Time-based side-channel inference leveraging conditional latency (SLEEP, BENCHMARK).
4. Response latency profiling and visual threshold analysis.
5. Defense and remediation through parameterized prepared statements.
"""

import re
import time
from typing import Any, Dict, List, Optional
import pymysql
from database import get_db_connection, log_audit_query

SUSPICIOUS_TOKENS = {
    "EXTRACTVALUE", "UPDATEXML", "CONCAT", "0X7E", "SLEEP", "BENCHMARK",
    "SUBSTRING", "MID", "ASCII", "IF", "WHERE", "AND", "OR", "SELECT",
    "FROM", "INFORMATION_SCHEMA", "SYSTEM_SECRETS", "USERS", "DATABASE()",
    "VERSION()", "USER()", "@@VERSION", "LIMIT"
}

def analyze_error_blind_tokens(raw_query: str) -> List[Dict[str, Any]]:
    """Analyzes SQL query tokens to highlight structural injection keywords.

    Args:
        raw_query: Raw SQL query string sent to MySQL.

    Returns:
        List of dictionaries with token text and injection keyword boolean.
    """
    tokens: List[Dict[str, Any]] = []
    for word in raw_query.split():
        clean_word = word.strip("();,'\"").upper()
        is_highlighted = (
            clean_word in SUSPICIOUS_TOKENS
            or any(sym in word for sym in ["--", "#", "/*", "*/", "@@", "0x7e", "0X7E"])
        )
        tokens.append({
            "text": word,
            "is_injected_keyword": is_highlighted
        })
    return tokens

def extract_xpath_leak(error_message: str) -> Optional[str]:
    """Parses leaked payload data from MySQL XPath syntax error strings.

    Args:
        error_message: Error string returned by MySQL (e.g. XPATH syntax error: '~...~').

    Returns:
        Extracted data string between delimiter characters if found, else None.
    """
    match = re.search(r"XPATH syntax error:\s*'~?([^'~]+)~?'?", error_message, re.IGNORECASE)
    if match:
        return match.group(1).strip()
    return None

def execute_error_blind_query(
    username_input: str,
    scenario: str = "xpath_error",
    mode: str = "vulnerable",
    client_ip: str = "127.0.0.1"
) -> Dict[str, Any]:
    """Executes a user directory lookup query with diagnostic telemetry for inference attacks.

    Args:
        username_input: User-supplied username or SQL injection payload.
        scenario: Selected demonstration scenario ('xpath_error', 'boolean_blind', 'time_blind', 'latency_profiler').
        mode: Engine mode ('vulnerable' or 'secure').
        client_ip: Client IP address for query audit logging.

    Returns:
        Dictionary containing execution metadata, results, and pedagogical explanations.
    """
    start_time = time.time()
    result: Dict[str, Any] = {
        "success": False,
        "scenario": scenario,
        "mode": mode,
        "input_username": username_input,
        "constructed_query": "",
        "query_tokens": [],
        "results": [],
        "row_count": 0,
        "boolean_state": False,
        "user_found": False,
        "execution_time_ms": 0.0,
        "sleep_detected": False,
        "error": None,
        "mysql_error_code": None,
        "leaked_data": None,
        "exfiltrated": False,
        "flag": None,
        "explanation": ""
    }

    conn = None
    try:
        conn = get_db_connection()
        with conn.cursor() as cursor:
            if mode == "vulnerable":
                # Insecure dynamic concatenation
                query = (
                    f"SELECT id, username, full_name, email, role, created_at "
                    f"FROM users "
                    f"WHERE username = '{username_input}'"
                )
                result["constructed_query"] = query
                cursor.execute(query)
                raw_rows = cursor.fetchall()

                # Process rows and format timestamps for JSON serialization
                processed_rows: List[Dict[str, Any]] = []
                for row in raw_rows:
                    cleaned_row: Dict[str, Any] = {}
                    for k, v in row.items():
                        if hasattr(v, "isoformat"):
                            cleaned_row[k] = v.isoformat()
                        else:
                            cleaned_row[k] = v
                    processed_rows.append(cleaned_row)

                result["results"] = processed_rows
                result["row_count"] = len(processed_rows)
                result["boolean_state"] = len(processed_rows) > 0
                result["user_found"] = len(processed_rows) > 0
                result["success"] = True

                # Generate scenario explanations
                if scenario == "boolean_blind":
                    if result["boolean_state"]:
                        result["explanation"] = (
                            "Boolean Oracle evaluated to TRUE: The injected predicate evaluated as true, "
                            "allowing MySQL to successfully match and return the user record. "
                            "An attacker deduces that their tested character or condition is valid."
                        )
                    else:
                        result["explanation"] = (
                            "Boolean Oracle evaluated to FALSE: The injected condition evaluated as false, "
                            "causing MySQL to return zero rows. In a boolean blind attack, the attacker "
                            "now knows their tested condition does not match."
                        )
                elif scenario in ["time_blind", "latency_profiler"]:
                    result["explanation"] = (
                        "Query completed execution. If an active SLEEP() payload evaluated to true, "
                        "execution latency reflects the sleep duration; otherwise it returns in standard baseline time."
                    )
                else:
                    result["explanation"] = (
                        f"Standard user lookup executed for username '{username_input}'. "
                        f"Returned {len(processed_rows)} record(s)."
                    )

                log_audit_query(
                    "Module 3: Error & Blind Inference",
                    query,
                    False,
                    "SUCCESS",
                    None,
                    client_ip
                )

            else:
                # SECURE MODE: Parameterized Prepared Statements
                query = (
                    "SELECT id, username, full_name, email, role, created_at "
                    "FROM users "
                    "WHERE username = %s"
                )
                result["constructed_query"] = (
                    f"PREPARED: SELECT id, username, full_name, email, role, created_at "
                    f"FROM users WHERE username = ? [PARAMS: ({username_input!r})]"
                )

                cursor.execute(query, (username_input,))
                raw_rows = cursor.fetchall()

                processed_rows = []
                for row in raw_rows:
                    cleaned_row = {}
                    for k, v in row.items():
                        if hasattr(v, "isoformat"):
                            cleaned_row[k] = v.isoformat()
                        else:
                            cleaned_row[k] = v
                    processed_rows.append(cleaned_row)

                result["results"] = processed_rows
                result["row_count"] = len(processed_rows)
                result["boolean_state"] = len(processed_rows) > 0
                result["user_found"] = len(processed_rows) > 0
                result["success"] = True
                result["explanation"] = (
                    "Prepared statements treat user input strictly as a literal data parameter. "
                    "Injected functions (EXTRACTVALUE, UPDATEXML, SLEEP, SUBSTRING) are never parsed "
                    "by the MySQL syntax compiler, completely neutralizing error disclosure, "
                    "boolean inference, and time-based side-channel attacks."
                )

                log_audit_query(
                    "Module 3: Error & Blind Inference",
                    query,
                    True,
                    "SUCCESS",
                    None,
                    client_ip
                )

    except pymysql.MySQLError as err:
        error_code, error_msg = err.args if len(err.args) >= 2 else (0, str(err))
        result["mysql_error_code"] = error_code
        result["error"] = f"MySQL Error [{error_code}]: {error_msg}"
        result["success"] = False

        if error_code == 1105:
            # XPath syntax error disclosure
            leaked_val = extract_xpath_leak(error_msg)
            result["leaked_data"] = leaked_val
            result["explanation"] = (
                "MySQL Error 1105 (XPath syntax error): The database attempted to parse the second argument "
                "of EXTRACTVALUE() or UPDATEXML() as an XPath expression. Because it begins with a non-XPath "
                "delimiter (0x7e / '~'), MySQL throws a syntax error containing the evaluated subquery result! "
                "This leaks confidential data directly inside the returned error message."
            )
            if leaked_val:
                if any(flag_indicator in leaked_val for flag_indicator in ["FLAG{", "tok_sec_", "CRITICAL"]):
                    result["exfiltrated"] = True
                    result["flag"] = "FLAG{mysql_blind_and_error_inference_pwned}"
        elif error_code == 1064:
            result["explanation"] = (
                f"MySQL Error 1064 (Syntax Error): The query string has unbalanced quotes or invalid SQL syntax: {error_msg}"
            )
        else:
            result["explanation"] = f"MySQL query failed during execution: {error_msg}"

        log_audit_query(
            "Module 3: Error & Blind Inference",
            result.get("constructed_query", ""),
            mode == "secure",
            "MYSQL_ERROR",
            result["error"],
            client_ip
        )
    except Exception as e:
        result["error"] = f"Application Error: {str(e)}"
        result["success"] = False
    finally:
        if conn:
            conn.close()

    elapsed_ms = round((time.time() - start_time) * 1000, 2)
    result["execution_time_ms"] = elapsed_ms
    result["sleep_detected"] = elapsed_ms >= 1000.0
    result["query_tokens"] = analyze_error_blind_tokens(result["constructed_query"])
    return result
