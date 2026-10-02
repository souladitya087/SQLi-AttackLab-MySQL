import time
import pymysql
from database import get_db_connection, log_audit_query

def analyze_query_tokens(raw_query):
    """
    Educational query token analyzer:
    Highlights dangerous SQL keywords and injection constructs.
    """
    suspicious_tokens = ["OR", "AND", "--", "#", "/*", "*/", "UNION", "SELECT", "1=1", "TRUE", "'='"]
    tokens = []
    for word in raw_query.split():
        clean_word = word.strip("();'\"")
        is_highlighted = clean_word.upper() in suspicious_tokens or any(sym in word for sym in ["--", "#", "/*", "*/", "'="])
        tokens.append({
            "text": word,
            "is_injected_keyword": is_highlighted
        })
    return tokens

def execute_auth_attempt(username, password, scenario="tautology", mode="vulnerable", client_ip="127.0.0.1"):
    """
    Executes authentication query against MySQL based on scenario and mode.
    Returns detailed diagnostics, raw query, execution status, and educational breakdown.
    """
    start_time = time.time()
    result = {
        "success": False,
        "scenario": scenario,
        "mode": mode,
        "input_username": username,
        "input_password": password,
        "constructed_query": "",
        "query_tokens": [],
        "user_profile": None,
        "error": None,
        "bypassed": False,
        "execution_time_ms": 0.0,
        "flag": None,
        "explanation": ""
    }

    conn = None
    try:
        conn = get_db_connection()
        with conn.cursor() as cursor:
            if mode == "vulnerable":
                # Construct query depending on scenario
                if scenario == "tautology":
                    # Classic inline concatenation: SELECT * FROM users WHERE username = '...' AND password = '...'
                    query = f"SELECT id, username, full_name, email, role, api_key FROM users WHERE username = '{username}' AND password = '{password}' LIMIT 1"
                    result["constructed_query"] = query
                    result["explanation"] = (
                        "Vulnerable concatenation allows injecting quote delimiters (') to break out of the string literal "
                        "and append an OR condition (e.g., OR 1=1) that forces the WHERE clause to evaluate to TRUE."
                    )
                elif scenario == "comment_truncation":
                    # Single quote with comment: SELECT * FROM users WHERE username = '...' AND password = '...'
                    query = f"SELECT id, username, full_name, email, role, api_key FROM users WHERE username = '{username}' AND password = '{password}' LIMIT 1"
                    result["constructed_query"] = query
                    result["explanation"] = (
                        "Using MySQL inline comments (--  or #) terminates the remainder of the SQL statement, "
                        "discarding the entire password verification clause."
                    )
                elif scenario == "parenthesized":
                    # Query wrapped in parentheses: SELECT * FROM users WHERE (username = '...') AND (password = '...')
                    query = f"SELECT id, username, full_name, email, role, api_key FROM users WHERE (username = '{username}') AND (password = '{password}') LIMIT 1"
                    result["constructed_query"] = query
                    result["explanation"] = (
                        "Parenthesized queries require balancing brackets (e.g. ') OR ('1'='1). "
                        "If parentheses are unbalanced, MySQL throws a syntax error."
                    )
                else:
                    query = f"SELECT id, username, full_name, email, role, api_key FROM users WHERE username = '{username}' AND password = '{password}' LIMIT 1"
                    result["constructed_query"] = query
                    result["explanation"] = "Standard dynamic query execution."

                # Execute raw vulnerable query in MySQL
                cursor.execute(query)
                user = cursor.fetchone()

                if user:
                    result["success"] = True
                    result["user_profile"] = user
                    # Check if authentication was bypassed (no real password supplied or injection characters present)
                    has_injection_chars = any(c in username for c in ["'", "--", "#", "/*", " OR ", " or "])
                    if has_injection_chars:
                        result["bypassed"] = True
                        if user["role"] == "admin":
                            result["flag"] = "FLAG{mysql_auth_tautology_bypass_mastered}"

                log_audit_query("Module 1: Auth Bypass", query, False, "SUCCESS" if user else "AUTH_FAIL", None, client_ip)

            else:
                # SECURE MODE: Parameterized Prepared Statements
                query = "SELECT id, username, full_name, email, role, api_key FROM users WHERE username = %s AND password = %s LIMIT 1"
                result["constructed_query"] = f"PREPARED: SELECT id, username, full_name, email, role, api_key FROM users WHERE username = ? AND password = ? [PARAMS: ({username!r}, {password!r})]"
                result["explanation"] = (
                    "Prepared statements pre-compile the SQL statement structure on the MySQL server. "
                    "User input is transmitted separately in a data channel and bound strictly as literal values, "
                    "preventing input from ever altering the SQL parser's syntax tree."
                )

                cursor.execute(query, (username, password))
                user = cursor.fetchone()

                if user:
                    result["success"] = True
                    result["user_profile"] = user
                    result["bypassed"] = False
                else:
                    result["success"] = False
                    result["bypassed"] = False

                log_audit_query("Module 1: Auth Bypass", query, True, "SUCCESS" if user else "AUTH_FAIL", None, client_ip)

    except pymysql.MySQLError as err:
        error_code, error_msg = err.args
        result["error"] = f"MySQL Error [{error_code}]: {error_msg}"
        log_audit_query("Module 1: Auth Bypass", result.get("constructed_query", ""), mode == "secure", "MYSQL_ERROR", result["error"], client_ip)
    except Exception as e:
        result["error"] = f"System Error: {str(e)}"
    finally:
        if conn:
            conn.close()

    result["execution_time_ms"] = round((time.time() - start_time) * 1000, 2)
    result["query_tokens"] = analyze_query_tokens(result["constructed_query"])
    return result
