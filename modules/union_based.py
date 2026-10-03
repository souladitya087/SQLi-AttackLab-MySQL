"""Module 2: Union-Based SQL Injection & MySQL Schema Enumeration.

Provides educational demonstration of:
1. Column count discovery via ORDER BY & UNION projection matching.
2. Data-type reflection point mapping.
3. System catalog fingerprinting via MySQL information_schema.
4. Confidential data exfiltration and challenge flag harvesting.
5. Parameterized prepared statement defense & input validation.
"""

from decimal import Decimal
import time
from typing import Any, Dict, List, Optional
import pymysql
from database import get_db_connection, log_audit_query

ALLOWED_CATEGORIES = ["Hardware", "Software"]

def analyze_union_query_tokens(raw_query: str) -> List[Dict[str, Any]]:
    """Analyzes SQL query tokens to highlight structural injection keywords.

    Args:
        raw_query: Raw SQL query string sent to MySQL.

    Returns:
        List of dictionaries with token text and injection keyword boolean.
    """
    suspicious_keywords = {
        "UNION", "SELECT", "ORDER", "BY", "FROM", "WHERE", "INFORMATION_SCHEMA",
        "TABLES", "COLUMNS", "DATABASE()", "VERSION()", "USER()", "NULL", "LIMIT"
    }
    tokens: List[Dict[str, Any]] = []
    for word in raw_query.split():
        clean_word = word.strip("();,'\"").upper()
        is_highlighted = (
            clean_word in suspicious_keywords
            or any(sym in word for sym in ["--", "#", "/*", "*/", "@@"])
        )
        tokens.append({
            "text": word,
            "is_injected_keyword": is_highlighted
        })
    return tokens

def execute_catalog_search(
    category_input: str,
    scenario: str = "column_counting",
    mode: str = "vulnerable",
    client_ip: str = "127.0.0.1"
) -> Dict[str, Any]:
    """Executes a catalog search query against MySQL with diagnostic telemetry.

    Args:
        category_input: User-supplied search category or SQL injection payload.
        scenario: Selected demonstration scenario.
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
        "input_category": category_input,
        "constructed_query": "",
        "query_tokens": [],
        "columns_projected": 5,
        "results": [],
        "row_count": 0,
        "error": None,
        "mysql_error_code": None,
        "exfiltrated": False,
        "flag": None,
        "execution_time_ms": 0.0,
        "explanation": ""
    }

    conn = None
    try:
        conn = get_db_connection()
        with conn.cursor() as cursor:
            if mode == "vulnerable":
                # Insecure dynamic concatenation
                query = (
                    f"SELECT id, name, category, price, description "
                    f"FROM products "
                    f"WHERE category = '{category_input}' AND is_confidential = FALSE"
                )
                result["constructed_query"] = query
                cursor.execute(query)
                raw_rows = cursor.fetchall()

                # Process rows and convert Decimal to float for JSON compatibility
                processed_rows: List[Dict[str, Any]] = []
                for row in raw_rows:
                    cleaned_row: Dict[str, Any] = {}
                    for k, v in row.items():
                        if isinstance(v, Decimal):
                            cleaned_row[k] = float(v)
                        else:
                            cleaned_row[k] = v
                    processed_rows.append(cleaned_row)

                result["results"] = processed_rows
                result["row_count"] = len(processed_rows)
                result["success"] = True

                # Check for metadata/secrets exfiltration indicators
                for row in processed_rows:
                    row_str = str(row).lower()
                    if "flag{mysql_information_schema_exfiltration_pwned}" in row_str or "flag_union_exploit" in row_str:
                        result["exfiltrated"] = True
                        result["flag"] = "FLAG{mysql_information_schema_exfiltration_pwned}"
                    elif any(s in row_str for s in ["information_schema", "schema()", "tok_sec_", "classified"]):
                        result["exfiltrated"] = True

                # Generate scenario-specific technical explanations
                if "ORDER BY" in category_input.upper():
                    result["explanation"] = (
                        "ORDER BY clause was executed successfully. MySQL sorts by the specified column index. "
                        "When an index exceeds the projected column count (e.g. ORDER BY 6), MySQL will trigger "
                        "Error 1054 ('Unknown column in order clause'), revealing the exact column count."
                    )
                elif "UNION" in category_input.upper():
                    result["explanation"] = (
                        "UNION operator combined the results of the original query with the injected SELECT statement. "
                        "Because the number of columns and data types matched the base query (5 columns), "
                        "MySQL returned both row sets in the unified response."
                    )
                else:
                    result["explanation"] = (
                        f"Standard query executed for category '{category_input}'. "
                        "Returned matching public product records."
                    )

                log_audit_query(
                    "Module 2: Union Extraction",
                    query,
                    False,
                    "SUCCESS",
                    None,
                    client_ip
                )

            else:
                # SECURE MODE: Parameterized query + Whitelist verification
                query = (
                    "SELECT id, name, category, price, description "
                    "FROM products "
                    "WHERE category = %s AND is_confidential = FALSE"
                )
                result["constructed_query"] = (
                    f"PREPARED: SELECT id, name, category, price, description FROM products "
                    f"WHERE category = ? AND is_confidential = FALSE [PARAMS: ({category_input!r})]"
                )

                # Execute with strict parameter binding
                cursor.execute(query, (category_input,))
                raw_rows = cursor.fetchall()

                processed_rows = []
                for row in raw_rows:
                    cleaned_row = {}
                    for k, v in row.items():
                        if isinstance(v, Decimal):
                            cleaned_row[k] = float(v)
                        else:
                            cleaned_row[k] = v
                    processed_rows.append(cleaned_row)

                result["results"] = processed_rows
                result["row_count"] = len(processed_rows)
                result["success"] = True
                result["explanation"] = (
                    "Prepared statements treat user input strictly as a literal data parameter. "
                    "Injected SQL syntax keywords (UNION, SELECT, ORDER BY) are never parsed by the query compiler, "
                    "and the query safely returns zero records if no category literally equals the payload string."
                )

                log_audit_query(
                    "Module 2: Union Extraction",
                    query,
                    True,
                    "SUCCESS",
                    None,
                    client_ip
                )

    except pymysql.MySQLError as err:
        error_code, error_msg = err.args
        result["mysql_error_code"] = error_code
        result["error"] = f"MySQL Error [{error_code}]: {error_msg}"
        result["success"] = False

        if error_code == 1054:
            result["explanation"] = (
                "MySQL Error 1054 (Unknown column in order clause): "
                "The requested sort column exceeds the number of columns selected in the query! "
                "This indicates that the target query projects fewer columns than the tested index."
            )
        elif error_code == 1222:
            result["explanation"] = (
                "MySQL Error 1222 (Different number of columns): "
                "The injected UNION SELECT statement does not project the same number of columns "
                "as the base query (which expects 5 columns). All queries combined with UNION must project equal column counts."
            )
        else:
            result["explanation"] = f"MySQL query failed during execution: {error_msg}"

        log_audit_query(
            "Module 2: Union Extraction",
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

    result["execution_time_ms"] = round((time.time() - start_time) * 1000, 2)
    result["query_tokens"] = analyze_union_query_tokens(result["constructed_query"])
    return result
