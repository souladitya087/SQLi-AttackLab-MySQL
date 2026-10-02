import pymysql
from pymysql.cursors import DictCursor
from config import Config

def get_db_connection():
    """Returns a new PyMySQL connection to the target lab database."""
    return pymysql.connect(
        host=Config.DB_HOST,
        port=Config.DB_PORT,
        user=Config.DB_USER,
        password=Config.DB_PASS,
        database=Config.DB_NAME,
        cursorclass=DictCursor,
        autocommit=True
    )

def log_audit_query(module_name, query_str, is_parameterized, status, error_msg, client_ip="127.0.0.1"):
    """Logs the executed query into the security audit log table."""
    try:
        conn = get_db_connection()
        with conn.cursor() as cursor:
            cursor.execute("""
                INSERT INTO `query_audit_logs` 
                (`lab_module`, `executed_query`, `is_parameterized`, `execution_status`, `error_message`, `client_ip`)
                VALUES (%s, %s, %s, %s, %s, %s)
            """, (module_name, query_str, is_parameterized, status, error_msg, client_ip))
        conn.close()
    except Exception as e:
        print(f"[!] Failed to log audit query: {e}")

def get_recent_audit_logs(limit=20):
    """Retrieves recent executed queries for the real-time query debugger console."""
    try:
        conn = get_db_connection()
        with conn.cursor() as cursor:
            cursor.execute("SELECT * FROM `query_audit_logs` ORDER BY `id` DESC LIMIT %s", (limit,))
            rows = cursor.fetchall()
        conn.close()
        return rows
    except Exception as e:
        print(f"[!] Failed to fetch audit logs: {e}")
        return []
