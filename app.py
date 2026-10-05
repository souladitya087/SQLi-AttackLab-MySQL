from flask import Flask, render_template, request, jsonify
from config import Config
from database import get_recent_audit_logs
from modules.auth_bypass import execute_auth_attempt
from modules.union_based import execute_catalog_search
from modules.error_blind import execute_error_blind_query
from modules.evasion_audit import (
    save_user_profile,
    execute_profile_audit_report,
    execute_waf_sandbox_query,
    audit_sql_code,
    generate_security_audit_report
)

app = Flask(__name__)
app.config.from_object(Config)

@app.route("/")
def index():
    """Main Dashboard with security modules overview and status."""
    return render_template("index.html")

@app.route("/lab/auth-bypass")
def auth_bypass_lab():
    """Module 1: Authentication Bypass Exploitation & Query Visualizer Lab."""
    return render_template("auth_bypass.html")

@app.route("/lab/union-based")
def union_based_lab():
    """Module 2: Union-Based SQLi & Schema Enumeration Laboratory."""
    return render_template("union_based.html")

@app.route("/lab/error-blind")
def error_blind_lab():
    """Module 3: Error-Based & Blind/Time-Based SQLi Laboratory."""
    return render_template("error_blind.html")

@app.route("/lab/evasion-audit")
def evasion_audit_lab():
    """Module 4: Filter Evasion & SAST Remediation Toolkit."""
    return render_template("evasion_audit.html")

@app.route("/api/auth/test", methods=["POST"])
def api_auth_test():
    """API endpoint to execute an authentication test against MySQL."""
    data = request.get_json() or {}
    username = data.get("username", "")
    password = data.get("password", "")
    scenario = data.get("scenario", "tautology")
    mode = data.get("mode", "vulnerable")
    client_ip = request.remote_addr or "127.0.0.1"

    result = execute_auth_attempt(
        username=username,
        password=password,
        scenario=scenario,
        mode=mode,
        client_ip=client_ip
    )
    return jsonify(result)

@app.route("/api/union/search", methods=["POST"])
def api_union_search():
    """API endpoint to execute a catalog search/UNION injection test against MySQL."""
    data = request.get_json() or {}
    category = data.get("category", "Hardware")
    scenario = data.get("scenario", "column_counting")
    mode = data.get("mode", "vulnerable")
    client_ip = request.remote_addr or "127.0.0.1"

    result = execute_catalog_search(
        category_input=category,
        scenario=scenario,
        mode=mode,
        client_ip=client_ip
    )
    return jsonify(result)

@app.route("/api/error-blind/query", methods=["POST"])
def api_error_blind_query():
    """API endpoint to execute an error-based or blind inference query against MySQL."""
    data = request.get_json() or {}
    username = data.get("username", "admin")
    scenario = data.get("scenario", "xpath_error")
    mode = data.get("mode", "vulnerable")
    client_ip = request.remote_addr or "127.0.0.1"

    result = execute_error_blind_query(
        username_input=username,
        scenario=scenario,
        mode=mode,
        client_ip=client_ip
    )
    return jsonify(result)

@app.route("/api/profile/save", methods=["POST"])
def api_profile_save():
    """API endpoint to save a user profile (First-Order phase)."""
    data = request.get_json() or {}
    username = data.get("username", "test_user")
    display_name = data.get("display_name", "Test User")
    bio = data.get("bio", "Regular user profile.")
    res = save_user_profile(username, display_name, bio)
    return jsonify(res)

@app.route("/api/profile/audit", methods=["POST"])
def api_profile_audit():
    """API endpoint to trigger security audit report (Second-Order trigger phase)."""
    data = request.get_json() or {}
    target_username = data.get("username", "john_doe")
    mode = data.get("mode", "vulnerable")
    client_ip = request.remote_addr or "127.0.0.1"
    res = execute_profile_audit_report(target_username, mode, client_ip)
    return jsonify(res)

@app.route("/api/waf/test", methods=["POST"])
def api_waf_test():
    """API endpoint to test payload against simulated WAF and MySQL."""
    data = request.get_json() or {}
    payload = data.get("payload", "admin' -- ")
    filter_profile = data.get("filter_profile", "spaces")
    mode = data.get("mode", "vulnerable")
    client_ip = request.remote_addr or "127.0.0.1"
    res = execute_waf_sandbox_query(payload, filter_profile, mode, client_ip)
    return jsonify(res)

@app.route("/api/sast/audit", methods=["POST"])
def api_sast_audit():
    """API endpoint for static query code analysis and auto-remediation."""
    data = request.get_json() or {}
    code_snippet = data.get("code_snippet", "")
    res = audit_sql_code(code_snippet)
    return jsonify(res)

@app.route("/api/compliance/report", methods=["GET"])
def api_compliance_report():
    """API endpoint to compile system-wide security audit and compliance telemetry."""
    res = generate_security_audit_report()
    return jsonify(res)

@app.route("/api/audit-logs", methods=["GET"])
def api_audit_logs():
    """API endpoint to fetch recent executed SQL queries from MySQL query_audit_logs."""
    logs = get_recent_audit_logs(limit=25)
    # Serialize datetime and timestamp objects to string
    for log in logs:
        if "timestamp" in log and log["timestamp"]:
            log["timestamp"] = str(log["timestamp"])
    return jsonify({"logs": logs})

if __name__ == "__main__":
    print("[*] Starting SQLi Attack Lab Server on http://127.0.0.1:5000")
    app.run(host="127.0.0.1", port=5000, debug=True)
