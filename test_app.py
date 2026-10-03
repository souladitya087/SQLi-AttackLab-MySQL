"""Comprehensive automated test suite for SQLi-AttackLab.

Verifies:
- HTTP route availability for all lab views and REST endpoints.
- Module 1 (Authentication Bypass) offensive vectors and prepared defenses.
- Module 2 (Union Extraction) column counting, schema dumping, flag harvesting, and remediation.
- MySQL query audit logging telemetry.
"""

from typing import Any, Dict
from app import app

def run_all_tests() -> None:
    """Executes end-to-end integration and API test assertions."""
    client = app.test_client()

    print("[*] Running Module 1 & 2 Verification Suite...\n")

    # 1. Navigation & View Endpoints
    print("[+] [TEST 1/8] Verifying Web View Routes...")
    for route in ['/', '/lab/auth-bypass', '/lab/union-based', '/lab/error-blind', '/lab/evasion-audit']:
        res = client.get(route)
        assert res.status_code == 200, f"Route {route} failed with status {res.status_code}"
    print("    -> All web lab views returned HTTP 200 OK.")

    # 2. Module 1: Vulnerable Tautology Bypass
    print("\n[+] [TEST 2/8] Module 1: Testing Tautology Auth Bypass (' OR 1=1 -- )...")
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
    print("\n[+] [TEST 3/8] Module 1: Testing Parameterized Defense against Auth Bypass...")
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
    print("\n[+] [TEST 4/8] Module 2: Testing Standard Product Catalog Query...")
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
    print("\n[+] [TEST 5/8] Module 2: Testing Column Counting (ORDER BY 5 valid vs ORDER BY 6 error)...")
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
    print("\n[+] [TEST 6/8] Module 2: Testing Column Projection Mismatch (UNION Error 1222)...")
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
    print("\n[+] [TEST 7/8] Module 2: Testing UNION Data Exfiltration & Challenge Flag...")
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
    print("\n[+] [TEST 8/8] Module 2: Testing Remediated Parameterized Query against UNION Injection...")
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

    # Telemetry Audit Log Check
    print("\n[+] Verifying MySQL Audit Logging Telemetry...")
    res_logs = client.get('/api/audit-logs')
    logs = res_logs.get_json().get('logs', [])
    assert len(logs) > 0, "Audit logs must contain recorded queries"
    modules_in_logs = {log.get('lab_module') for log in logs}
    assert "Module 1: Auth Bypass" in modules_in_logs, "Module 1 queries must be audited"
    assert "Module 2: Union Extraction" in modules_in_logs, "Module 2 queries must be audited"
    print(f"    -> Audit logs verified ({len(logs)} queries logged across {len(modules_in_logs)} modules).")

    print("\n" + "="*60)
    print("[SUCCESS] ALL 8 TESTS PASSED SUCCESSFULLY! ZERO REGRESSIONS DETECTED.")
    print("="*60 + "\n")

if __name__ == "__main__":
    run_all_tests()
