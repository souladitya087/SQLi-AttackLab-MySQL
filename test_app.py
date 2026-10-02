from app import app

def test_endpoints():
    client = app.test_client()

    print("[*] Testing GET / ...")
    res = client.get('/')
    assert res.status_code == 200, f"Failed: {res.status_code}"

    print("[*] Testing GET /lab/auth-bypass ...")
    res = client.get('/lab/auth-bypass')
    assert res.status_code == 200, f"Failed: {res.status_code}"

    print("[*] Testing POST /api/auth/test (Vulnerable Tautology Bypass)...")
    payload = "' OR 1=1 -- "
    res = client.post('/api/auth/test', json={
        'username': payload,
        'password': 'any',
        'scenario': 'tautology',
        'mode': 'vulnerable'
    })
    assert res.status_code == 200
    data = res.get_json()
    print("  -> Success:", data.get('success'))
    print("  -> Bypassed:", data.get('bypassed'))
    print("  -> User compromised:", data.get('user_profile', {}).get('username'))
    print("  -> Flag awarded:", data.get('flag'))
    assert data.get('success') is True
    assert data.get('bypassed') is True
    assert data.get('user_profile', {}).get('username') == 'admin'

    print("[*] Testing POST /api/auth/test (Secure Parameterized Mode)...")
    res = client.post('/api/auth/test', json={
        'username': payload,
        'password': 'any',
        'scenario': 'tautology',
        'mode': 'secure'
    })
    data = res.get_json()
    print("  -> Secure Success (must be False):", data.get('success'))
    assert data.get('success') is False

    print("[*] Testing GET /api/audit-logs ...")
    res = client.get('/api/audit-logs')
    logs = res.get_json().get('logs', [])
    print(f"  -> Audit log entries count: {len(logs)}")
    assert len(logs) > 0

    print("[+] ALL AUTOMATED TESTS PASSED SUCCESSFULLY!")

if __name__ == "__main__":
    test_endpoints()
