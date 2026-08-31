import os
import sys
import requests

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

BASE_URL = "http://127.0.0.1:5000"

def test_authentication_system():
    print("\n" + "=" * 70)
    print("  DNSWatch Authentication & Route Protection Test Suite")
    print("=" * 70 + "\n")
    
    # ---------------------------------------------------------
    # TEST 1: Direct access to protected routes without session
    # ---------------------------------------------------------
    print("[TEST 1] Direct access to protected pages without session (Unauthenticated):")
    protected_urls = [
        "/",
        "/home",
        "/dashboard",
        "/website-activity",
        "/devices",
        "/dns-logs",
        "/security-alerts",
        "/threat-detection",
        "/reports",
        "/settings"
    ]
    
    unauth_session = requests.Session()
    for path in protected_urls:
        r = unauth_session.get(f"{BASE_URL}{path}", allow_redirects=False)
        print(f" -> Accessing {path:20} => Status: {r.status_code} | Location: {r.headers.get('Location', '-')}")
        assert r.status_code == 302, f"Expected 302 redirect for {path}, got {r.status_code}"
        assert "/login" in r.headers.get('Location', ''), f"Expected redirect to /login for {path}"
    print(" -> PASS: All protected pages correctly block unauthenticated access and redirect to /login.\n")

    # ---------------------------------------------------------
    # TEST 2: Empty username / password
    # ---------------------------------------------------------
    print("[TEST 2] Submitting empty credentials:")
    r = unauth_session.post(f"{BASE_URL}/api/auth/login", json={'username': '', 'password': ''})
    data = r.json()
    print(f" -> Status: {r.status_code} | Response: {data}")
    assert r.status_code == 400, f"Expected 400, got {r.status_code}"
    assert data['success'] is False
    assert "Username and password are required" in data['message']
    print(" -> PASS: Empty credentials rejected with proper error message.\n")

    # ---------------------------------------------------------
    # TEST 3: Wrong username
    # ---------------------------------------------------------
    print("[TEST 3] Submitting wrong username:")
    r = unauth_session.post(f"{BASE_URL}/api/auth/login", json={'username': 'nonexistent_user', 'password': 'somepassword'})
    data = r.json()
    print(f" -> Status: {r.status_code} | Response: {data}")
    assert r.status_code == 401, f"Expected 401, got {r.status_code}"
    assert data['success'] is False
    assert "Invalid username or password" in data['message']
    print(" -> PASS: Non-existent username rejected.\n")

    # ---------------------------------------------------------
    # TEST 4: Wrong password for valid user
    # ---------------------------------------------------------
    print("[TEST 4] Submitting wrong password for user 'admin':")
    r = unauth_session.post(f"{BASE_URL}/api/auth/login", json={'username': 'admin', 'password': 'wrongpassword123'})
    data = r.json()
    print(f" -> Status: {r.status_code} | Response: {data}")
    assert r.status_code == 401, f"Expected 401, got {r.status_code}"
    assert data['success'] is False
    assert "Invalid username or password" in data['message']
    print(" -> PASS: Incorrect password rejected.\n")

    # ---------------------------------------------------------
    # TEST 5: Valid credentials login & session establishment
    # ---------------------------------------------------------
    print("[TEST 5] Submitting valid credentials (admin / admin123):")
    auth_session = requests.Session()
    r = auth_session.post(f"{BASE_URL}/api/auth/login", json={'username': 'admin', 'password': 'admin123'})
    data = r.json()
    print(f" -> Status: {r.status_code} | Response: {data}")
    assert r.status_code == 200, f"Expected 200, got {r.status_code}"
    assert data['success'] is True
    assert data['redirect'] == "/dashboard"
    print(" -> PASS: Login successful with authenticated session cookie.\n")

    # ---------------------------------------------------------
    # TEST 6: Accessing protected pages WITH authenticated session
    # ---------------------------------------------------------
    print("[TEST 6] Accessing protected pages WITH valid session:")
    for path in ["/dashboard", "/website-activity", "/devices", "/dns-logs", "/security-alerts", "/threat-detection", "/reports", "/settings"]:
        r = auth_session.get(f"{BASE_URL}{path}", allow_redirects=False)
        print(f" -> Accessing {path:20} => Status: {r.status_code}")
        assert r.status_code == 200, f"Expected 200 for authenticated access to {path}, got {r.status_code}"
    print(" -> PASS: All protected pages load 200 OK for authenticated user.\n")

    # ---------------------------------------------------------
    # TEST 7: Accessing /login when ALREADY logged in redirects to /dashboard
    # ---------------------------------------------------------
    print("[TEST 7] Accessing /login when already authenticated:")
    r = auth_session.get(f"{BASE_URL}/login", allow_redirects=False)
    print(f" -> Accessing /login => Status: {r.status_code} | Location: {r.headers.get('Location')}")
    assert r.status_code == 302
    assert "/dashboard" in r.headers.get('Location', '')
    print(" -> PASS: Authenticated user accessing /login is redirected to /dashboard.\n")

    # ---------------------------------------------------------
    # TEST 8: Session persistence across multiple requests / page refreshes
    # ---------------------------------------------------------
    print("[TEST 8] Testing session persistence (simulated browser refresh):")
    r1 = auth_session.get(f"{BASE_URL}/dashboard")
    assert r1.status_code == 200
    r2 = auth_session.get(f"{BASE_URL}/api/auth/me").json()
    assert r2['authenticated'] is True
    assert r2['user']['username'] == 'admin'
    print(" -> PASS: Session persists across subsequent requests.\n")

    # ---------------------------------------------------------
    # TEST 9: Logout destroys session
    # ---------------------------------------------------------
    print("[TEST 9] Logging out:")
    r_logout = auth_session.get(f"{BASE_URL}/logout", allow_redirects=False)
    print(f" -> Logout request => Status: {r_logout.status_code} | Location: {r_logout.headers.get('Location')}")
    assert r_logout.status_code == 302
    assert "/login" in r_logout.headers.get('Location', '')
    
    # Check that me endpoint now reports unauthenticated
    r_me = auth_session.get(f"{BASE_URL}/api/auth/me").json()
    print(f" -> /api/auth/me => {r_me}")
    assert r_me['authenticated'] is False
    print(" -> PASS: Session cleared successfully.\n")

    # ---------------------------------------------------------
    # TEST 10: Accessing /dashboard AFTER logout
    # ---------------------------------------------------------
    print("[TEST 10] Accessing /dashboard AFTER logout:")
    r_post_logout = auth_session.get(f"{BASE_URL}/dashboard", allow_redirects=False)
    print(f" -> Accessing /dashboard after logout => Status: {r_post_logout.status_code} | Location: {r_post_logout.headers.get('Location')}")
    assert r_post_logout.status_code == 302
    assert "/login" in r_post_logout.headers.get('Location', '')
    print(" -> PASS: Access to /dashboard blocked and redirected to /login after logout.\n")

    print("=" * 70)
    print("  ALL 10 AUTHENTICATION & ROUTE PROTECTION TESTS PASSED 100%!")
    print("=" * 70 + "\n")

if __name__ == "__main__":
    test_authentication_system()
