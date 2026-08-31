import os
import sys
import json
import time

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from app import create_app
from database import db
from models import DNSLog, Device, SecurityAlert, WebsiteActivity, MonitoringSession
from services.sniffer import sniffer_service

def test_monitoring_synchronization_standalone():
    print("\n" + "=" * 70)
    print("  DNSWatch Monitoring State Synchronization & Persistence Test")
    print("=" * 70 + "\n")
    
    app = create_app()
    client = app.test_client()
    
    with app.app_context():
        # 1. Login
        print("Step 1: Authenticating as Administrator...")
        r_login = client.post("/api/auth/login", json={'username': 'admin', 'password': 'admin123'})
        assert r_login.status_code == 200, f"Login failed: {r_login.get_data(as_text=True)}"
        print(" -> Login successful.\n")

        # 2. Stop monitoring and verify Inactive state
        print("Step 2: Stopping monitoring (Setting state to Inactive)...")
        sniffer_service.stop_monitoring()
        
        r_status = client.get("/api/monitoring/status")
        status_data = json.loads(r_status.get_data(as_text=True))
        print(f" -> Backend Status: {status_data['monitoring']['status']} | is_running: {status_data['monitoring']['is_running']}")
        assert status_data['monitoring']['is_running'] is False
        assert status_data['monitoring']['status'] == "Inactive"
        print(" -> PASS: Backend accurately reports Monitoring Inactive.\n")

        # 3. Verify HTML rendering across Dashboard, Website Activity, DNS Logs, Devices
        print("Step 3: Checking HTML rendering of all views when Inactive...")
        views = [
            ('/dashboard', 'Monitoring Inactive'),
            ('/website-activity', 'Monitoring Inactive'),
            ('/dns-logs', 'Monitoring Inactive'),
            ('/devices', 'Monitoring Inactive')
        ]
        for path, expected_str in views:
            resp = client.get(path)
            html = resp.get_data(as_text=True)
            assert expected_str in html, f"Expected '{expected_str}' in {path} HTML"
            print(f" -> View {path:20} rendered '{expected_str}' correctly.")
        print(" -> PASS: All views synchronized with Inactive backend state.\n")

        # 4. Start monitoring and verify Active state
        print("Step 4: Starting monitoring (Setting state to Active)...")
        r_start = client.post("/api/monitoring/start", json={})
        assert r_start.status_code == 200, f"Failed to start monitoring: {r_start.get_data(as_text=True)}"
        
        r_status_active = client.get("/api/monitoring/status")
        status_active_data = json.loads(r_status_active.get_data(as_text=True))
        print(f" -> Backend Status: {status_active_data['monitoring']['status']} | is_running: {status_active_data['monitoring']['is_running']}")
        assert status_active_data['monitoring']['is_running'] is True
        assert status_active_data['monitoring']['status'] == "Active"
        print(" -> PASS: Backend accurately reports Monitoring Active.\n")

        # 5. Verify HTML rendering across views when Active
        print("Step 5: Checking HTML rendering of all views when Active...")
        for path, _ in views:
            resp = client.get(path)
            html = resp.get_data(as_text=True)
            assert 'Monitoring Active' in html, f"Expected 'Monitoring Active' in {path} HTML"
            print(f" -> View {path:20} rendered 'Monitoring Active' correctly.")
        print(" -> PASS: All views synchronized with Active backend state.\n")

        # 6. Capture / Ingest DNS traffic while Active
        print("Step 6: Ingesting DNS traffic while Active...")
        initial_log_count = DNSLog.query.count()
        
        queries = [
            ("192.168.254.108", "github.com", "A", "140.82.121.4"),
            ("192.168.254.108", "github.com", "AAAA", "2001:db8::10"),
            ("192.168.1.50", "apple.com", "A", "17.253.144.10"),
            ("192.168.1.75", "chatgpt.com", "HTTPS", "104.18.2.161")
        ]
        for ip, dom, qtype, resp_ip in queries:
            r_sim = client.post("/api/monitoring/simulate", json={
                'client_ip': ip,
                'domain': dom,
                'query_type': qtype,
                'response_ip': resp_ip
            })
            assert r_sim.status_code == 200
        
        time.sleep(1.0) # Allow queue to flush
        db.session.expire_all()
        db.session.commit()
        
        new_log_count = DNSLog.query.count()
        print(f" -> Initial logs: {initial_log_count} | New logs: {new_log_count}")
        assert new_log_count >= initial_log_count + len(queries)
        print(" -> PASS: DNS packets successfully captured and written to database in real-time.\n")

        # 7. Stop monitoring and verify NO logs are deleted
        print("Step 7: Stopping monitoring and checking log persistence...")
        r_stop = client.post("/api/monitoring/stop", json={})
        assert r_stop.status_code == 200
        
        r_status_stopped = client.get("/api/monitoring/status")
        status_stopped_data = json.loads(r_status_stopped.get_data(as_text=True))
        assert status_stopped_data['monitoring']['is_running'] is False
        assert status_stopped_data['monitoring']['status'] == "Inactive"
        
        # Check that previous logs were NOT deleted
        stopped_log_count = DNSLog.query.count()
        print(f" -> DNS Logs count after stopping monitoring: {stopped_log_count}")
        assert stopped_log_count == new_log_count, "DNS logs were unexpectedly deleted when monitoring was stopped!"
        
        r_web = client.get("/api/website-activity")
        web_data = json.loads(r_web.get_data(as_text=True))
        print(f" -> Website Activity count after stop: {web_data['pagination']['total']}")
        assert web_data['pagination']['total'] == stopped_log_count, "Website activity records do not match logs!"
        
        r_dev = client.get("/api/devices")
        dev_data = json.loads(r_dev.get_data(as_text=True))
        print(f" -> Devices count after stop: {dev_data['total_devices']}")
        assert dev_data['total_devices'] >= 2, "Devices were deleted or missing!"
        
        print(" -> PASS: Existing DNS logs, website activities, and devices remain 100% intact after stopping monitoring.\n")

    print("=" * 70)
    print("  ALL 7 MONITORING SYNCHRONIZATION & PERSISTENCE TESTS PASSED 100%!")
    print("=" * 70 + "\n")

if __name__ == "__main__":
    test_monitoring_synchronization_standalone()
