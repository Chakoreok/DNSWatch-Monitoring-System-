import os
import sys

# Ensure d:\DNS is on python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import pymysql
from config import Config

def clear_sample_data():
    print(f"Connecting to MySQL database '{Config.DB_NAME}'...")
    conn = pymysql.connect(
        host=Config.DB_HOST,
        user=Config.DB_USER,
        password=Config.DB_PASSWORD,
        port=int(Config.DB_PORT),
        database=Config.DB_NAME
    )
    
    with conn.cursor() as cur:
        # Disable foreign key checks for clean truncation
        cur.execute("SET FOREIGN_KEY_CHECKS = 0;")
        
        # 1. Truncate Security Alerts
        print("Clearing security_alerts table...")
        cur.execute("TRUNCATE TABLE security_alerts;")
        
        # 2. Truncate DNS Logs
        print("Clearing dns_logs table...")
        cur.execute("TRUNCATE TABLE dns_logs;")
        
        # 3. Truncate Devices
        print("Clearing devices table...")
        cur.execute("TRUNCATE TABLE devices;")
        
        # 4. Truncate Website Activity
        print("Clearing website_activity table...")
        cur.execute("TRUNCATE TABLE website_activity;")
        
        # 5. Truncate / Reset Monitoring Sessions
        print("Clearing monitoring_sessions table...")
        cur.execute("TRUNCATE TABLE monitoring_sessions;")
        
        cur.execute("SET FOREIGN_KEY_CHECKS = 1;")
        conn.commit()
        
    conn.close()
    print("\n[SUCCESS] All sample/test logs, alerts, devices, and session data have been cleared from MySQL.")

if __name__ == "__main__":
    clear_sample_data()
