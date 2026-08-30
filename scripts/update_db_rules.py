import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import pymysql
from config import Config

conn = pymysql.connect(
    host=Config.DB_HOST,
    user=Config.DB_USER,
    password=Config.DB_PASSWORD,
    db=Config.DB_NAME,
    port=int(Config.DB_PORT)
)

with conn.cursor() as cur:
    print("Updating detection_rules table in MySQL to remove overly broad single-word rules...")
    
    # Update Rule 6 (or any generic 'Suspicious Keywords' rule) to specific compound phishing patterns
    cur.execute("""
        UPDATE detection_rules 
        SET pattern = 'login-verify, account-update, secure-banking, auth-portal, wallet-connect, verify-account',
            rule_name = 'Phishing Keywords Pattern',
            category = 'Phishing / Social Engineering',
            severity = 'MEDIUM',
            action = 'Alert',
            description = 'Flags domains containing high-risk compound phishing patterns (e.g. login-verify, account-update)'
        WHERE pattern LIKE '%account%' OR pattern LIKE '%update%' OR rule_name LIKE '%Keywords%';
    """)
    
    # Delete temporary unit test rules
    cur.execute("DELETE FROM detection_rules WHERE rule_name LIKE 'Test-Phish-Rule%';")
    
    # Delete temporary unit test malicious domains
    cur.execute("DELETE FROM malicious_domains WHERE domain LIKE 'test-malware-%';")
    
    conn.commit()
    
    print("\n--- UPDATED DETECTION RULES ---")
    cur.execute("SELECT id, rule_name, rule_type, pattern, severity, action, is_active FROM detection_rules;")
    for r in cur.fetchall():
        print(r)
        
conn.close()
print("\nDatabase rules successfully updated!")
