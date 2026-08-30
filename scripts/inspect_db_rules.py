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
    cur.execute("SELECT id, domain, category, severity, status FROM malicious_domains;")
    m_domains = cur.fetchall()
    print("=== MALICIOUS DOMAINS IN DB ===")
    for m in m_domains:
        print(m)

    cur.execute("SELECT id, rule_name, rule_type, pattern, category, severity, action, is_active FROM detection_rules;")
    rules = cur.fetchall()
    print("\n=== DETECTION RULES IN DB ===")
    for r in rules:
        print(r)

conn.close()
