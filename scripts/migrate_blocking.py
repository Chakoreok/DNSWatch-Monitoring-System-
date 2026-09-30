"""
DNSWatch - Safe DB Migration: Manual Blocking Tables
------------------------------------------------------
Adds two new tables to dnswatch_db WITHOUT touching existing data.
Uses direct PyMySQL connection to avoid triggering the Flask app startup
(which would call the detection engine before tables exist).

Run once:  python scripts/migrate_blocking.py
Safe to re-run (IF NOT EXISTS guards repeated execution).
"""
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from dotenv import load_dotenv
load_dotenv(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), '.env'))

import pymysql

DB_HOST = os.getenv('DB_HOST', '127.0.0.1')
DB_PORT = int(os.getenv('DB_PORT', '3306'))
DB_USER = os.getenv('DB_USER', 'root')
DB_PASSWORD = os.getenv('DB_PASSWORD', '')
DB_NAME = os.getenv('DB_NAME', 'dnswatch_db')

SQL_STATEMENTS = [
    # 1. manual_block_rules
    """
    CREATE TABLE IF NOT EXISTS manual_block_rules (
        id                INT          NOT NULL AUTO_INCREMENT,
        domain            VARCHAR(255) NOT NULL,
        reason            TEXT         NULL,
        created_by        VARCHAR(100) NOT NULL DEFAULT 'admin',
        approved_by       VARCHAR(100) NULL,
        source_request_id INT          NULL,
        is_active         TINYINT(1)  NOT NULL DEFAULT 1,
        created_at        DATETIME    NOT NULL DEFAULT CURRENT_TIMESTAMP,
        updated_at        DATETIME    NOT NULL DEFAULT CURRENT_TIMESTAMP
                                     ON UPDATE CURRENT_TIMESTAMP,
        PRIMARY KEY  (id),
        UNIQUE KEY uq_mbr_domain  (domain),
        KEY        idx_mbr_active (is_active)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
    """,

    # 2. block_requests
    """
    CREATE TABLE IF NOT EXISTS block_requests (
        id               INT          NOT NULL AUTO_INCREMENT,
        domain           VARCHAR(255) NOT NULL,
        client_ip        VARCHAR(45)  NULL,
        reason           TEXT         NOT NULL,
        detection_info   TEXT         NULL,
        requested_by     VARCHAR(100) NOT NULL,
        requested_at     DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
        reviewed_by      VARCHAR(100) NULL,
        reviewed_at      DATETIME     NULL,
        rejection_reason TEXT         NULL,
        status           VARCHAR(20)  NOT NULL DEFAULT 'PENDING',
        PRIMARY KEY (id),
        KEY idx_br_domain       (domain),
        KEY idx_br_status       (status),
        KEY idx_br_requested_at (requested_at)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
    """,
]


def run_migration():
    conn = pymysql.connect(
        host=DB_HOST, port=DB_PORT,
        user=DB_USER, password=DB_PASSWORD,
        database=DB_NAME, charset='utf8mb4',
        autocommit=False
    )
    try:
        with conn.cursor() as cur:
            for sql in SQL_STATEMENTS:
                stmt = sql.strip()
                if stmt:
                    cur.execute(stmt)
        conn.commit()
        print("[Migration] SUCCESS: manual_block_rules and block_requests tables are ready.")
    except Exception as exc:
        conn.rollback()
        print(f"[Migration] FAILED: {exc}")
        raise
    finally:
        conn.close()


if __name__ == '__main__':
    run_migration()
