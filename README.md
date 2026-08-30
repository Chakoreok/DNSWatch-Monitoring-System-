# DNSWatch: A Real-Time DNS Monitoring and Alert System

**DNSWatch** is a real-time, web-based DNS traffic monitoring, logging, and security alerting system developed for *Information Assurance and Security*.

It captures live DNS requests directly from network interfaces using **Scapy**, analyzes queries locally through a **3-Tier Threat Detection Engine**, logs events asynchronously into **MySQL**, and provides a dashboard interface.

---

## 🌟 Key Features

- **Live DNS Packet Sniffing**: Non-blocking asynchronous capture of UDP/TCP port 53 packets using Scapy and Npcap.
- **3-Tier Local Threat Detection**:
  1. **Malicious Domain List Matching**: Blacklist matching with fast in-memory lookups.
  2. **Basic Domain Rule Checking**: High-risk phishing compound patterns, suspicious TLDs, and regex checks.
  3. **DNS Query Frequency Rule**: Per-client sliding window velocity tracking to catch DNS flood/burst attacks.
- **Alert Deduplication & Cooldown**: Prevents alert flooding on rapid burst queries while preserving 100% of individual DNS request logs.
- **Observed Device Inventory**: Passive client IP tracker recording query volume, timestamps, and active status (without IP geolocation).
- **Web Interface**:
  - Real-time Dashboard with live counters and alert feeds.
  - DNS Network Logs with full filtering and pagination.
  - Security Alerts table with detailed investigation modals.
  - Threat Detection Rule & Blacklist Manager.
  - Reports & Analytics with Chart.js line charts and CSV export.
  - Role-Based Access Control (Admin, Security Analyst, Viewer).

---

## 🛠️ Technology Stack

- **Backend**: Python 3.13, Flask 3.1.3, Flask-Login, Flask-SQLAlchemy
- **Capture Engine**: Scapy 2.7.0 (Npcap driver)
- **Database**: MySQL Server (via PyMySQL)
- **Frontend**: HTML5, Vanilla CSS (Custom Design System), JavaScript, Chart.js, FontAwesome 6

---

## 🚀 Quick Setup & Installation

### 1. Prerequisites
- Python 3.10+ installed
- MySQL Server (e.g., XAMPP, WampServer, or MySQL 8.0)
- Npcap (installed with "WinPcap API-compatible mode" enabled)
- Git

### 2. Clone the Repository
```bash
git clone https://github.com/<your-username>/dnswatch.git
cd dnswatch
```

### 3. Install Dependencies
```bash
pip install -r requirements.txt
```

### 4. Configure Database
Create a `.env` file in the root directory:
```env
DB_HOST=127.0.0.1
DB_PORT=3306
DB_USER=root
DB_PASSWORD=
DB_NAME=dnswatch_db
SECRET_KEY=dnswatch_super_secret_key_2026
```

Initialize and seed the database:
```bash
python scripts/init_db.py
```

### 5. Run the System
```bash
python run.py
```

Open your browser and navigate to:
👉 **`http://127.0.0.1:5000`**

Default Credentials:
- **Username**: `admin`
- **Password**: `admin123`

---

## 🧪 Testing

Run the automated verification test suites:
```bash
# Test Detection Engine & False Positive Fix
python scripts/test_false_positive_fix.py

# Full End-to-End System Test Suite
python scripts/test_system.py
```

---

## 🔒 Security & Privacy Notice
DNSWatch runs **100% locally**. It strictly complies with privacy constraints:
- No external threat intelligence APIs.
- No IP Geolocation / GeoIP lookup dependencies.
- Client IPs remain raw IP addresses.
