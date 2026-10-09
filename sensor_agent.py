"""
sensor_agent.py
===============
DNSWatch Local Network Sensor Agent
-----------------------------------
Captures real DNS packets on the local network (Wi-Fi / Ethernet) using Scapy,
parses queries & responses, and streams them securely to the DNSWatch backend
(e.g., deployed on Render) over HTTPS.

Target Architecture:
  Local Network -> Scapy Sniffer -> DNS Parser -> Render Backend (/api/sensor/ingest)
  -> Database & Heuristic Engine -> Real-Time SSE/WebSocket -> DNSWatch Web SOC

Usage:
  python sensor_agent.py
  python sensor_agent.py --url https://your-dnswatch.onrender.com --key YOUR_SECRET_KEY
"""

import sys
import os
import time
import queue
import argparse
import threading
from datetime import datetime

# Load environment variables if python-dotenv is available
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

try:
    import requests
except ImportError:
    print("[ERROR] 'requests' is required: pip install requests")
    sys.exit(1)

try:
    from scapy.all import sniff, conf, get_if_list, IP, IPv6, UDP, TCP, Ether, DNS, DNSQR, DNSRR
except ImportError:
    print("[ERROR] 'scapy' is required: pip install scapy")
    print("        On Windows, also install Npcap: https://npcap.com")
    sys.exit(1)

# DNS query type mapping
DNS_QTYPE_MAP = {
    1: 'A', 2: 'NS', 5: 'CNAME', 6: 'SOA', 12: 'PTR', 15: 'MX',
    16: 'TXT', 28: 'AAAA', 33: 'SRV', 64: 'SVCB', 65: 'HTTPS', 255: 'ANY'
}

RCODE_MAP = {
    0: 'NOERROR', 1: 'FORMERR', 2: 'SERVFAIL', 3: 'NXDOMAIN',
    4: 'NOTIMP', 5: 'REFUSED', 6: 'YXDOMAIN', 7: 'YXRRSET',
    8: 'NXRRSET', 9: 'NOTAUTH', 10: 'NOTZONE'
}


class DNSWatchSensorAgent:
    def __init__(self, backend_url, sensor_key, interface=None, autostart=False):
        self.backend_url = backend_url.rstrip('/')
        self.sensor_key = sensor_key or ''
        self.interface_arg = interface
        self.selected_interface = None
        self.iface_name = "Auto"
        
        self.is_capturing = False
        self.stop_sniff_event = threading.Event()
        self.sniff_thread = None
        self.total_captured = 0
        
        self.packet_queue = queue.Queue(maxsize=10000)
        self.running = True
        self.autostart = autostart
        self.session = requests.Session()
        if self.sensor_key:
            self.session.headers.update({'X-Sensor-Key': self.sensor_key})
        self.session.headers.update({'User-Agent': 'DNSWatch-Sensor/2.0'})

    def resolve_interface(self):
        """Resolves physical network interface for packet capture."""
        if self.interface_arg:
            for iface in conf.ifaces.values():
                if (getattr(iface, 'name', '') == self.interface_arg or
                    getattr(iface, 'description', '') == self.interface_arg or
                    str(getattr(iface, 'index', '')) == str(self.interface_arg)):
                    self.selected_interface = iface
                    self.iface_name = getattr(iface, 'description', None) or getattr(iface, 'name', str(iface))
                    return self.selected_interface

        # Auto-detect physical interface with active IPv4
        for iface in conf.ifaces.values():
            ip = getattr(iface, 'ip', '') or ''
            desc = (getattr(iface, 'description', '') or '').lower()
            name = (getattr(iface, 'name', '') or '').lower()
            if ip and not ip.startswith('127.') and not ip.startswith('169.254.'):
                if 'virtualbox' not in desc and 'vmware' not in desc and 'virtualbox' not in name:
                    self.selected_interface = iface
                    self.iface_name = getattr(iface, 'description', None) or getattr(iface, 'name', str(iface))
                    return self.selected_interface

        self.selected_interface = conf.iface
        self.iface_name = getattr(conf.iface, 'description', None) or str(conf.iface)
        return self.selected_interface

    def test_backend_connection(self):
        """Validates network route to the cloud Render backend."""
        print(f"[*] Testing connection to backend: {self.backend_url} ...")
        try:
            res = self.session.get(f"{self.backend_url}/api/sensor/status", timeout=10)
            if res.status_code == 200:
                print(f"[+] Connected successfully to DNSWatch Backend at {self.backend_url}")
                return True
            elif res.status_code == 401:
                print(f"[-] Authentication failed: SENSOR_KEY does not match the server's key.")
                return False
            else:
                print(f"[-] Backend returned HTTP {res.status_code}: {res.text[:200]}")
                return True  # Proceed anyway in case route is working
        except requests.exceptions.RequestException as e:
            print(f"[!] Warning: Cannot reach {self.backend_url}: {e}")
            print(f"[!] The agent will keep retrying in the background...")
            return False

    def start_sniffing(self):
        """Starts Scapy sniffing in a dedicated worker thread."""
        if self.is_capturing:
            return
        self.stop_sniff_event.clear()
        self.is_capturing = True
        self.sniff_thread = threading.Thread(target=self._sniff_loop, daemon=True, name="SnifferThread")
        self.sniff_thread.start()
        print(f"[+] Local packet sniffing STARTED on: {self.iface_name} (Filter: port 53)")

    def stop_sniffing(self):
        """Stops Scapy packet capture."""
        if not self.is_capturing:
            return
        self.stop_sniff_event.set()
        self.is_capturing = False
        print(f"[*] Local packet sniffing STOPPED.")

    def _sniff_loop(self):
        """Scapy capture loop targeting port 53."""
        try:
            sniff(
                iface=self.selected_interface,
                filter="udp port 53 or tcp port 53",
                prn=self._process_packet,
                store=False,
                stop_filter=lambda p: self.stop_sniff_event.is_set()
            )
        except PermissionError:
            print("[ERROR] Insufficient privileges: Raw socket capture requires Administrator / root privileges.")
            print("        Please re-run this command from an Administrator terminal or install Npcap in WinPcap API-compatible mode.")
            self.is_capturing = False
        except Exception as e:
            print(f"[!] Sniff loop error: {e}")
            self.is_capturing = False

    def _process_packet(self, packet):
        """Extracts and parses DNS query/response fields."""
        if not packet.haslayer(DNS):
            return

        dns = packet[DNS]
        
        # Determine client and server IPs
        client_ip = "127.0.0.1"
        client_mac = None
        if packet.haslayer(Ether):
            client_mac = packet[Ether].src

        if packet.haslayer(IP):
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
        elif packet.haslayer(IPv6):
            src_ip = packet[IPv6].src
            dst_ip = packet[IPv6].dst
        else:
            src_ip, dst_ip = "Unknown", "Unknown"

        # Packet direction
        is_response = bool(dns.qr == 1)
        client_ip = dst_ip if is_response else src_ip

        # Parse queries
        records = []
        if dns.qdcount > 0 and dns.qd:
            qd = dns.qd
            while qd:
                try:
                    qname = qd.qname.decode('utf-8', errors='ignore') if isinstance(qd.qname, bytes) else str(qd.qname)
                    qname = qname.rstrip('.')
                except Exception:
                    qname = "unknown"
                
                qtype_num = getattr(qd, 'qtype', 1)
                qtype_name = DNS_QTYPE_MAP.get(qtype_num, str(qtype_num))

                resp_ip = "-"
                ttl = 300
                rcode = RCODE_MAP.get(dns.rcode, 'NOERROR')

                # Check answers if this is a response packet
                if is_response and dns.ancount > 0 and dns.an:
                    an = dns.an
                    while an:
                        if hasattr(an, 'rdata') and an.rdata:
                            rdata_str = str(an.rdata)
                            if resp_ip == "-":
                                resp_ip = rdata_str
                        if hasattr(an, 'ttl'):
                            ttl = int(an.ttl)
                        an = getattr(an, 'payload', None) if hasattr(an, 'payload') and isinstance(an.payload, DNSRR) else None

                records.append({
                    'domain': qname,
                    'client_ip': client_ip,
                    'client_mac': client_mac,
                    'query_type': qtype_name,
                    'response_ip': resp_ip,
                    'response_code': rcode,
                    'ttl': ttl,
                    'timestamp': datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')
                })

                qd = getattr(qd, 'payload', None) if hasattr(qd, 'payload') and isinstance(qd.payload, DNSQR) else None

        for rec in records:
            try:
                self.packet_queue.put_nowait(rec)
                self.total_captured += 1
            except queue.Full:
                pass

    def _ingestion_worker(self):
        """Flushes captured DNS records to the Render backend in batches."""
        batch = []
        last_flush = time.time()

        while self.running:
            try:
                item = self.packet_queue.get(timeout=0.3)
                batch.append(item)
            except queue.Empty:
                pass

            now = time.time()
            if (len(batch) >= 15) or (batch and now - last_flush >= 0.5):
                to_send = batch[:]
                batch.clear()
                last_flush = now

                payload = {
                    'queries': to_send,
                    'interface': self.iface_name,
                    'sensor_name': 'local-agent'
                }
                try:
                    res = self.session.post(
                        f"{self.backend_url}/api/sensor/ingest",
                        json=payload,
                        timeout=5
                    )
                    if res.status_code == 200:
                        data = res.json()
                        alerts = data.get('alerts_generated', 0)
                        alert_tag = f" -> [! ALERT: {alerts} generated]" if alerts > 0 else ""
                        sys.stdout.write(f"\r[Ingest] Streamed {len(to_send)} DNS queries to cloud SOC{alert_tag} | Total: {self.total_captured}")
                        sys.stdout.flush()
                except Exception as e:
                    # Non-fatal network hiccup, log briefly
                    pass

    def _heartbeat_worker(self):
        """Periodically reports agent telemetry and checks for remote Start/Stop commands."""
        while self.running:
            try:
                payload = {
                    'interface': self.iface_name,
                    'is_capturing': self.is_capturing,
                    'total_captured': self.total_captured,
                    'sensor_name': 'local-agent'
                }
                res = self.session.post(
                    f"{self.backend_url}/api/sensor/heartbeat",
                    json=payload,
                    timeout=5
                )
                if res.status_code == 200:
                    data = res.json()
                    cmd = data.get('command', 'NONE')
                    if cmd == 'START' and not self.is_capturing:
                        print(f"\n[Command] Received remote START command from Render dashboard.")
                        self.start_sniffing()
                    elif cmd == 'STOP' and self.is_capturing:
                        print(f"\n[Command] Received remote STOP command from Render dashboard.")
                        self.stop_sniffing()
            except Exception:
                pass

            time.sleep(3)

    def run(self):
        """Main lifecycle of the sensor agent."""
        self.resolve_interface()
        print("=" * 65)
        print("   DNSWatch Sensor Agent — Real-Time Local Packet Sniffer")
        print("=" * 65)
        print(f"Backend Target  : {self.backend_url}")
        print(f"Selected Adapter: {self.iface_name}")
        print(f"Sensor Auth Key : {'[CONFIGURED]' if self.sensor_key else '[NONE / OPEN]'}")
        print("=" * 65)

        self.test_backend_connection()

        # Start background workers
        ingest_t = threading.Thread(target=self._ingestion_worker, daemon=True, name="IngestWorker")
        ingest_t.start()

        heartbeat_t = threading.Thread(target=self._heartbeat_worker, daemon=True, name="HeartbeatWorker")
        heartbeat_t.start()

        if self.autostart:
            self.start_sniffing()
        else:
            print("[*] Sensor is STANDBY and synced with Render dashboard.")
            print("[*] Click 'Start Sniffer' in the web SOC dashboard to begin capture,")
            print("    or press Ctrl+C to exit.\n")

        try:
            while self.running:
                time.sleep(1)
        except KeyboardInterrupt:
            print("\n[*] Stopping sensor agent...")
            self.running = False
            self.stop_sniffing()
            print("[+] Sensor agent cleanly terminated.")


def parse_args():
    parser = argparse.ArgumentParser(description="DNSWatch Local Packet Sniffer Agent")
    parser.add_argument(
        '--url',
        default=os.getenv('RENDER_URL') or os.getenv('BACKEND_URL') or 'http://127.0.0.1:5000',
        help='URL of the DNSWatch backend (e.g. https://dnswatch.onrender.com or http://127.0.0.1:5000)'
    )
    parser.add_argument(
        '--key',
        default=os.getenv('SENSOR_KEY', 'dnswatch-secret-sensor-key-2026'),
        help='Secret sensor authentication key matching SENSOR_KEY configured on backend'
    )
    parser.add_argument(
        '--interface',
        default=os.getenv('CAPTURE_INTERFACE', None),
        help='Network interface name or index to sniff (default: auto-detected)'
    )
    parser.add_argument(
        '--start',
        action='store_true',
        help='Start packet capture immediately without waiting for dashboard command'
    )
    return parser.parse_args()


if __name__ == '__main__':
    args = parse_args()
    agent = DNSWatchSensorAgent(
        backend_url=args.url,
        sensor_key=args.key,
        interface=args.interface,
        autostart=args.start
    )
    agent.run()
