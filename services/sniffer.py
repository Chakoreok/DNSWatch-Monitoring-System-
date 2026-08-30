import time
import queue
import threading
from datetime import datetime
from collections import deque
from scapy.all import sniff, conf, get_if_list, IP, IPv6, UDP, TCP, DNS, DNSQR, DNSRR
from database import db
from models import MonitoringSession, DNSLog, SecurityAlert
from services.detection_engine import detection_engine
from services.device_tracker import device_tracker

DNS_QTYPE_MAP = {
    1: 'A',
    2: 'NS',
    5: 'CNAME',
    6: 'SOA',
    12: 'PTR',
    15: 'MX',
    16: 'TXT',
    28: 'AAAA',
    33: 'SRV',
    255: 'ANY'
}

class DNSSnifferService:
    def __init__(self):
        self._lock = threading.RLock()
        self.is_running = False
        self.stop_event = threading.Event()
        self.sniff_thread = None
        self.db_writer_thread = None
        
        self.app = None
        self.current_session_id = None
        self.selected_interface = None
        self.start_timestamp = None
        self.last_packet_time = None
        
        # Performance metrics
        self.total_captured = 0
        self.safe_count = 0
        self.suspicious_count = 0
        self.blocked_count = 0
        
        # Thread-safe queue for database batch writing
        self.log_queue = queue.Queue(maxsize=10000)
        
        # Real-time circular buffer for instant dashboard updates
        self.live_logs_buffer = deque(maxlen=100)
        self.recent_alerts_buffer = deque(maxlen=20)
        
    def init_app(self, app):
        self.app = app

    def reset_in_memory_metrics(self):
        """Clears in-memory circular buffers and live counters."""
        with self._lock:
            self.total_captured = 0
            self.safe_count = 0
            self.suspicious_count = 0
            self.blocked_count = 0
            self.live_logs_buffer.clear()
            self.recent_alerts_buffer.clear()
            self.last_packet_time = None
            device_tracker.device_cache.clear()

    def get_auto_detected_interface(self):
        """Finds the most likely active physical interface (e.g. Wi-Fi / Ethernet with valid IPv4)."""
        # 1. Prefer interface with non-local, non-APIPA, non-VirtualBox IPv4
        for iface in conf.ifaces.values():
            ip = getattr(iface, 'ip', '') or ''
            desc = (getattr(iface, 'description', '') or '').lower()
            name = (getattr(iface, 'name', '') or '').lower()
            if ip and not ip.startswith('127.') and not ip.startswith('169.254.') and 'virtualbox' not in desc and 'virtualbox' not in name:
                return iface
                
        # 2. Fallback to any active non-loopback IP
        for iface in conf.ifaces.values():
            ip = getattr(iface, 'ip', '') or ''
            if ip and not ip.startswith('127.') and not ip.startswith('169.254.'):
                return iface
                
        return None

    def get_available_interfaces(self):
        """Returns list of network interfaces with human-friendly descriptions."""
        interfaces = []
        try:
            for iface in conf.ifaces.values():
                name = getattr(iface, 'name', '') or str(iface)
                ip = getattr(iface, 'ip', '') or ''
                mac = getattr(iface, 'mac', '') or ''
                desc = getattr(iface, 'description', '') or name
                
                is_loopback = 'loopback' in name.lower() or '127.0.0.1' in ip
                
                interfaces.append({
                    'id': str(iface.index) if hasattr(iface, 'index') else name,
                    'name': name,
                    'description': desc,
                    'ip': ip,
                    'mac': mac,
                    'is_loopback': is_loopback
                })
        except Exception as e:
            print(f"[DNSSniffer] Error listing interfaces: {e}")
            for iface_str in get_if_list():
                interfaces.append({
                    'id': iface_str,
                    'name': iface_str,
                    'description': iface_str,
                    'ip': '',
                    'mac': '',
                    'is_loopback': 'loopback' in iface_str.lower()
                })
        return interfaces

    def start_monitoring(self, interface=None, user_id=None):
        """Starts Scapy sniffing in a background thread."""
        with self._lock:
            if self.is_running:
                return False, "Monitoring is already active."
                
            self.stop_event.clear()
            
            # Resolve interface
            if interface:
                # Find matching iface object by name or description or id
                matched = None
                for iface in conf.ifaces.values():
                    if getattr(iface, 'name', '') == interface or getattr(iface, 'description', '') == interface or str(getattr(iface, 'index', '')) == str(interface):
                        matched = iface
                        break
                self.selected_interface = matched or interface
            else:
                self.selected_interface = self.get_auto_detected_interface()
                
            self.start_timestamp = datetime.utcnow()
            self.last_packet_time = None
            
            self.total_captured = 0
            self.safe_count = 0
            self.suspicious_count = 0
            self.blocked_count = 0
            
            iface_display_name = getattr(self.selected_interface, 'description', None) or getattr(self.selected_interface, 'name', None) or str(self.selected_interface) or "All Interfaces"
            
            # Reload detection rules cache
            if self.app:
                with self.app.app_context():
                    detection_engine.reload_cache()
                    
                    # Create new monitoring session in DB
                    session_rec = MonitoringSession(
                        session_name=f"Capture-{self.start_timestamp.strftime('%Y%m%d-%H%M%S')}",
                        start_time=self.start_timestamp,
                        status="ACTIVE",
                        interface=iface_display_name,
                        created_by=user_id
                    )
                    db.session.add(session_rec)
                    db.session.commit()
                    self.current_session_id = session_rec.id
                    
            self.is_running = True
            
            # Start background worker threads
            self.db_writer_thread = threading.Thread(
                target=self._db_writer_worker,
                daemon=True,
                name="DNSWatch-DBWriter"
            )
            self.db_writer_thread.start()
            
            self.sniff_thread = threading.Thread(
                target=self._sniff_worker,
                daemon=True,
                name="DNSWatch-Sniffer"
            )
            self.sniff_thread.start()
            
            return True, f"Monitoring started successfully on {iface_display_name} (Session #{self.current_session_id})."

    def stop_monitoring(self):
        """Gracefully signals Scapy and DB writer to stop."""
        with self._lock:
            if not self.is_running:
                return False, "Monitoring is not currently active."
                
            self.stop_event.set()
            self.is_running = False
            
            # Update session in DB
            if self.app and self.current_session_id:
                try:
                    with self.app.app_context():
                        session_rec = MonitoringSession.query.get(self.current_session_id)
                        if session_rec:
                            session_rec.end_time = datetime.utcnow()
                            session_rec.status = "STOPPED"
                            session_rec.total_queries = self.total_captured
                            session_rec.safe_queries = self.safe_count
                            session_rec.suspicious_queries = self.suspicious_count
                            session_rec.blocked_queries = self.blocked_count
                            db.session.commit()
                except Exception as e:
                    print(f"[DNSSniffer] Error updating session on stop: {e}")
                    
            return True, "Monitoring stopped successfully."

    def get_status(self):
        """Returns real-time status summary for UI and API."""
        with self._lock:
            uptime_seconds = 0
            if self.is_running and self.start_timestamp:
                uptime_seconds = int((datetime.utcnow() - self.start_timestamp).total_seconds())
                
            uptime_str = f"{uptime_seconds // 3600:02d}:{(uptime_seconds % 3600) // 60:02d}:{uptime_seconds % 60:02d}"
            
            last_pkt_str = self.last_packet_time.strftime('%I:%M:%S %p') if self.last_packet_time else "None"
            started_at_str = self.start_timestamp.strftime('%b %d, %Y %I:%M %p') if self.start_timestamp else "Not started"
            
            iface_name = getattr(self.selected_interface, 'description', None) or getattr(self.selected_interface, 'name', None) or str(self.selected_interface) or "All Interfaces"
            
            return {
                'is_running': self.is_running,
                'status': 'Active' if self.is_running else 'Inactive',
                'session_id': self.current_session_id,
                'started_at': started_at_str,
                'uptime': uptime_str,
                'last_packet_time': last_pkt_str,
                'interface': iface_name,
                'total_queries': self.total_captured,
                'safe_queries': self.safe_count,
                'suspicious_queries': self.suspicious_count,
                'blocked_queries': self.blocked_count
            }

    def _sniff_worker(self):
        """Scapy sniffing execution loop."""
        iface_name = getattr(self.selected_interface, 'description', None) or getattr(self.selected_interface, 'name', None) or str(self.selected_interface) or 'Default'
        print(f"[DNSSniffer] Background sniffer active on interface: {iface_name}")
        
        def packet_handler(pkt):
            if self.stop_event.is_set():
                return
            try:
                self._process_scapy_packet(pkt)
            except Exception as e:
                pass

        def stop_filter(pkt):
            return self.stop_event.is_set()

        try:
            sniff_kwargs = {
                'filter': "udp port 53 or tcp port 53",
                'prn': packet_handler,
                'store': False,
                'stop_filter': stop_filter
            }
            if self.selected_interface:
                sniff_kwargs['iface'] = self.selected_interface
                
            sniff(**sniff_kwargs)
        except Exception as e:
            print(f"[DNSSniffer] Sniffer stopped or encountered interface error: {e}")
        finally:
            with self._lock:
                self.is_running = False

    def _process_scapy_packet(self, pkt):
        """Extracts DNS information and evaluates rules."""
        if not pkt.haslayer(DNS):
            return
            
        dns_layer = pkt[DNS]
        if not dns_layer.haslayer(DNSQR):
            return
            
        now_dt = datetime.now()
        self.last_packet_time = now_dt
        
        # 1. Extract Domain Name
        qname = dns_layer[DNSQR].qname
        if isinstance(qname, bytes):
            raw_domain = qname.decode('utf-8', errors='ignore').rstrip('.')
        else:
            raw_domain = str(qname).rstrip('.')
            
        if not raw_domain:
            return
            
        # 2. Extract Query Type
        qtype_num = dns_layer[DNSQR].qtype
        query_type = DNS_QTYPE_MAP.get(qtype_num, str(qtype_num))
        
        # 3. Extract Client IP
        client_ip = "Unknown"
        client_port = None
        if pkt.haslayer(IP):
            client_ip = pkt[IP].src if dns_layer.qr == 0 else pkt[IP].dst
            if pkt.haslayer(UDP):
                client_port = pkt[UDP].sport if dns_layer.qr == 0 else pkt[UDP].dport
            elif pkt.haslayer(TCP):
                client_port = pkt[TCP].sport if dns_layer.qr == 0 else pkt[TCP].dport
        elif pkt.haslayer(IPv6):
            client_ip = pkt[IPv6].src if dns_layer.qr == 0 else pkt[IPv6].dst
            
        # 4. Extract Response IP and TTL if available
        response_ip = "-"
        ttl = 300
        response_code = "NOERROR"
        
        if dns_layer.qr == 1:
            rcode = dns_layer.rcode
            rcode_names = {0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN", 4: "NOTIMP", 5: "REFUSED"}
            response_code = rcode_names.get(rcode, str(rcode))
            
            if dns_layer.an:
                for i in range(dns_layer.ancount):
                    rr = dns_layer.an[i]
                    if isinstance(rr, DNSRR):
                        if hasattr(rr, 'ttl') and rr.ttl:
                            ttl = int(rr.ttl)
                        if rr.type in (1, 28) and hasattr(rr, 'rdata'):
                            response_ip = str(rr.rdata)
                            break
                            
        # 5. Evaluate through 3-Tier Detection Engine
        status, detection_reason, matched_rule_id, alert_dict, activity_category = \
            detection_engine.evaluate_dns_request(client_ip, raw_domain, query_type)
            
        # 6. Update counts
        with self._lock:
            self.total_captured += 1
            if status == "SAFE":
                self.safe_count += 1
            elif status == "SUSPICIOUS":
                self.suspicious_count += 1
            elif status == "BLOCKED":
                self.blocked_count += 1
                
        # 7. Record device activity
        device_tracker.record_device_activity(client_ip, now_dt)
        
        # 8. Prepare log payload
        log_payload = {
            'session_id': self.current_session_id,
            'timestamp': now_dt,
            'client_ip': client_ip,
            'client_port': client_port,
            'query_domain': raw_domain,
            'query_type': query_type,
            'response_ip': response_ip if response_ip != "-" else "",
            'response_code': response_code,
            'ttl': ttl,
            'status': status,
            'detection_reason': detection_reason,
            'matched_rule_id': matched_rule_id,
            'source': 'SCAPY_CAPTURE',
            'activity_category': activity_category,
            'alert_dict': alert_dict
        }
        
        # Add to fast circular buffer for real-time frontend stream
        ui_log_entry = {
            'id': self.total_captured,
            'time_only': now_dt.strftime('%I:%M:%S %p'),
            'timestamp': now_dt.strftime('%Y-%m-%d %H:%M:%S'),
            'client_ip': client_ip,
            'domain': raw_domain,
            'query_domain': raw_domain,
            'query_type': query_type,
            'response_ip': response_ip,
            'status': status,
            'info': activity_category
        }
        self.live_logs_buffer.appendleft(ui_log_entry)
        
        if alert_dict:
            ui_alert_entry = {
                'id': alert_dict['alert_id'],
                'alert_id': alert_dict['alert_id'],
                'time_only': now_dt.strftime('%I:%M:%S %p'),
                'timestamp': now_dt.strftime('%Y-%m-%d %H:%M:%S'),
                'severity': alert_dict['severity'],
                'domain': alert_dict['domain'],
                'client_ip': alert_dict['client_ip'],
                'alert_type': alert_dict['alert_type'],
                'description': alert_dict['description'],
                'status': 'New'
            }
            self.recent_alerts_buffer.appendleft(ui_alert_entry)
            
        try:
            self.log_queue.put_nowait(log_payload)
        except queue.Full:
            pass

    def ingest_simulated_packet(self, client_ip, domain, query_type="A", response_ip=None):
        """Allows testing & simulation tools to feed DNS requests through the exact same capture pipeline."""
        now_dt = datetime.now()
        self.last_packet_time = now_dt
        
        status, detection_reason, matched_rule_id, alert_dict, activity_category = \
            detection_engine.evaluate_dns_request(client_ip, domain, query_type)
            
        with self._lock:
            self.total_captured += 1
            if status == "SAFE":
                self.safe_count += 1
            elif status == "SUSPICIOUS":
                self.suspicious_count += 1
            elif status == "BLOCKED":
                self.blocked_count += 1
                
        device_tracker.record_device_activity(client_ip, now_dt)
        
        log_payload = {
            'session_id': self.current_session_id,
            'timestamp': now_dt,
            'client_ip': client_ip,
            'client_port': 53535,
            'query_domain': domain,
            'query_type': query_type,
            'response_ip': response_ip or "",
            'response_code': "NOERROR",
            'ttl': 300,
            'status': status,
            'detection_reason': detection_reason,
            'matched_rule_id': matched_rule_id,
            'source': 'SIMULATED' if not self.is_running else 'SCAPY_CAPTURE',
            'activity_category': activity_category,
            'alert_dict': alert_dict
        }
        
        ui_log_entry = {
            'id': self.total_captured,
            'time_only': now_dt.strftime('%I:%M:%S %p'),
            'timestamp': now_dt.strftime('%Y-%m-%d %H:%M:%S'),
            'client_ip': client_ip,
            'domain': domain,
            'query_domain': domain,
            'query_type': query_type,
            'response_ip': response_ip or "-",
            'status': status,
            'info': activity_category
        }
        self.live_logs_buffer.appendleft(ui_log_entry)
        
        if alert_dict:
            ui_alert_entry = {
                'id': alert_dict['alert_id'],
                'alert_id': alert_dict['alert_id'],
                'time_only': now_dt.strftime('%I:%M:%S %p'),
                'timestamp': now_dt.strftime('%Y-%m-%d %H:%M:%S'),
                'severity': alert_dict['severity'],
                'domain': alert_dict['domain'],
                'client_ip': alert_dict['client_ip'],
                'alert_type': alert_dict['alert_type'],
                'description': alert_dict['description'],
                'status': 'New'
            }
            self.recent_alerts_buffer.appendleft(ui_alert_entry)
            
        try:
            self.log_queue.put_nowait(log_payload)
        except queue.Full:
            pass
            
        return status, alert_dict

    def _db_writer_worker(self):
        """Asynchronously writes queued logs and alerts into MySQL in batches."""
        last_device_flush = time.time()
        
        while self.is_running or not self.log_queue.empty():
            batch = []
            try:
                while len(batch) < 50:
                    try:
                        item = self.log_queue.get(timeout=0.5)
                        batch.append(item)
                    except queue.Empty:
                        break
            except Exception:
                pass
                
            if batch and self.app:
                with self.app.app_context():
                    try:
                        alerts_to_add = []
                        logs_to_add = []
                        
                        for item in batch:
                            alert_dict = item.pop('alert_dict', None)
                            
                            log_obj = DNSLog(**item)
                            db.session.add(log_obj)
                            logs_to_add.append((log_obj, alert_dict))
                            
                        db.session.commit()
                        
                        for log_obj, alert_dict in logs_to_add:
                            if alert_dict:
                                alert_obj = SecurityAlert(
                                    alert_id=alert_dict['alert_id'],
                                    log_id=log_obj.id,
                                    timestamp=alert_dict['timestamp'],
                                    severity=alert_dict['severity'],
                                    domain=alert_dict['domain'],
                                    client_ip=alert_dict['client_ip'],
                                    alert_type=alert_dict['alert_type'],
                                    description=alert_dict['description'],
                                    status=alert_dict['status']
                                )
                                alerts_to_add.append(alert_obj)
                                
                        if alerts_to_add:
                            db.session.bulk_save_objects(alerts_to_add)
                            db.session.commit()
                            
                    except Exception as e:
                        db.session.rollback()
                        print(f"[DNSSniffer] DB batch insert error: {e}")
                        
            if time.time() - last_device_flush > 5.0 and self.app:
                device_tracker.flush_devices_to_db(self.app)
                last_device_flush = time.time()
                
            time.sleep(0.1)

sniffer_service = DNSSnifferService()
