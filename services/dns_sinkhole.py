"""
DNSWatch DNS Sinkhole Service
------------------------------
A lightweight UDP DNS resolver that enforces manual block rules.

How it works
------------
* Blocked domains  → NXDOMAIN response (browser cannot resolve the site)
* All other domains → forwarded to upstream DNS (default 8.8.8.8) and relayed back

Requirements for real enforcement
----------------------------------
LAN clients must use the DNSWatch host IP as their DNS server (set via DHCP or
manually).  On Windows, the built-in DNS Client service (Dnscache) typically
holds port 53 on the local loopback; run as Administrator to free it:

    net stop Dnscache

Or bind the sinkhole to the specific LAN interface IP instead of 0.0.0.0.

Integration
-----------
* Block cache is reloaded from ManualBlockRule (MySQL) on start and every 15 s.
* Blocked query events are logged through the sniffer pipeline when Scapy
  monitoring is not active (avoids double-logging when both run simultaneously).
* The detection engine Tier-0 check ensures Scapy-captured packets also show
  BLOCKED status when monitoring is running.
"""
import socket
import struct
import threading
import time

# Map common QTYPE numbers to readable strings
_DNS_QTYPE_MAP = {
    1: 'A', 2: 'NS', 5: 'CNAME', 6: 'SOA', 12: 'PTR',
    15: 'MX', 16: 'TXT', 28: 'AAAA', 33: 'SRV',
    64: 'SVCB', 65: 'HTTPS', 255: 'ANY'
}


class DNSSinkholeService:
    """
    Embedded DNS sinkhole running on a background UDP socket.
    Thread-safe; controlled via start() / stop().
    """

    def __init__(self):
        self._lock = threading.RLock()
        self.is_running = False
        self.stop_event = threading.Event()
        self.server_thread = None
        self.app = None

        # Default configuration (overridable via start())
        self.port = 53
        self.upstream_dns = '8.8.8.8'
        self.bind_address = '0.0.0.0'

        # In-memory block cache: {normalized_domain: {'domain':..., 'reason':...}}
        self.blocked_domains: dict = {}
        self.last_block_reload: float = 0
        self.error_message: str = ''

    # ------------------------------------------------------------------
    # Flask app context
    # ------------------------------------------------------------------

    def init_app(self, app) -> None:
        self.app = app

    # ------------------------------------------------------------------
    # Block-list cache management
    # ------------------------------------------------------------------

    def reload_block_cache(self) -> None:
        """Load (or refresh) active ManualBlockRule records from MySQL."""
        if not self.app:
            return
        try:
            with self.app.app_context():
                from models import ManualBlockRule  # lazy import – avoids circular at module level
                active = ManualBlockRule.query.filter_by(is_active=True).all()
                new_cache = {
                    r.domain.strip().lower().rstrip('.'): {
                        'domain': r.domain.strip().lower().rstrip('.'),
                        'reason': r.reason or ''
                    }
                    for r in active
                }
            with self._lock:
                self.blocked_domains = new_cache
            self.last_block_reload = time.time()
        except Exception as exc:
            print(f"[DNSSinkhole] Block cache reload error: {exc}")

    def _is_blocked(self, domain: str):
        """
        Boundary-safe lookup.
        Returns (True, rule_dict) if *domain* or any parent of *domain* is blocked,
        otherwise (False, None).

        Example: blocking 'evil.com' blocks 'www.evil.com' but NOT 'notevil.com'.
        """
        domain = domain.lower().rstrip('.')
        with self._lock:
            if domain in self.blocked_domains:
                return True, self.blocked_domains[domain]
            parts = domain.split('.')
            for i in range(1, len(parts)):
                parent = '.'.join(parts[i:])
                if parent in self.blocked_domains:
                    return True, self.blocked_domains[parent]
        return False, None

    # ------------------------------------------------------------------
    # Raw DNS packet helpers (pure Python – no extra dependencies)
    # ------------------------------------------------------------------

    @staticmethod
    def _parse_query(data: bytes):
        """
        Extract (domain_str, qtype_int) from raw DNS query bytes.
        Returns (None, None) on any parse error.
        """
        try:
            if len(data) < 13:
                return None, None
            pos = 12  # question section starts after the 12-byte header
            labels = []
            while pos < len(data):
                length = data[pos]
                if length == 0:
                    pos += 1
                    break
                if (length & 0xC0) == 0xC0:   # DNS name compression pointer
                    pos += 2
                    break
                pos += 1
                if pos + length > len(data):
                    return None, None
                labels.append(data[pos:pos + length].decode('utf-8', errors='ignore'))
                pos += length

            domain = '.'.join(labels) if labels else None

            # QTYPE is the first 2 bytes after the null-terminated QNAME
            qtype = struct.unpack('!H', data[pos:pos + 2])[0] if pos + 1 < len(data) else None
            return domain, qtype
        except Exception:
            return None, None

    @staticmethod
    def _build_nxdomain(query: bytes) -> bytes:
        """
        Forge a minimal NXDOMAIN (RCODE 3) DNS response.
        Flags: QR=1 AA=0 TC=0 RD=1 RA=1 RCODE=3  →  0x8183
        """
        txn_id  = query[:2]
        flags   = struct.pack('!H', 0x8183)
        qdcount = query[4:6]
        zeros   = struct.pack('!HHH', 0, 0, 0)     # ANCOUNT NSCOUNT ARCOUNT
        return txn_id + flags + qdcount + zeros + query[12:]

    @staticmethod
    def _build_servfail(query: bytes) -> bytes:
        """Forge a SERVFAIL (RCODE 2) DNS response (used when upstream times out)."""
        txn_id  = query[:2]
        flags   = struct.pack('!H', 0x8182)
        qdcount = query[4:6]
        zeros   = struct.pack('!HHH', 0, 0, 0)
        return txn_id + flags + qdcount + zeros + query[12:]

    def _forward(self, data: bytes, timeout: float = 3.0):
        """
        Forward *data* to the upstream resolver and return its response,
        or None on timeout / error.
        """
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.settimeout(timeout)
                s.sendto(data, (self.upstream_dns, 53))
                response, _ = s.recvfrom(4096)
                return response
        except Exception:
            return None

    # ------------------------------------------------------------------
    # Per-query handler
    # ------------------------------------------------------------------

    def _handle_query(self, sock: socket.socket, data: bytes, addr) -> None:
        """
        Handle one incoming DNS query in its own short-lived thread.
        Blocked  → NXDOMAIN + optional log when Scapy is inactive.
        Allowed  → forward to upstream, relay response.
        """
        try:
            if len(data) < 12:
                return

            domain, qtype_num = self._parse_query(data)
            if not domain:
                return

            client_ip = addr[0]

            # Refresh block cache every 15 s without holding the main lock
            if time.time() - self.last_block_reload > 15:
                self.reload_block_cache()

            is_blocked, rule = self._is_blocked(domain)

            if is_blocked:
                # ---- Enforcement: return NXDOMAIN ----
                try:
                    sock.sendto(self._build_nxdomain(data), addr)
                except Exception:
                    pass

                # ---- Logging when Scapy is NOT capturing ----
                # When Scapy IS running it will capture this client query and
                # the detection engine Tier-0 will label it BLOCKED automatically.
                if self.app:
                    try:
                        from services.sniffer import sniffer_service
                        if not sniffer_service.is_running:
                            qt = _DNS_QTYPE_MAP.get(qtype_num, f'TYPE{qtype_num}') if qtype_num else 'A'
                            sniffer_service.ingest_simulated_packet(
                                client_ip, domain, qt, None, None
                            )
                    except Exception:
                        pass
            else:
                # ---- Forward to upstream resolver ----
                response = self._forward(data)
                try:
                    sock.sendto(response if response else self._build_servfail(data), addr)
                except Exception:
                    pass

        except Exception:
            pass   # never crash the sinkhole thread

    # ------------------------------------------------------------------
    # Server lifecycle
    # ------------------------------------------------------------------

    def _server_worker(self) -> None:
        """Main loop: receive UDP DNS packets and spawn handler threads."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.settimeout(1.0)          # allows stop_event check every second

        try:
            sock.bind((self.bind_address, self.port))
            self.error_message = ''
            print(f"[DNSSinkhole] Listening on {self.bind_address}:{self.port}  "
                  f"upstream={self.upstream_dns}")
        except OSError as exc:
            self.error_message = str(exc)
            print(f"[DNSSinkhole] Failed to bind on port {self.port}: {exc}")
            with self._lock:
                self.is_running = False
            return

        while not self.stop_event.is_set():
            try:
                data, addr = sock.recvfrom(512)
                threading.Thread(
                    target=self._handle_query,
                    args=(sock, data, addr),
                    daemon=True
                ).start()
            except socket.timeout:
                continue
            except Exception as exc:
                if not self.stop_event.is_set():
                    print(f"[DNSSinkhole] Socket error: {exc}")

        sock.close()
        print("[DNSSinkhole] Server stopped.")

    def start(self, port: int = None, upstream_dns: str = None):
        """
        Start the DNS sinkhole.
        Returns (success: bool, message: str).
        """
        with self._lock:
            if self.is_running:
                return False, "DNS Sinkhole is already running."

        if port is not None:
            self.port = int(port)
        if upstream_dns:
            self.upstream_dns = upstream_dns.strip()

        self.stop_event.clear()
        self.reload_block_cache()

        # Test-bind before spawning the thread so we can return a clear error
        try:
            probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            probe.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            probe.bind((self.bind_address, self.port))
            probe.close()
        except OSError as exc:
            self.error_message = str(exc)
            return False, (
                f"Cannot bind to port {self.port}: {exc}.  "
                "To free port 53 on Windows, run as Administrator: net stop Dnscache"
            )

        with self._lock:
            self.is_running = True

        self.server_thread = threading.Thread(
            target=self._server_worker,
            daemon=True,
            name='DNSWatch-Sinkhole'
        )
        self.server_thread.start()
        return True, (
            f"DNS Sinkhole started on port {self.port} "
            f"(upstream: {self.upstream_dns}). "
            "Point client DNS to this machine's IP to enforce blocking."
        )

    def stop(self):
        """Stop the DNS sinkhole. Returns (success, message)."""
        with self._lock:
            if not self.is_running:
                return False, "DNS Sinkhole is not running."
            self.stop_event.set()
            self.is_running = False

        if self.server_thread and self.server_thread.is_alive():
            self.server_thread.join(timeout=5)

        print("[DNSSinkhole] Sinkhole stopped.")
        return True, "DNS Sinkhole stopped."

    def get_status(self) -> dict:
        with self._lock:
            return {
                'is_running': self.is_running,
                'port': self.port,
                'upstream_dns': self.upstream_dns,
                'blocked_domains_count': len(self.blocked_domains),
                'status': 'Active' if self.is_running else 'Inactive',
                'error_message': self.error_message or ''
            }


# Module-level singleton – imported by routes and app.py
dns_sinkhole_service = DNSSinkholeService()
