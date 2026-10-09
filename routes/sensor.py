"""
routes/sensor.py
================
Secure Remote Sensor Ingestion & Telemetry API for DNSWatch.

Allows a local packet sniffer (running on the user's computer / LAN) to:
  1. Stream captured & parsed DNS packets securely to the Render backend over HTTPS.
  2. Send periodic heartbeats to maintain active sensor status on the cloud dashboard.
  3. Receive remote Start/Stop commands issued from the cloud dashboard.

Authentication:
  Checked via 'X-Sensor-Key' or 'Authorization: Bearer <key>' matching Config.SENSOR_KEY.
"""

from flask import Blueprint, request, jsonify
from config import Config
from services.sniffer import sniffer_service

sensor_bp = Blueprint('sensor', __name__)


def _authenticate_sensor(req):
    """Verify sensor key matches configured secret."""
    key = req.headers.get('X-Sensor-Key') or ''
    if not key and req.headers.get('Authorization', '').startswith('Bearer '):
        key = req.headers.get('Authorization', '')[7:].strip()

    expected_key = Config.SENSOR_KEY
    if not expected_key:
        return True  # If no key configured, allow
    return key == expected_key


@sensor_bp.route('/api/sensor/ingest', methods=['POST'])
def ingest_dns_traffic():
    """Receives parsed DNS packets from the local packet sniffer."""
    if not _authenticate_sensor(request):
        return jsonify({'success': False, 'message': 'Unauthorized sensor key.'}), 401

    data = request.get_json(silent=True) or {}
    queries = data.get('queries', [])
    if not queries and 'domain' in data:
        # Single query payload
        queries = [data]

    interface = data.get('interface', 'Local sensor')
    sensor_name = data.get('sensor_name', 'default-sensor')

    processed, alerts = sniffer_service.ingest_sensor_batch(
        queries,
        sensor_name=sensor_name,
        interface=interface
    )

    return jsonify({
        'success': True,
        'processed': processed,
        'alerts_generated': alerts
    })


@sensor_bp.route('/api/sensor/heartbeat', methods=['POST'])
def sensor_heartbeat():
    """Receives heartbeat from the local sensor and returns remote command if any."""
    if not _authenticate_sensor(request):
        return jsonify({'success': False, 'message': 'Unauthorized sensor key.'}), 401

    data = request.get_json(silent=True) or {}
    interface = data.get('interface', 'Local sensor')
    is_capturing = bool(data.get('is_capturing', False))
    total_captured = int(data.get('total_captured', 0))
    sensor_name = data.get('sensor_name', 'default-sensor')

    command = sniffer_service.record_sensor_heartbeat(
        interface=interface,
        is_capturing=is_capturing,
        total_captured=total_captured,
        sensor_name=sensor_name
    )

    return jsonify({
        'success': True,
        'command': command,
        'status': sniffer_service.get_status()
    })


@sensor_bp.route('/api/sensor/status', methods=['GET'])
def get_sensor_status():
    """Returns remote sensor connectivity status."""
    return jsonify({
        'success': True,
        'monitoring': sniffer_service.get_status()
    })
