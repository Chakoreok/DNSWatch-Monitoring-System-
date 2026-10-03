import os
from app import create_app

app = create_app()

if __name__ == '__main__':
    port = int(os.getenv("PORT", 5000))
    # Lets the cloud (Render) dashboard start/stop packet capture on this machine.
    # Set SENSOR_AGENT=0 in .env to disable.
    if os.getenv("SENSOR_AGENT", "1") != "0":
        from services.sniffer import sniffer_service
        sniffer_service.start_sensor_agent()
    print(f"==================================================")
    print(f"   DNSWatch: DNS Security Monitoring System       ")
    print(f"   Running on http://127.0.0.1:{port}             ")
    print(f"==================================================")
    app.run(host='0.0.0.0', port=port, debug=False, threaded=True)
