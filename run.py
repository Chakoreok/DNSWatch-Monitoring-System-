import os
from app import create_app

app = create_app()

if __name__ == '__main__':
    port = int(os.getenv("PORT", 5000))
    print(f"==================================================")
    print(f"   DNSWatch: DNS Security Monitoring System       ")
    print(f"   Running on http://127.0.0.1:{port}             ")
    print(f"==================================================")
    app.run(host='0.0.0.0', port=port, debug=False, threaded=True)
