# mini-port-scanner
A fast and lightweight Python-based port scanner that detects open TCP ports, supports banner grabbing, and exports results in multiple formats (CSV, JSON). Built for learning cybersecurity and penetration testing fundamentals.
# Mini Port Scanner

A simple and efficient Python-based port scanner that allows you to detect open TCP ports, grab banners, and export results into CSV or JSON formats. 
It supports multi-threading for faster scans.

## 🚀 Features
- Scan a target for open TCP ports
- Supports custom port ranges
- Banner grabbing (detects service information)
- Export results to CSV and JSON
- Multi-threaded scanning for performance

## 🛠️ Usage
# Scan local HTTP server on port 8000
python3 port_scanner.py --target 127.0.0.1 --ports 8000 --banner

# Scan a range of ports with banner grabbing
python3 port_scanner.py --target 127.0.0.1 --ports 8000-8010 --banner

# Export results to CSV
python3 port_scanner.py --target 127.0.0.1 --ports 1-1024 --out csv --outfile open_ports.csv

# Export results to JSON
python3 port_scanner.py --target 127.0.0.1 --ports 1-1024 --out json --outfile open_ports.json

## 📊 Example Output
Open TCP Ports:
PORT     SERVICE        BANNER/NOTE
8000     http-alt       HTTP/1.0 200 OK Server: SimpleHTTP/0.6 Python/3.13.5
80       http           Apache httpd 2.4.41
139      netbios-ssn    Microsoft Windows NetBIOS
443      https          OpenSSL Service
445      microsoft-ds   Windows SMB Service

## 📂 Project Structure
mini-port-scanner/
│
├── port_scanner.py               # Main Python script
│
├── README.md                     # Project overview
│
├── reports/
│   └── mini_port_scanner_report.pdf   # Project mini-report
│
├── results/
│   ├── open_ports.csv            # Example output (CSV)
│   └── open_ports.json           # Example output (JSON)
│
└── screenshots/
    └── screenshot_usage.png      # Screenshot of running the tool
