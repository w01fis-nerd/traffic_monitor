# Real-time Traffic Monitor and Alert System

A Python-based network monitoring tool that provides real-time traffic analysis and threat detection capabilities.

## Features

- Real-time packet capture and analysis
- HTTP traffic monitoring
- Suspicious activity detection
- Port scanning of suspicious IPs
- Sensitive data detection
- Continuous logging and statistics
- Colorized console output
- JSON-based statistics export

## Requirements

- Python 3.7+
- Administrator/root privileges (for packet capture)
- Nmap installed on your system

## Installation

1. Clone this repository:
```bash
git clone <repository-url>
cd <repository-directory>
```

2. Install the required Python packages:
```bash
pip install -r requirements.txt
```

3. Install Nmap on your system if not already installed:
- Windows: Download from https://nmap.org/download.html
- Linux: `sudo apt-get install nmap`
- macOS: `brew install nmap`

## Usage

1. Run the script with administrator/root privileges:

```bash
# Windows (PowerShell Admin)
python network_monitor.py

# Linux/macOS
sudo python3 network_monitor.py
```

2. The script will start monitoring network traffic on the default interface (eth0).
   To specify a different interface, modify the interface parameter in the script.

## Output Files

- `network_monitor.log`: Contains detailed logs of all detected events
- `network_stats.json`: Contains statistics updated every 5 minutes

## Alerts

The system will generate alerts for:
- Excessive traffic from specific IPs
- Detection of sensitive information in HTTP POST requests
- Suspicious port scanning activity
- HTTP request monitoring

## Security Considerations

- Run this tool only on networks you own or have permission to monitor
- Be aware that port scanning might trigger security systems
- Handle any captured sensitive data according to your security policies

## License

This project is licensed under the MIT License - see the LICENSE file for details. 
