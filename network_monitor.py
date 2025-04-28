#!/usr/bin/env python3

import scapy.all as scapy
from scapy.layers import http
import nmap
import datetime
import threading
import time
from colorama import Fore, Style, init
import pyfiglet
import logging
from collections import defaultdict
import json

# Initialize colorama
init()

# Configure logging
logging.basicConfig(
    filename='network_monitor.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

class NetworkMonitor:
    def __init__(self):
        self.suspicious_ips = set()
        self.packet_counts = defaultdict(int)
        self.connection_history = defaultdict(list)
        self.alert_threshold = 100  # Packets per minute threshold
        self.is_running = True

    def display_banner(self):
        banner = pyfiglet.figlet_format("Network Monitor")
        print(f"{Fore.CYAN}{banner}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}Real-time Traffic Monitor and Alert System{Style.RESET_ALL}\n")

    def packet_callback(self, packet):
        try:
            if packet.haslayer(scapy.IP):
                src_ip = packet[scapy.IP].src
                dst_ip = packet[scapy.IP].dst
                
                # Update packet counts
                self.packet_counts[src_ip] += 1
                
                # Log connection
                timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                self.connection_history[src_ip].append({
                    'timestamp': timestamp,
                    'destination': dst_ip,
                    'protocol': packet[scapy.IP].proto
                })

                # Check for HTTP layer
                if packet.haslayer(http.HTTPRequest):
                    url = packet[http.HTTPRequest].Host.decode() + packet[http.HTTPRequest].Path.decode()
                    print(f"{Fore.GREEN}[+] HTTP Request >> {url}{Style.RESET_ALL}")
                    
                    # Check for potential sensitive information in POST requests
                    if packet.haslayer(scapy.Raw) and packet[http.HTTPRequest].Method == b'POST':
                        load = packet[scapy.Raw].load.decode()
                        self.check_sensitive_info(load)

                # Perform threat detection
                self.detect_threats(src_ip)

        except Exception as e:
            logging.error(f"Error processing packet: {str(e)}")

    def detect_threats(self, ip):
        """Basic threat detection based on packet frequency and patterns"""
        if self.packet_counts[ip] > self.alert_threshold:
            if ip not in self.suspicious_ips:
                self.suspicious_ips.add(ip)
                alert_msg = f"⚠️ HIGH TRAFFIC ALERT: Excessive packets from {ip}"
                print(f"{Fore.RED}{alert_msg}{Style.RESET_ALL}")
                logging.warning(alert_msg)
                self.scan_suspicious_ip(ip)

    def scan_suspicious_ip(self, ip):
        """Perform a quick port scan on suspicious IPs"""
        try:
            scanner = nmap.PortScanner()
            scanner.scan(ip, arguments='-F -T4')  # Fast scan of common ports
            
            if ip in scanner.all_hosts():
                print(f"{Fore.YELLOW}[*] Port scan results for {ip}:{Style.RESET_ALL}")
                for port in scanner[ip]['tcp']:
                    state = scanner[ip]['tcp'][port]['state']
                    print(f"   Port {port}: {state}")
        except Exception as e:
            logging.error(f"Error scanning IP {ip}: {str(e)}")

    def check_sensitive_info(self, data):
        """Check for sensitive information in packet data"""
        sensitive_keywords = ['password', 'user', 'login', 'pwd', 'admin']
        for keyword in sensitive_keywords:
            if keyword in data.lower():
                alert_msg = f"🔒 SENSITIVE DATA ALERT: Possible {keyword} transmission detected"
                print(f"{Fore.RED}{alert_msg}{Style.RESET_ALL}")
                logging.warning(alert_msg)

    def start_monitoring(self, interface="eth0"):
        """Start the network monitoring"""
        self.display_banner()
        print(f"{Fore.GREEN}[*] Starting network monitoring on interface {interface}{Style.RESET_ALL}")
        print(f"{Fore.GREEN}[*] Logging to network_monitor.log{Style.RESET_ALL}")
        
        try:
            # Start packet capture
            scapy.sniff(iface=interface, store=False, prn=self.packet_callback)
        except KeyboardInterrupt:
            print(f"\n{Fore.YELLOW}[*] Monitoring stopped by user{Style.RESET_ALL}")
        except Exception as e:
            logging.error(f"Error in monitoring: {str(e)}")
            print(f"{Fore.RED}[!] Error: {str(e)}{Style.RESET_ALL}")

    def save_statistics(self):
        """Save monitoring statistics to a file"""
        stats = {
            'timestamp': datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            'suspicious_ips': list(self.suspicious_ips),
            'packet_counts': dict(self.packet_counts),
            'connection_history': dict(self.connection_history)
        }
        
        with open('network_stats.json', 'w') as f:
            json.dump(stats, f, indent=4)

if __name__ == "__main__":
    monitor = NetworkMonitor()
    try:
        # Start statistics saving thread
        def save_stats_periodically():
            while monitor.is_running:
                monitor.save_statistics()
                time.sleep(300)  # Save every 5 minutes

        stats_thread = threading.Thread(target=save_stats_periodically)
        stats_thread.daemon = True
        stats_thread.start()

        # Start monitoring
        monitor.start_monitoring()
    except KeyboardInterrupt:
        monitor.is_running = False
        print("\nShutting down...") 