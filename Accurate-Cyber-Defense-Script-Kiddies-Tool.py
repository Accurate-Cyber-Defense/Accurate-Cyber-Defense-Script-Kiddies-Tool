import asyncio
import datetime
import json
import os
import platform
import re
import socket
import subprocess
import sys
import threading
import time
from collections import deque
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Union

import psutil
from scapy.all import ARP, ICMP, ICMPv6EchoRequest, IP, TCP, UDP, IPv6, conf, sniff, sr1, srp
from scapy.layers.inet6 import ICMPv6EchoRequest, IPv6, ICMPv6ND_NS, ICMPv6ND_NA
from scapy.layers.l2 import Ether

# Try to import Telegram, but make it optional
try:
    import requests
    TELEGRAM_AVAILABLE = True
except ImportError:
    TELEGRAM_AVAILABLE = False

# Configuration
class Config:
    def __init__(self):
        self.config_file = Path.home() / ".cyber_monitor_config.json"
        self.telegram_token = None
        self.telegram_chat_id = None
        self.monitored_ips = set()
        self.scan_history = deque(maxlen=1000)
        self.thresholds = {
            'ping_timeout': 2,
            'traceroute_timeout': 3,
            'port_scan_threshold': 10,  # Ports per second
            'ddos_threshold': 1000,  # Packets per second
        }
        self.load_config()
    
    def load_config(self):
        if self.config_file.exists():
            try:
                with open(self.config_file, 'r') as f:
                    data = json.load(f)
                    self.telegram_token = data.get('telegram_token')
                    self.telegram_chat_id = data.get('telegram_chat_id')
                    self.monitored_ips = set(data.get('monitored_ips', []))
                    self.thresholds = data.get('thresholds', self.thresholds)
            except Exception as e:
                print(f"Error loading config: {e}")
    
    def save_config(self):
        try:
            data = {
                'telegram_token': self.telegram_token,
                'telegram_chat_id': self.telegram_chat_id,
                'monitored_ips': list(self.monitored_ips),
                'thresholds': self.thresholds
            }
            with open(self.config_file, 'w') as f:
                json.dump(data, f, indent=4)
            return True
        except Exception as e:
            print(f"Error saving config: {e}")
            return False

# Network Monitoring
class NetworkMonitor:
    def __init__(self, config):
        self.config = config
        self.packet_counts = {}
        self.port_scan_attempts = {}
        self.ddos_detections = 0
        self.last_reset = time.time()
        self.sniffing = False
        self.sniffer_thread = None
    
    def start_monitoring(self):
        """Start monitoring network traffic for threats"""
        if self.sniffing:
            return "Already monitoring network"
        
        self.sniffing = True
        self.sniffer_thread = threading.Thread(target=self._sniff_packets, daemon=True)
        self.sniffer_thread.start()
        return "Started network monitoring"
    
    def stop_monitoring(self):
        """Stop monitoring network traffic"""
        self.sniffing = False
        return "Stopped network monitoring"
    
    def _sniff_packets(self):
        """Sniff network packets for analysis"""
        try:
            sniff(prn=self._analyze_packet, store=False, stop_filter=lambda x: not self.sniffing)
        except Exception as e:
            print(f"Error in packet sniffing: {e}")
    
    def _analyze_packet(self, packet):
        """Analyze packets for security threats"""
        current_time = time.time()
        
        # Reset counters every minute
        if current_time - self.last_reset > 60:
            self.packet_counts.clear()
            self.port_scan_attempts.clear()
            self.last_reset = current_time
        
        # Check for DDOS attacks
        if IP in packet:
            src_ip = packet[IP].src
            self.packet_counts[src_ip] = self.packet_counts.get(src_ip, 0) + 1
            
            if self.packet_counts[src_ip] > self.config.thresholds['ddos_threshold']:
                self.ddos_detections += 1
                message = f"⚠️ Possible DDOS attack detected from {src_ip} - {self.packet_counts[src_ip]} packets/sec"
                print(message)
                self.config.scan_history.append({
                    'timestamp': datetime.datetime.now().isoformat(),
                    'type': 'DDOS Detection',
                    'target': src_ip,
                    'message': message
                })
                self._send_telegram_alert(message)
        
        # Check for port scanning
        if TCP in packet and packet[TCP].flags == 2:  # SYN packet
            src_ip = packet[IP].src if IP in packet else None
            dst_port = packet[TCP].dport
            
            if src_ip:
                if src_ip not in self.port_scan_attempts:
                    self.port_scan_attempts[src_ip] = {'ports': set(), 'first_seen': current_time}
                
                self.port_scan_attempts[src_ip]['ports'].add(dst_port)
                scan_duration = current_time - self.port_scan_attempts[src_ip]['first_seen']
                scan_rate = len(self.port_scan_attempts[src_ip]['ports']) / max(scan_duration, 1)
                
                if scan_rate > self.config.thresholds['port_scan_threshold']:
                    message = f"⚠️ Possible port scan detected from {src_ip} - {len(self.port_scan_attempts[src_ip]['ports'])} ports in {scan_duration:.1f}s"
                    print(message)
                    self.config.scan_history.append({
                        'timestamp': datetime.datetime.now().isoformat(),
                        'type': 'Port Scan Detection',
                        'target': src_ip,
                        'message': message
                    })
                    self._send_telegram_alert(message)
    
    def _send_telegram_alert(self, message):
        """Send alert via Telegram if configured"""
        if self.config.telegram_token and self.config.telegram_chat_id and TELEGRAM_AVAILABLE:
            try:
                url = f"https://api.telegram.org/bot{self.config.telegram_token}/sendMessage"
                data = {
                    "chat_id": self.config.telegram_chat_id,
                    "text": message
                }
                requests.post(url, data=data, timeout=10)
            except Exception as e:
                print(f"Failed to send Telegram alert: {e}")

# Security Scanner
class SecurityScanner:
    def __init__(self, config):
        self.config = config
    
    def ping(self, target, ipv6=False):
        """Ping a target IP address"""
        try:
            param = "-n" if platform.system().lower() == "windows" else "-c"
            command = ["ping", param, "4", target]
            result = subprocess.run(command, capture_output=True, text=True, timeout=10)
            
            # Log the action
            self.config.scan_history.append({
                'timestamp': datetime.datetime.now().isoformat(),
                'type': 'Ping',
                'target': target,
                'command': ' '.join(command),
                'output': result.stdout
            })
            
            return result.stdout
        except subprocess.TimeoutExpired:
            return "Ping request timed out"
        except Exception as e:
            return f"Ping failed: {e}"
    
    def ping6(self, target):
        """Ping an IPv6 address"""
        return self.ping(target, ipv6=True)
    
    def traceroute(self, target, ipv6=False, protocol='icmp'):
        """Perform a traceroute to a target"""
        try:
            if ipv6:
                command = ["traceroute6", target]
            else:
                command = ["traceroute", target]
            
            result = subprocess.run(command, capture_output=True, text=True, timeout=30)
            
            # Log the action
            self.config.scan_history.append({
                'timestamp': datetime.datetime.now().isoformat(),
                'type': 'Traceroute',
                'target': target,
                'command': ' '.join(command),
                'output': result.stdout
            })
            
            return result.stdout
        except subprocess.TimeoutExpired:
            return "Traceroute timed out"
        except Exception as e:
            return f"Traceroute failed: {e}"
    
    def udp_traceroute(self, target, ipv6=False):
        """Perform a UDP traceroute"""
        try:
            if ipv6:
                command = ["traceroute6", "-U", target]
            else:
                command = ["traceroute", "-U", target]
            
            result = subprocess.run(command, capture_output=True, text=True, timeout=30)
            return result.stdout
        except subprocess.TimeoutExpired:
            return "UDP Traceroute timed out"
        except Exception as e:
            return f"UDP Traceroute failed: {e}"
    
    def tcp_traceroute(self, target, ipv6=False):
        """Perform a TCP traceroute"""
        try:
            if ipv6:
                command = ["traceroute6", "-T", target]
            else:
                command = ["traceroute", "-T", target]
            
            result = subprocess.run(command, capture_output=True, text=True, timeout=30)
            return result.stdout
        except subprocess.TimeoutExpired:
            return "TCP Traceroute timed out"
        except Exception as e:
            return f"TCP Traceroute failed: {e}"
    
    def scan_ports(self, target, ipv6=False):
        """Scan common ports on a target"""
        try:
            # Common ports to scan
            common_ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080]
            open_ports = []
            
            for port in common_ports:
                try:
                    sock = socket.socket(socket.AF_INET6 if ipv6 else socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(1)
                    result = sock.connect_ex((target, port))
                    if result == 0:
                        open_ports.append(port)
                    sock.close()
                except:
                    pass
            
            # Get service names for open ports
            services = []
            for port in open_ports:
                try:
                    service = socket.getservbyport(port)
                    services.append(f"{port}/{service}")
                except:
                    services.append(str(port))
            
            result = f"Open ports on {target}: {', '.join(services)}" if services else f"No open ports found on {target}"
            
            # Log the action
            self.config.scan_history.append({
                'timestamp': datetime.datetime.now().isoformat(),
                'type': 'Port Scan',
                'target': target,
                'result': result
            })
            
            return result
        except Exception as e:
            return f"Port scan failed: {e}"
    
    def scan_vulnerabilities(self, target):
        """Basic vulnerability assessment (simulated)"""
        # In a real tool, this would integrate with vulnerability scanners like OpenVAS or Nessus
        # This is a simplified simulation for demonstration purposes
        
        result = f"Vulnerability scan results for {target}:\n"
        result += "[-] No critical vulnerabilities found\n"
        result += "[+] 2 medium severity vulnerabilities detected:\n"
        result += "    - SSL/TLS weak cipher suites\n"
        result += "    - HTTP security headers missing\n"
        result += "[+] 5 low severity vulnerabilities detected\n"
        
        # Log the action
        self.config.scan_history.append({
            'timestamp': datetime.datetime.now().isoformat(),
            'type': 'Vulnerability Scan',
            'target': target,
            'result': result
        })
        
        return result

# Telegram Integration
class TelegramIntegration:
    def __init__(self, config):
        self.config = config
    
    def test_connection(self):
        """Test Telegram connection"""
        if not TELEGRAM_AVAILABLE:
            return "Telegram integration requires the 'requests' library. Install it with 'pip install requests'"
        
        if not self.config.telegram_token or not self.config.telegram_chat_id:
            return "Telegram token or chat ID not configured"
        
        try:
            url = f"https://api.telegram.org/bot{self.config.telegram_token}/getMe"
            response = requests.get(url, timeout=10)
            if response.status_code == 200:
                return "Telegram connection successful"
            else:
                return f"Telegram connection failed: {response.status_code}"
        except Exception as e:
            return f"Telegram connection failed: {e}"
    
    def export_to_telegram(self):
        """Export scan history to Telegram"""
        if not TELEGRAM_AVAILABLE:
            return "Telegram integration requires the 'requests' library. Install it with 'pip install requests'"
        
        if not self.config.telegram_token or not self.config.telegram_chat_id:
            return "Telegram token or chat ID not configured"
        
        try:
            # Prepare message with history
            message = "Accurate Cyber Defense Tool - Scan History\n\n"
            for item in list(self.config.scan_history)[-10:]:  # Last 10 items
                message += f"{item['timestamp']} - {item['type']} - {item.get('target', 'N/A')}\n"
                if 'message' in item:
                    message += f"    {item['message']}\n"
                message += "\n"
            
            # Send message
            url = f"https://api.telegram.org/bot{self.config.telegram_token}/sendMessage"
            data = {
                "chat_id": self.config.telegram_chat_id,
                "text": message
            }
            response = requests.post(url, data=data, timeout=10)
            
            if response.status_code == 200:
                return "History exported to Telegram successfully"
            else:
                return f"Failed to export history: {response.status_code}"
        except Exception as e:
            return f"Failed to export history: {e}"

# User Interface
class CyberSecurityTool:
    def __init__(self):
        self.config = Config()
        self.monitor = NetworkMonitor(self.config)
        self.scanner = SecurityScanner(self.config)
        self.telegram = TelegramIntegration(self.config)
        self.running = True
        self.setup_ui()
    
    def setup_ui(self):
        """Setup the UI with green theme"""
        # This is a simplified text-based UI with green coloring
        if os.name == 'nt':  # Windows
            os.system('color 0a')
        else:  # Unix/Linux/Mac
            print("\033[0;32m")  # Green text
    
    def display_banner(self):
        """Display the tool banner"""
        banner = """
        #######################################################
        #                   Accurate Cyber Defense           #
        #                   Monitoring & Defense             #
        #######################################################
        """
        print(banner)
    
    def display_help(self):
        """Display help information"""
        help_text = """
        Available Commands:
        
        help - Show this help message
        ping <ip> - Ping an IP address
        ping6 <ip> - Ping an IPv6 address
        traceroute <ip> - Traceroute to an IP address
        udptraceroute <ip> - UDP traceroute to an IP address
        tcptraceroute <ip> - TCP traceroute to an IP address
        udptraceroute6 <ip> - UDP traceroute to an IPv6 address
        tcptraceroute6 <ip> - TCP traceroute to an IPv6 address
        scan <ip> - Scan common ports on an IP address
        scan6 <ip> - Scan common ports on an IPv6 address
        vulnscan <ip> - Scan for vulnerabilities (simulated)
        add <ip> - Add an IP to monitoring list
        remove <ip> - Remove an IP from monitoring list
        config telegram token <token> - Set Telegram bot token
        config telegram chat_id <id> - Set Telegram chat ID
        history - View scan history
        export telegram - Export history to Telegram
        test telegram - Test Telegram connection
        start monitor - Start network monitoring
        stop monitor - Stop network monitoring
        clear - Clear the screen
        exit - Exit the tool
        """
        print(help_text)
    
    def clear_screen(self):
        """Clear the terminal screen"""
        os.system('cls' if os.name == 'nt' else 'clear')
    
    def show_history(self):
        """Display scan history"""
        if not self.config.scan_history:
            print("No history available")
            return
        
        for item in self.config.scan_history:
            print(f"{item['timestamp']} - {item['type']} - {item.get('target', 'N/A')}")
            if 'message' in item:
                print(f"    {item['message']}")
            print()
    
    def process_command(self, command):
        """Process user commands"""
        parts = command.strip().split()
        if not parts:
            return
        
        cmd = parts[0].lower()
        args = parts[1:]
        
        if cmd == "help":
            self.display_help()
        
        elif cmd == "ping" and len(args) == 1:
            result = self.scanner.ping(args[0])
            print(result)
        
        elif cmd == "ping6" and len(args) == 1:
            result = self.scanner.ping6(args[0])
            print(result)
        
        elif cmd == "traceroute" and len(args) == 1:
            result = self.scanner.traceroute(args[0])
            print(result)
        
        elif cmd == "udptraceroute" and len(args) == 1:
            result = self.scanner.udp_traceroute(args[0])
            print(result)
        
        elif cmd == "tcptraceroute" and len(args) == 1:
            result = self.scanner.tcp_traceroute(args[0])
            print(result)
        
        elif cmd == "udptraceroute6" and len(args) == 1:
            result = self.scanner.udp_traceroute(args[0], ipv6=True)
            print(result)
        
        elif cmd == "tcptraceroute6" and len(args) == 1:
            result = self.scanner.tcp_traceroute(args[0], ipv6=True)
            print(result)
        
        elif cmd == "scan" and len(args) == 1:
            result = self.scanner.scan_ports(args[0])
            print(result)
        
        elif cmd == "scan6" and len(args) == 1:
            result = self.scanner.scan_ports(args[0], ipv6=True)
            print(result)
        
        elif cmd == "vulnscan" and len(args) == 1:
            result = self.scanner.scan_vulnerabilities(args[0])
            print(result)
        
        elif cmd == "add" and len(args) == 1:
            if self._is_valid_ip(args[0]):
                self.config.monitored_ips.add(args[0])
                self.config.save_config()
                print(f"Added {args[0]} to monitoring list")
            else:
                print("Invalid IP address")
        
        elif cmd == "remove" and len(args) == 1:
            if args[0] in self.config.monitored_ips:
                self.config.monitored_ips.remove(args[0])
                self.config.save_config()
                print(f"Removed {args[0]} from monitoring list")
            else:
                print("IP not in monitoring list")
        
        elif cmd == "config" and len(args) >= 3:
            if args[0] == "telegram":
                if args[1] == "token":
                    self.config.telegram_token = ' '.join(args[2:])
                    self.config.save_config()
                    print("Telegram token configured")
                elif args[1] == "chat_id":
                    self.config.telegram_chat_id = ' '.join(args[2:])
                    self.config.save_config()
                    print("Telegram chat ID configured")
                else:
                    print("Invalid config option")
            else:
                print("Invalid config section")
        
        elif cmd == "history":
            self.show_history()
        
        elif cmd == "export" and len(args) == 1 and args[0] == "telegram":
            result = self.telegram.export_to_telegram()
            print(result)
        
        elif cmd == "test" and len(args) == 1 and args[0] == "telegram":
            result = self.telegram.test_connection()
            print(result)
        
        elif cmd == "start" and len(args) == 1 and args[0] == "monitor":
            result = self.monitor.start_monitoring()
            print(result)
        
        elif cmd == "stop" and len(args) == 1 and args[0] == "monitor":
            result = self.monitor.stop_monitoring()
            print(result)
        
        elif cmd == "clear":
            self.clear_screen()
        
        elif cmd == "exit":
            self.running = False
            print("Exiting Accurate Cyber Defense Security Tool")
        
        else:
            print("Invalid command. Type 'help' for available commands.")
    
    def _is_valid_ip(self, ip):
        """Check if a string is a valid IP address"""
        try:
            socket.inet_pton(socket.AF_INET, ip)
            return True
        except socket.error:
            try:
                socket.inet_pton(socket.AF_INET6, ip)
                return True
            except socket.error:
                return False
    
    def run(self):
        """Main run loop"""
        self.clear_screen()
        self.display_banner()
        
        while self.running:
            try:
                command = input("cyber-tool> ")
                self.process_command(command)
            except KeyboardInterrupt:
                print("\nUse 'exit' to quit the tool")
            except Exception as e:
                print(f"Error: {e}")

# Main entry point
if __name__ == "__main__":
    # Check for root privileges (required for some network operations)
    if os.name != 'nt' and os.geteuid() != 0:
        print("This tool requires root privileges for network monitoring.")
        print("Please run with sudo or as administrator.")
        sys.exit(1)
    
    # Check for scapy
    try:
        import scapy
    except ImportError:
        print("This tool requires scapy. Install it with: pip install scapy")
        sys.exit(1)
    
    tool = CyberSecurityTool()
    tool.run()