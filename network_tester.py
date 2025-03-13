#!/usr/bin/env python3

from scapy.all import *
import sys
import argparse
import logging
import time
import ctypes
import platform

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def is_admin():
    """
    Check if the script is running with administrator privileges
    Works on both Windows and Unix systems
    """
    try:
        if platform.system() == 'Windows':
            return ctypes.windll.shell32.IsUserAnAdmin()
        else:
            return os.geteuid() == 0
    except:
        return False

class NetworkTester:
    def __init__(self):
        self.default_interface = conf.iface

    def send_spoofed_ping(self, target_ip, spoofed_source_ip):
        """
        Send a spoofed ICMP ping packet
        """
        try:
            # Create an IP packet with a spoofed source address
            ip = IP(src=spoofed_source_ip, dst=target_ip)
            # Create an ICMP ping request
            icmp = ICMP(type=8, code=0)  # type 8 is echo request
            
            # Send the packet and wait for response
            reply = sr1(ip/icmp, timeout=2, verbose=False)
            
            if reply:
                logger.info(f"Received reply from {target_ip}")
                logger.info(f"Reply source: {reply.src}")
                logger.info(f"Reply type: {reply.type}")
            else:
                logger.warning(f"No reply received from {target_ip}")
                
        except Exception as e:
            logger.error(f"Error sending spoofed ping: {str(e)}")

    def tcp_syn_scan(self, target_ip, ports, source_ip=None):
        """
        Perform a TCP SYN scan with optional IP spoofing
        """
        if not source_ip:
            source_ip = RandIP()._fix()

        for port in ports:
            try:
                # Craft TCP SYN packet
                ip = IP(src=source_ip, dst=target_ip)
                tcp = TCP(sport=RandShort(), dport=port, flags="S")
                
                # Send packet and wait for response
                response = sr1(ip/tcp, timeout=1, verbose=False)
                
                if response is None:
                    logger.info(f"Port {port}: Filtered/Dropped")
                elif response.haslayer(TCP):
                    if response[TCP].flags == 0x12:  # SYN-ACK
                        logger.info(f"Port {port}: Open")
                        # Send RST to close connection
                        rst = IP(src=source_ip, dst=target_ip)/TCP(sport=tcp.sport, dport=port, flags="R")
                        send(rst, verbose=False)
                    elif response[TCP].flags == 0x14:  # RST-ACK
                        logger.info(f"Port {port}: Closed")
            
            except Exception as e:
                logger.error(f"Error scanning port {port}: {str(e)}")

    def udp_scan(self, target_ip, ports, source_ip=None):
        """
        Perform a UDP scan with optional IP spoofing
        """
        if not source_ip:
            source_ip = RandIP()._fix()

        for port in ports:
            try:
                # Craft UDP packet
                ip = IP(src=source_ip, dst=target_ip)
                udp = UDP(sport=RandShort(), dport=port)
                payload = Raw(load="Testing UDP port")
                
                # Send packet and wait for response
                response = sr1(ip/udp/payload, timeout=1, verbose=False)
                
                if response is None:
                    logger.info(f"UDP Port {port}: Open|Filtered")
                elif response.haslayer(ICMP):
                    if int(response[ICMP].type) == 3 and int(response[ICMP].code) == 3:
                        logger.info(f"UDP Port {port}: Closed")
                    elif int(response[ICMP].type) == 3 and int(response[ICMP].code) in [1, 2, 9, 10, 13]:
                        logger.info(f"UDP Port {port}: Filtered")
                
            except Exception as e:
                logger.error(f"Error scanning UDP port {port}: {str(e)}")

    def test_vlan_hopping(self, target_ip, vlan_id):
        """
        Test for VLAN hopping vulnerabilities using double tagging
        """
        try:
            # Create double-tagged 802.1Q packet
            ether = Ether(src=RandMAC(), dst="ff:ff:ff:ff:ff:ff")
            dot1q1 = Dot1Q(vlan=1)
            dot1q2 = Dot1Q(vlan=vlan_id)
            ip = IP(src=RandIP()._fix(), dst=target_ip)
            icmp = ICMP()
            
            # Send the packet
            pkt = ether/dot1q1/dot1q2/ip/icmp
            sendp(pkt, verbose=False)
            logger.info(f"Sent VLAN hopping test packet to VLAN {vlan_id}")
            
        except Exception as e:
            logger.error(f"Error testing VLAN hopping: {str(e)}")

def main():
    parser = argparse.ArgumentParser(description="Network Testing Tool with Scapy")
    parser.add_argument("--target", required=True, help="Target IP address")
    parser.add_argument("--mode", choices=['ping', 'tcp', 'udp', 'vlan'], required=True, help="Test mode")
    parser.add_argument("--source", help="Source IP address for spoofing")
    parser.add_argument("--ports", help="Comma-separated list of ports to scan")
    parser.add_argument("--vlan", type=int, help="VLAN ID for VLAN hopping test")
    
    args = parser.parse_args()
    
    tester = NetworkTester()
    
    if args.mode == 'ping':
        source_ip = args.source if args.source else RandIP()._fix()
        tester.send_spoofed_ping(args.target, source_ip)
    
    elif args.mode == 'tcp':
        ports = [int(p) for p in args.ports.split(',')] if args.ports else [80, 443, 22, 21]
        tester.tcp_syn_scan(args.target, ports, args.source)
    
    elif args.mode == 'udp':
        ports = [int(p) for p in args.ports.split(',')] if args.ports else [53, 161, 123]
        tester.udp_scan(args.target, ports, args.source)
    
    elif args.mode == 'vlan':
        vlan_id = args.vlan if args.vlan else 1
        tester.test_vlan_hopping(args.target, vlan_id)

if __name__ == "__main__":
    # Check if running as administrator/root
    if not is_admin():
        logger.error("This script must be run as administrator/root!")
        if platform.system() == 'Windows':
            logger.error("Please right-click the script and select 'Run as administrator'")
        else:
            logger.error("Please run with sudo")
        sys.exit(1)
    main()