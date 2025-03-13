# Network Segmentation Testing Tool

This tool is designed for testing network segmentation and firewall rules using various techniques with Scapy. It provides multiple testing methods including IP spoofing, TCP/UDP port scanning, and VLAN hopping tests.

## Prerequisites

- Python 3.x
- Scapy library
- Administrator/Root privileges (required for raw socket operations)

### Windows-Specific Requirements
- Npcap (Required for packet capture and injection on Windows)
  - Download from: https://npcap.com/
  - Install with "WinPcap API-compatible Mode" option checked
- Make sure to run the script as Administrator
- You may need to configure Windows Defender Firewall to allow the script

### Linux/Unix Requirements
- No additional requirements beyond the basic prerequisites

## Installation

1. Install the required package:
```bash
pip install scapy
```

2. For Windows systems only:
   - Download and install Npcap from https://npcap.com/
   - During Npcap installation, make sure to check "Install Npcap in WinPcap API-compatible Mode"
   - You may need to restart your system after installing Npcap

3. Clone or download this repository

## Usage

The script provides several testing modes that can be used to validate network segmentation:

### Basic Usage

Windows (Command Prompt as Administrator):
```cmd
python network_tester.py --target TARGET_IP --mode MODE [additional options]
```

Linux/Unix:
```bash
sudo python network_tester.py --target TARGET_IP --mode MODE [additional options]
```

### Available Modes

1. **Ping Test with IP Spoofing**
```bash
sudo python network_tester.py --target 192.168.1.1 --mode ping --source 10.0.0.1
```

2. **TCP SYN Scan**
```bash
sudo python network_tester.py --target 192.168.1.1 --mode tcp --ports 80,443,22
```

3. **UDP Port Scan**
```bash
sudo python network_tester.py --target 192.168.1.1 --mode udp --ports 53,161,123
```

4. **VLAN Hopping Test**
```bash
sudo python network_tester.py --target 192.168.1.1 --mode vlan --vlan 100
```

### Command Line Arguments

- `--target`: Target IP address (required)
- `--mode`: Test mode (required) - choices: ping, tcp, udp, vlan
- `--source`: Source IP address for spoofing (optional)
- `--ports`: Comma-separated list of ports to scan (optional)
- `--vlan`: VLAN ID for VLAN hopping test (optional)

## Features

1. **IP Spoofing with ICMP**
   - Sends spoofed ICMP ping requests
   - Tests if firewalls properly filter spoofed source addresses

2. **TCP SYN Scanning**
   - Performs TCP SYN scans with optional source IP spoofing
   - Identifies open, closed, and filtered ports
   - Automatically sends RST packets to close half-open connections

3. **UDP Port Scanning**
   - Tests UDP ports with customizable payloads
   - Identifies open, closed, and filtered ports
   - Interprets ICMP responses for port state determination

4. **VLAN Hopping Tests**
   - Tests for VLAN hopping vulnerabilities using double tagging
   - Helps identify misconfigured trunk ports
   - Supports custom VLAN IDs

## Security Notice

This tool is intended for educational purposes and testing your own network infrastructure. Always ensure you have proper authorization before testing any network infrastructure.

## Logging

The tool provides detailed logging of all operations and results. Logs include:
- Timestamp
- Operation type
- Results and responses
- Error messages (if any)

## Error Handling

The script includes comprehensive error handling for:
- Network timeouts
- Permission issues
- Invalid input parameters
- Network connectivity problems

## Troubleshooting

### Windows-Specific Issues

1. **Permission Denied**
   - Make sure you're running the Command Prompt or PowerShell as Administrator
   - Right-click the Command Prompt/PowerShell and select "Run as administrator"

2. **Packet Capture/Injection Issues**
   - Verify Npcap is properly installed
   - Check if WinPcap API-compatible Mode is enabled
   - Try reinstalling Npcap if issues persist

3. **Firewall Blocking**
   - Temporarily disable Windows Defender Firewall for testing
   - Or add Python/Scapy to the Windows Defender Firewall exceptions

4. **Interface Issues**
   - Use `scapy show_interfaces()` to list available interfaces
   - Specify the correct interface name if default doesn't work