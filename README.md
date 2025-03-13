# Network Segmentation Testing Tool

This tool is designed for testing network segmentation and firewall rules using various techniques with Scapy. It provides multiple testing methods including IP spoofing, TCP/UDP port scanning, VLAN hopping tests, and advanced firewall validation features.

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

The script provides several testing modes that can be used to validate network segmentation and firewall rules:

### Basic Usage

Windows (Command Prompt as Administrator):
```cmd
python network_tester.py --target TARGET_IP --mode MODE [additional options]
```

Linux/Unix:
```bash
sudo python network_tester.py --target TARGET_IP --mode MODE [additional options]
```

### Available Test Modes

1. **Basic Network Tests**

   a. **Ping Test with IP Spoofing** (`--mode ping`)
   ```bash
   python network_tester.py --target 192.168.1.1 --mode ping --source 10.0.0.1
   ```

   b. **TCP SYN Scan** (`--mode tcp`)
   ```bash
   python network_tester.py --target 192.168.1.1 --mode tcp --ports 80,443,22
   ```

   c. **UDP Port Scan** (`--mode udp`)
   ```bash
   python network_tester.py --target 192.168.1.1 --mode udp --ports 53,161,123
   ```

   d. **VLAN Hopping Test** (`--mode vlan`)
   ```bash
   python network_tester.py --target 192.168.1.1 --mode vlan --vlan 100
   ```

2. **Advanced Firewall Testing**

   a. **Fragment Handling Test** (`--mode fragment`)
   ```bash
   python network_tester.py --target 192.168.1.1 --mode fragment --ports 80
   ```
   - Tests firewall's ability to handle fragmented packets
   - Sends fragments in reverse order to test reassembly
   - Detects if firewall blocks or properly reassembles fragments

   b. **Protocol Enforcement Test** (`--mode protocol`)
   ```bash
   python network_tester.py --target 192.168.1.1 --mode protocol
   ```
   - Tests Deep Packet Inspection (DPI) capabilities
   - Attempts HTTP traffic over non-HTTP ports
   - Tests handling of malformed protocol headers

   c. **Rate Limiting Detection** (`--mode rate`)
   ```bash
   python network_tester.py --target 192.168.1.1 --mode rate --packets 200 --interval 0.5
   ```
   - Tests for rate limiting implementation
   - Configurable packet count and interval
   - Measures success rate to detect throttling

   d. **State Tracking Test** (`--mode state`)
   ```bash
   python network_tester.py --target 192.168.1.1 --mode state
   ```
   - Determines if firewall is stateful or stateless
   - Tests handling of out-of-state packets
   - Validates TCP connection state tracking

   e. **Policy Consistency Check** (`--mode policy`)
   ```bash
   python network_tester.py --target 192.168.1.1 --mode policy
   ```
   - Tests rule consistency across protocols
   - Checks common service ports
   - Identifies policy inconsistencies between TCP/UDP

### Command Line Arguments

- `--target`: Target IP address (required)
- `--mode`: Test mode (required) - choices: ping, tcp, udp, vlan, fragment, protocol, rate, state, policy
- `--source`: Source IP address for spoofing (optional)
- `--ports`: Comma-separated list of ports to scan (optional)
- `--vlan`: VLAN ID for VLAN hopping test (optional)
- `--packets`: Number of packets for rate limiting test (default: 100)
- `--interval`: Interval for rate limiting test in seconds (default: 1.0)

## Port State Detection

The tool uses the following methods to determine port states:

### TCP Port States
- **Open**: Receives SYN-ACK (flags 0x12)
- **Closed**: Receives RST-ACK (flags 0x14)
- **Filtered**: No response or ICMP unreachable

### UDP Port States
- **Open|Filtered**: No response (UDP being stateless makes this ambiguous)
- **Closed**: ICMP Port Unreachable (type 3, code 3)
- **Filtered**: Other ICMP messages (codes 1,2,9,10,13)

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

## Best Practices for Testing

1. Start with basic port scans to understand the network topology
2. Use state tracking tests to determine firewall sophistication
3. Follow up with protocol enforcement tests for DPI detection
4. Use rate limiting tests to understand throttling policies
5. Finally, run policy consistency checks to find misconfigurations