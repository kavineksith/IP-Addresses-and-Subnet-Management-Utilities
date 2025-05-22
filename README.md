# Network Calculator Suite

A comprehensive collection of network calculation tools for IPv4 and IPv6 addressing, subnetting, and CIDR notation conversions.

## 📦 Toolset Overview

1. **CIDR Notation Converter**
   - Convert between subnet masks, CIDR notation, and IP ranges
   - Supports both interactive and CLI modes
   - IPv4 focused with IPv6 scaffolding

2. **IPv4 Subnet Calculator**
   - Calculate subnets by network count or host requirements
   - Detailed network analysis and reporting
   - JSON, CSV, and text output formats

3. **IPv6 Subnet Calculator**
   - Full IPv6 address parsing and validation
   - CIDR-based subnet calculations
   - Address type detection and conversions

## 🚀 Features

- **Dual-mode operation**: Interactive shell and command-line interface
- **Batch processing**: Handle multiple IPs/subnets simultaneously
- **Multiple output formats**: JSON, CSV, plain text
- **Comprehensive logging**: Debug and audit all operations
- **Threaded processing**: Optimized performance for large datasets
- **Robust validation**: Graceful handling of invalid inputs

## 📋 Installation

```bash
git clone https://github.com/your-repo/network-calculators.git
cd network-calculators
```

**Requirements**: Python 3.10+

## 🛠️ Usage

### CIDR Notation Converter
```bash
python cidr.py [subnet-mask|subnet|ip-range] <input> [--output file.json]
```

### IPv4 Subnet Calculator
```bash
python ipv4_calculator.py <network_ip/prefix> (--networks N | --hosts H) [--output json|csv|txt]
```

### IPv6 Subnet Calculator
```bash
python ipv6_calculator.py --ip "2001:db8::/64" [--output-format json|csv|txt]
```

For interactive mode, run any script without arguments.

## 📄 Sample Outputs

**CIDR Conversion**:
```json
{
  "input": "255.255.255.0",
  "type": "subnet_mask",
  "cidr_notation": "/24",
  "ip_version": "IPV4"
}
```

**IPv4 Subnet Calculation**:
```json
{
  "network": "192.168.1.0/24",
  "subnets": 8,
  "new_prefix": "/27",
  "subnet_details": [...]
}
```

**IPv6 Address Analysis**:
```json
{
  "address": "2001:db8::1",
  "type": "Global Unicast",
  "binary": "0010000000000001...",
  "subnet": "2001:db8::/64"
}
```

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

## ⚠️ Disclaimer

This software is provided "as is" without warranty of any kind, express or implied. The authors are not responsible for any legal implications of generated license files or repository management actions. It is designed for educational and professional use. Use it responsibly, especially when processing large or sensitive datasets. **This is a personal project intended for educational purposes. The developer makes no guarantees about the reliability or security of this software. Use at your own risk.**
