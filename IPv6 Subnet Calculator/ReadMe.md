# IPv6 Subnet Calculator

**IPv6 Subnet Calculator** is a Python-based command-line tool for calculating and analyzing IPv6 subnets. Designed for reliability, flexibility, and clarity, this tool helps network engineers, system administrators, and enthusiasts:

* Subnet a network based on a required number of **hosts** or **subnetworks**
* Validate and interpret IPv6 addresses and prefixes
* Analyze subnet details like usable addresses, broadcast address, etc.
* Log all actions for troubleshooting and auditing

## 🛠 Features

* 📥 Input validation for IPv6 network format
* ⚙️ Calculate subnets by host count or network count
* 🔍 View detailed network and subnet summaries
* 📁 Logs all operations (`ipv6_subnet_calculator.log`)
* 🧱 Robust exception handling
* 🧪 Built with `ipaddress`, `math`, `logging`, and standard libraries

## 🚀 Getting Started

### Prerequisites

* Python 3.10+
* Cross-platform (Windows, macOS, Linux)

### Installation

1. Clone the repository or download the script

2. Ensure the script is executable:

```bash
chmod +x ipv6_subnet_calculator.py
```

## 📈 Usage

Run the script using:

```bash
./ipv6_subnet_calculator.py
```

Or with Python explicitly:

```bash
python3 ipv6_subnet_calculator.py
```

You will be prompted for the following:

1. **IPv6 network** with prefix (e.g., `2001:db8::/32`)
2. Choose **calculation mode**:

   * `1`: Subnet based on number of hosts per subnet
   * `2`: Subnet based on number of subnets required
3. Enter the appropriate count for the chosen mode

### Example

```plaintext
Enter the network IP address with prefix (e.g., 2001:db8::/32): 2001:db8::/48
Calculation Mode:
1. Calculate by number of hosts per subnet
2. Calculate by number of networks
Enter your choice (1 or 2): 2
Enter the number of networks required: 64
```

The tool will then calculate and display a summary and up to 5 subnets.

## 📄 Sample Output

```
Network: 2001:db8::/48
Prefix Length: /48
Total Addresses: 1,208,925,819,614,629,174,706,176
...

Subnet 1:
Network Address: 2001:db8::
First Usable: 2001:db8::1
Last Usable: 2001:db8::ffff:ffff:ffff:fffe
...
```

All logs will be written to `ipv6_subnet_calculator.log`.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

## Disclaimer

This software is provided "as is" without warranty of any kind, express or implied. The authors are not responsible for any legal implications of generated license files or repository management actions. It is intended for educational and operational use. Users are responsible for validating the results before applying them in critical production environments.  **This is a personal project intended for educational purposes. The developer makes no guarantees about the reliability or security of this software. Use at your own risk.**
