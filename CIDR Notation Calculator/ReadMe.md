# CIDR Notation Converter

A robust, production-grade CIDR conversion utility for network engineers, sysadmins, and developers. This tool supports multiple conversion types between subnet masks, IP ranges, and subnets, and can be run both interactively and from the command line.

## 🚀 Features

- Convert **Subnet Masks** (e.g., `255.255.255.0`) to **CIDR Notation** (`/24`)
- Parse **CIDR Subnets** (e.g., `192.168.1.0/24`) to extract prefix length and IP version
- Convert **IP Ranges** (e.g., `192.168.1.1-192.168.1.254`) to the smallest encompassing CIDR block
- Dual-mode: **interactive shell** and **command-line interface**
- Built-in **logging** with rotating logs
- IPv4 support (IPv6 partially scaffolded for future use)

## 📦 Installation

No installation required. Just clone and run:

Requires **Python 3.10+**

## 🛠️ Usage

### 🔹 Interactive Mode

Just run the script without arguments:

```bash
python cidr.py
```

You'll enter an interactive prompt where you can choose conversion options from a menu.

### 🔹 Command-Line Mode

Use specific commands to convert input directly:

#### Subnet Mask to CIDR

```bash
python cidr.py subnet-mask 255.255.255.0
```

#### Subnet to CIDR

```bash
python cidr.py subnet 192.168.1.0/24
```

#### IP Range to CIDR

```bash
python cidr.py ip-range 192.168.1.1-192.168.1.254
```

### Optional Arguments

* `--output <file>`: Save result as JSON to the specified file
* `--log-level <level>`: Set log level (`DEBUG`, `INFO`, `WARNING`, `ERROR`)

#### Example:

```bash
python cidr.py ip-range 10.0.0.1-10.0.0.254 --output result.json --log-level DEBUG
```

## 🧪 Example Output

```json
{
  "input": "192.168.1.1-192.168.1.254",
  "type": "ip_range",
  "cidr_notation": "192.168.1.0/24",
  "ip_version": "IPV4"
}
```

## License

This project is licensed under the MIT License. See the [LICENSE](../LICENSE) file for details.

## ⚠️ Disclaimer

This tool is intended for **informational and automation purposes**. Always validate the output in your specific infrastructure context. While effort has been made to handle edge cases and invalid inputs gracefully, it is **not guaranteed to be free of bugs**.

This software is provided "as is" without warranty of any kind, express or implied. The authors are not responsible for any legal implications of generated license files or repository management actions.  **This is a personal project intended for educational purposes. The developer makes no guarantees about the reliability or security of this software. Use at your own risk.**
