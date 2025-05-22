# 🧮 IPv4 Subnet Calculator

A robust and flexible command-line subnet calculator for IPv4 networks. This tool supports both **network-based** and **host-based** subnetting, with detailed outputs in both **text** and **JSON** formats. Built for IT professionals, network engineers, educators, and students who need to calculate and analyze subnets programmatically or via the command line.

## 🔍 Features

* ✅ IPv4 Subnet calculation for:

  * Specific number of **networks**
  * Specific number of **hosts per subnet**
* 🧠 Intelligent error handling and validation
* 🧾 Text and JSON output options
* 📁 Optional configuration file support
* 🪵 Logging to both console and file (`subnet_calculator.log`)
* 🧪 Unit-test-ready architecture with exception-based control flow

## 🚀 Usage

### ⚙️ Command-Line Syntax

```bash
./subnet_calculator.py <network_ip/prefix> (--networks N | --hosts H) [options]
```

### 🔧 Arguments

| Argument             | Description                                               |
| -------------------- | --------------------------------------------------------- |
| `network_ip`         | Base network IP with CIDR prefix (e.g., `192.168.1.0/24`) |
| `--networks` or `-n` | Number of desired subnets                                 |
| `--hosts` or `-H`    | Number of hosts per subnet                                |
| `--output` or `-o`   | Output format: `text` (default) or `json`                 |
| `--config` or `-c`   | Path to a configuration JSON file (optional)              |
| `--verbose` or `-v`  | Enable verbose (DEBUG-level) logging                      |

### ✅ Examples

**Calculate 8 subnets from a /24 network:**

```bash
./subnet_calculator.py 192.168.1.0/24 --networks 8
```

**Calculate subnets with 50 hosts each:**

```bash
./subnet_calculator.py 10.0.0.0/16 --hosts 50
```

**Get output as JSON:**

```bash
./subnet_calculator.py 172.16.0.0/20 --networks 4 --output json
```

**Using a config file:**

```bash
./subnet_calculator.py 192.168.0.0/24 -n 2 -c config.json
```

## 📄 Configuration File (Optional)

You can provide a `.json` configuration file to pre-load default settings. Example format:

```json
{
  "default_output": "json",
  "log_level": "DEBUG"
}
```

This can be used to customize behavior without command-line flags.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

## ⚠️ Disclaimer

This software is provided **"as is"** without any warranty of any kind. It is intended for educational, personal, or professional use in environments where validation and review are standard.

**Use in production systems is at your own risk.**

This software is provided "as is" without warranty of any kind, express or implied. The authors are not responsible for any legal implications of generated license files or repository management actions.  **This is a personal project intended for educational purposes. The developer makes no guarantees about the reliability or security of this software. Use at your own risk.**
