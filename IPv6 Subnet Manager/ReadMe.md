# IPv6 Subnet Calculator

A comprehensive, industrial-strength IPv6 subnet and address analysis tool designed for engineers, sysadmins, researchers, and security professionals. This tool provides precise breakdowns, transformations, and insights into IPv6 addresses, whether entered individually or in bulk.


## 📌 Features

- ✅ Full IPv6 address parsing and validation  
- ✅ CIDR-based subnet calculations  
- ✅ Output in JSON, CSV, or plain text  
- ✅ Converts IPv6 to binary, decimal, and hexadecimal  
- ✅ Determines address types (e.g., global, private, multicast)  
- ✅ Batch mode for processing multiple addresses with threading  
- ✅ Interactive CLI for real-time use  
- ✅ Logging with configurable levels

## 🚀 Usage

### Single IPv6 Address

```bash
./ipv6_calculator.py --ip "2001:db8::/64" --output-format json
```

### From File (Batch Processing)

```bash
./ipv6_calculator.py --file ipv6_list.txt --output-format csv --save
```

### Interactive Mode

```bash
./ipv6_calculator.py
```

Follow the on-screen prompts to process individual addresses or batch files.

### Arguments

| Flag              | Description                                    |
| ----------------- | ---------------------------------------------- |
| `--ip`            | IPv6 address with CIDR (e.g., `2001:db8::/64`) |
| `--file`          | Path to file with one IPv6/CIDR per line       |
| `--output-format` | Output format: `json`, `csv`, or `txt`         |
| `--save`          | Save the result to an export file              |
| `--log-level`     | Logging level: `DEBUG`, `INFO`, `ERROR`, etc.  |

## 📂 Output

Exported files are saved in the `./exports` directory with a timestamped filename.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

## ⚠️ Disclaimer

This software is provided "as is" without warranty of any kind, express or implied. The authors are not responsible for any legal implications of generated license files or repository management actions. It is designed for educational and professional use. Use it responsibly, especially when processing large or sensitive datasets. **This is a personal project intended for educational purposes. The developer makes no guarantees about the reliability or security of this software. Use at your own risk.**
