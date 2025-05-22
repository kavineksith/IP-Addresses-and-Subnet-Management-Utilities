# IPv4 Subnet Calculator

![Python Version](https://img.shields.io/badge/python-3.10%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)

A robust, feature-rich IP subnet calculator designed for network engineers, system administrators, and IT professionals.

## Features

- 🖥️ **Comprehensive IPv4 subnet calculations** - All essential subnet information in one place
- 📊 **Batch processing** - Process multiple IP addresses simultaneously
- 🚀 **Threaded processing** - Optimized performance for large datasets
- 📁 **Multiple output formats** - JSON, CSV, and TXT export options
- 📝 **Detailed logging** - Both file and console logging
- 🛡️ **Graceful error handling** - Comprehensive validation and error recovery
- 🔄 **Interactive and CLI modes** - Flexible usage options
- 📋 **IP list generation** - Generate complete lists of IPs in a subnet

## Usage

### Command Line Interface

```bash
# Single IP calculation
python ip_subnet_calculator.py --ip 192.168.1.1/24

# Batch processing from file
python ip_subnet_calculator.py --file ip_list.txt --format json

# Generate IP list
python ip_subnet_calculator.py --generate
```

### Interactive Mode

```bash
python ip_subnet_calculator.py
```

Available commands in interactive mode:
- `clear` - Clear the screen
- `exit` - Quit the program
- `multiple` - Process multiple IPs from a file
- `addresses` - Generate a list of IPs in a subnet

### Available Output Formats
- JSON (`--format json`)
- CSV (`--format csv`)
- Plain text (`--format txt`)

## Examples

### Single IP Calculation
```bash
python ip_subnet_calculator.py --ip 10.0.0.1/24 --format json
```

Sample output (JSON):
```json
{
    "IPv4 address": "10.0.0.1",
    "IPv4 class": "A",
    "IPv4 Type": "Private IPv4",
    "Network Address": "10.0.0.0",
    "Broadcast Address": "10.0.0.255",
    "Total Number of Hosts": "256",
    "Number of Usable Hosts": "254",
    "CIDR Notation": "/24",
    "Usable Host IP Range": "10.0.0.1 - 10.0.0.254",
    "Decimal representation": "167772161",
    "Hexadecimal representation": "0xa000001",
    "Binary representation": "00001010.00000000.00000000.00000001",
    "Subnet": "10.0.0.0/24",
    "Subnet mask": "255.255.255.0",
    "Host mask": "0.0.0.255",
    "Subnet binary": "00001010.00000000.00000000.00000000",
    "Subnet mask binary": "11111111.11111111.11111111.00000000",
    "Host mask binary": "00000000.00000000.00000000.11111111"
}
```

### Batch Processing
Create a file `ip_list.txt` with contents:
```
192.168.1.1/24
10.0.0.1/16
172.16.0.1/20
```

Then run:
```bash
python ip_subnet_calculator.py --file ip_list.txt --format csv
```

### IP List Generation
```bash
python ip_subnet_calculator.py --generate
```
Follow prompts to enter IP/CIDR and output file path.

## Output Formats

### JSON Format
Structured data ideal for programmatic processing.

### CSV Format
Comma-separated values suitable for spreadsheets.

### TXT Format
Human-readable plain text output.

## Configuration

The tool automatically creates an `exports` directory for output files. Logs are written to `ip_subnet_calculator.log`.

## Error Handling

The calculator includes comprehensive error handling for:
- Invalid IP addresses
- Invalid CIDR notation
- File I/O errors
- Concurrent processing issues

## Performance

- Utilizes thread pooling for efficient batch processing
- Configurable worker count (default: 4 threads)
- Memory-efficient processing of large IP lists

## License

This project is licensed under the MIT License. See the [LICENSE](../LICENSE) file for details.

## Disclaimer

This software is provided "as is" without warranty of any kind, express or implied. The authors are not responsible for any legal implications of generated license files or repository management actions.  **This is a personal project intended for educational purposes. The developer makes no guarantees about the reliability or security of this software. Use at your own risk.**

## Disclaimer (Summarized)

This software is provided as-is without any warranties. The developers are not responsible for:
- Any misuse of this software
- Network configuration decisions made based on this tool's output
- Any damage caused by incorrect calculations (though extensive testing has been performed)
- Compatibility issues with specific environments

Users are responsible for:
- Validating results for critical network configurations
- Ensuring proper input formats
- Backing up important data before making network changes
