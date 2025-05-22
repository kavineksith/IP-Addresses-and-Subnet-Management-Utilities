#!/usr/bin/env python3
"""
Industrial-Grade IPv6 Subnet Calculator

Features:
- Comprehensive IPv6 address analysis and subnet calculations
- Support for single IP and batch processing
- Multiple output formats (JSON, CSV, TXT)
- Logging and error handling
- Threaded batch processing
- Export functionality
- Interactive and command-line modes
"""

import argparse
import csv
import datetime
import ipaddress
import json
import logging
import os
import signal
import sys
from concurrent.futures import ThreadPoolExecutor
from typing import Dict, List, Optional, Tuple, Union

# Constants
DEFAULT_EXPORT_DIR = './exports'
MAX_WORKERS = 4
SUPPORTED_OUTPUT_FORMATS = ['json', 'csv', 'txt']
LOG_FORMAT = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
LOG_FILE = 'ipv6_subnet_calculator.log'

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format=LOG_FORMAT,
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)


class IPAddressError(Exception):
    """Custom exception for IP address related errors."""
    def __init__(self, message: str, ip_address: Optional[str] = None):
        self.message = message
        self.ip_address = ip_address
        super().__init__(self.message)


class ScreenManager:
    """Handles screen operations with platform independence."""
    def __init__(self):
        self.clear_command = 'cls' if os.name == 'nt' else 'clear'
    
    def clear_screen(self) -> None:
        """Clear the terminal screen."""
        try:
            os.system(self.clear_command)
        except Exception as e:
            logger.error(f"Error clearing screen: {e}")
            raise IPAddressError("Failed to clear screen")


class IPAddressConverter:
    """Handles IPv6 address conversion operations."""
    def __init__(self, ip: str):
        self.ip = ip
        self.validate_ip()
    
    def validate_ip(self) -> None:
        """Validate the IPv6 address."""
        try:
            ipaddress.IPv6Address(self.ip)
        except ValueError as ve:
            logger.error(f"Invalid IPv6 address {self.ip}: {ve}")
            raise IPAddressError(f"Invalid IPv6 address: {self.ip}", self.ip)
    
    def to_hex(self) -> str:
        """Convert IPv6 to hexadecimal representation."""
        try:
            decimal_ip = int(ipaddress.IPv6Address(self.ip))
            return format(decimal_ip, 'x')
        except Exception as e:
            logger.error(f"Hex conversion error for {self.ip}: {e}")
            raise IPAddressError(f"Hex conversion error for IP {self.ip}", self.ip)
    
    def to_binary(self) -> str:
        """Convert IPv6 to binary representation."""
        try:
            return format(int(ipaddress.IPv6Address(self.ip)), '0128b')
        except Exception as e:
            logger.error(f"Binary conversion error for {self.ip}: {e}")
            raise IPAddressError(f"Binary conversion error for IP {self.ip}", self.ip)
    
    def to_decimal(self) -> int:
        """Convert IPv6 to decimal representation."""
        try:
            return int(ipaddress.IPv6Address(self.ip))
        except Exception as e:
            logger.error(f"Decimal conversion error for {self.ip}: {e}")
            raise IPAddressError(f"Decimal conversion error for IP {self.ip}", self.ip)


class IPv6SubnetCalculator:
    """Performs subnet calculations for a given IPv6 and CIDR."""
    def __init__(self, ip: str, cidr: int):
        self.ip = ip
        self.cidr = cidr
        self.validate_inputs()
    
    def validate_inputs(self) -> None:
        """Validate IPv6 and CIDR inputs."""
        try:
            ipaddress.IPv6Address(self.ip)
            if not 0 <= self.cidr <= 128:
                raise ValueError("CIDR must be between 0 and 128")
        except ValueError as ve:
            logger.error(f"Validation error for {self.ip}/{self.cidr}: {ve}")
            raise IPAddressError(f"Invalid input: {ve}", self.ip)
    
    def get_network(self) -> ipaddress.IPv6Network:
        """Return the network object for the IPv6/CIDR."""
        try:
            return ipaddress.IPv6Network(f"{self.ip}/{self.cidr}", strict=False)
        except ValueError as ve:
            logger.error(f"Network creation error for {self.ip}/{self.cidr}: {ve}")
            raise IPAddressError(f"Network error: {ve}", self.ip)
    
    def calculate_subnet(self) -> Tuple[ipaddress.IPv6Address, ipaddress.IPv6Address]:
        """Calculate subnet network address and netmask."""
        network = self.get_network()
        return network.network_address, network.netmask
    
    def subnet_mask_binary(self) -> str:
        """Return binary representation of subnet mask."""
        return bin(int(self.get_network().netmask))[2:].zfill(128)
    
    def host_mask_calculator(self) -> ipaddress.IPv6Address:
        """Calculate the host mask."""
        return self.get_network().hostmask
    
    def host_mask_binary(self) -> str:
        """Return binary representation of host mask."""
        host_mask = self.host_mask_calculator()
        return "{0:0128b}".format(int(host_mask))
    
    def subnet_binary(self) -> str:
        """Return binary representation of subnet."""
        return format(int(self.get_network().network_address), '0128b')
    
    def usable_host_ip_range(self) -> Tuple[ipaddress.IPv6Address, ipaddress.IPv6Address]:
        """Calculate the range of usable host IPs."""
        network = self.get_network()
        subnet = network.network_address
        broadcast = network.broadcast_address
        return subnet + 1, broadcast - 1
    
    def broadcast_address(self) -> ipaddress.IPv6Address:
        """Return the broadcast address."""
        return self.get_network().broadcast_address
    
    def total_number_of_hosts(self) -> int:
        """Return total number of host addresses."""
        return self.get_network().num_addresses
    
    def number_of_usable_hosts(self) -> int:
        """Return number of usable host addresses."""
        num_addresses = self.get_network().num_addresses
        return max(0, num_addresses - 2)
    
    def network_address(self) -> ipaddress.IPv6Address:
        """Return the network address."""
        return self.get_network().network_address
    
    def ip_type(self) -> str:
        """Determine the type of the IPv6 address."""
        ip_obj = ipaddress.IPv6Address(self.ip)
        
        if ip_obj.is_private:
            return "Private IPv6"
        elif ip_obj.is_loopback:
            return "Loopback IPv6"
        elif ip_obj.is_link_local:
            return "Link-local IPv6"
        elif ip_obj.is_site_local:
            return "Site-local IPv6"
        elif ip_obj.is_reserved:
            return "Reserved IPv6"
        elif ip_obj.is_unspecified:
            return "APIPA (Automatic Private IP Addressing) IPv6"
        elif ip_obj.is_global:
            return "Public IPv6"
        elif ip_obj.ipv4_mapped:
            return "IPv4-Mapped IPv6"
        elif ip_obj.is_multicast:
            return "Multicast IPv6"
        return "Global Unicast IPv6"


class OutputFormatter:
    """Handles formatting and output of results."""
    @staticmethod
    def chunkstring(string: str, length: int, delimiter: str = ':') -> str:
        """Split a string into chunks of specified length."""
        if len(string) % length != 0:
            raise ValueError("String length is not a multiple of chunk length")
        
        chunks = [string[i:i+length] for i in range(0, len(string), length)]
        return delimiter.join(chunks)
    
    @staticmethod
    def hex_ip_formatter(hex_ip_raw: str) -> str:
        """Format hexadecimal IPv6 string with colons."""
        return ':'.join(hex_ip_raw[i:i+4] for i in range(0, len(hex_ip_raw), 4))
    
    @staticmethod
    def timestamp_for_export() -> str:
        """Generate a timestamp for export files."""
        return datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    
    @staticmethod
    def ensure_export_dir() -> str:
        """Ensure the export directory exists."""
        os.makedirs(DEFAULT_EXPORT_DIR, exist_ok=True)
        return DEFAULT_EXPORT_DIR
    
    @staticmethod
    def save_to_file(file_name: str, data: Dict[str, str], file_type: str) -> str:
        """Save data to a file in the specified format."""
        try:
            OutputFormatter.ensure_export_dir()
            timestamp = OutputFormatter.timestamp_for_export()
            safe_file_name = file_name.replace(':', '_').replace('/', '_')
            file_path = os.path.join(DEFAULT_EXPORT_DIR, f"{timestamp}_{safe_file_name}.{file_type}")
            
            if file_type == 'json':
                with open(file_path, 'w', encoding='utf-8') as f:
                    json.dump(data, f, indent=4, ensure_ascii=False)
            elif file_type == 'csv':
                with open(file_path, 'w', encoding='utf-8', newline='') as f:
                    writer = csv.writer(f)
                    writer.writerow(data.keys())
                    writer.writerow(data.values())
            else:  # txt
                with open(file_path, 'w', encoding='utf-8') as f:
                    for key, value in data.items():
                        f.write(f"{key}: {value}\n")
            
            logger.info(f"Results saved to {file_path}")
            return file_path
        except Exception as e:
            logger.error(f"Error saving to file: {e}")
            raise IPAddressError(f"Failed to save results: {e}")
    
    @staticmethod
    def display_results(data: Dict[str, str], format_type: str) -> None:
        """Display results in the specified format."""
        try:
            if format_type == 'txt':
                for key, value in data.items():
                    print(f"{key}: {value}")
            elif format_type == 'csv':
                print(",".join(data.keys()))
                print(",".join(data.values()))
            elif format_type == 'json':
                print(json.dumps(data, indent=4))
            else:
                raise ValueError(f"Unsupported format: {format_type}")
        except Exception as e:
            logger.error(f"Error displaying results: {e}")
            raise IPAddressError(f"Failed to display results: {e}")


class BatchProcessor:
    """Processes multiple IPv6 addresses in batch."""
    @staticmethod
    def process_ip(ip_cidr: str, output_format: str = 'json', save_results: bool = False) -> None:
        """Process a single IPv6/CIDR from batch input."""
        try:
            ip, cidr = ip_cidr.strip().split('/')
            results = DataProcessor.process_single_ip(ip, int(cidr))
            
            if save_results:
                file_name = f"{ip.replace(':', '_')}_{cidr}"
                OutputFormatter.save_to_file(file_name, results, output_format)
            else:
                OutputFormatter.display_results(results, output_format)
                
        except Exception as e:
            logger.error(f"Error processing {ip_cidr}: {e}")
    
    @staticmethod
    def process_file(file_path: str, output_format: str = 'json', save_results: bool = False) -> None:
        """Process IPv6 addresses from a file."""
        try:
            if not os.path.exists(file_path):
                raise FileNotFoundError(f"File not found: {file_path}")
            
            with open(file_path, 'r', encoding='utf-8') as f:
                ip_list = [line.strip() for line in f if line.strip()]
            
            logger.info(f"Processing {len(ip_list)} IPv6 addresses from {file_path}")
            
            # Use ThreadPoolExecutor for parallel processing
            with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
                for ip_cidr in ip_list:
                    executor.submit(
                        BatchProcessor.process_ip,
                        ip_cidr,
                        output_format,
                        save_results
                    )
        
        except Exception as e:
            logger.error(f"Error processing file {file_path}: {e}")
            raise IPAddressError(f"Batch processing failed: {e}")


class DataProcessor:
    """Processes IPv6 address data and generates results."""
    @staticmethod
    def process_single_ip(ip_address: str, cidr: int) -> Dict[str, str]:
        """Process a single IPv6 address and CIDR."""
        try:
            subnet_calc = IPv6SubnetCalculator(ip_address, cidr)
            ip_converter = IPAddressConverter(ip_address)

            # Calculate all values first
            usable_host_range_start, usable_host_range_end = subnet_calc.usable_host_ip_range()
            usable_host_range_str = f"{usable_host_range_start} - {usable_host_range_end}"

            hex_ip_raw = ip_converter.to_hex()
            hex_ip = OutputFormatter.hex_ip_formatter(hex_ip_raw)
            simplified_hex_ip = ipaddress.IPv6Address(ip_address)
            standard_ip_address = simplified_hex_ip.exploded

            subnet, subnet_mask = subnet_calc.calculate_subnet()
            subnet_mask_bin = subnet_calc.subnet_mask_binary()
            subnet_bin = subnet_calc.subnet_binary()
            host_mask = subnet_calc.host_mask_calculator()
            host_mask_bin = subnet_calc.host_mask_binary()

            # Convert to hexadecimal representations
            subnet_hex = subnet.exploded
            subnet_mask_hex = subnet_mask.exploded
            host_mask_hex = ipaddress.IPv6Address(int(host_mask_bin, 2)).exploded

            # Prepare and return results dictionary
            return {
                "IPv6 address": ip_address,
                "IPv6 Type": subnet_calc.ip_type(),
                "Network Address": str(subnet_calc.network_address()),
                "Broadcast Address": str(subnet_calc.broadcast_address()),
                "Total Number of Hosts": str(subnet_calc.total_number_of_hosts()),
                "Number of Usable Hosts": str(subnet_calc.number_of_usable_hosts()),
                "CIDR Notation": f"/{cidr}",
                "Usable Host IP Range": usable_host_range_str,
                "Decimal representation": str(ip_converter.to_decimal()),
                "Hexadecimal representation": hex_ip,
                "Binary representation": OutputFormatter.chunkstring(ip_converter.to_binary(), 8, '.'),
                "Shorthand IPv6 Address": str(simplified_hex_ip),
                "Standard IPv6 Address": standard_ip_address,
                "Subnet": f"{subnet}/{cidr}",
                "Subnet mask": str(subnet_mask),
                "Host mask": str(host_mask),
                "Subnet binary": OutputFormatter.chunkstring(subnet_bin, 8),
                "Subnet mask binary": OutputFormatter.chunkstring(subnet_mask_bin, 8),
                "Host mask binary": OutputFormatter.chunkstring(host_mask_bin, 8),
                "Subnet hexadecimal representation": subnet_hex,
                "Subnet mask hexadecimal representation": subnet_mask_hex,
                "Host mask hexadecimal representation": host_mask_hex,
                "Subnet decimal representation": str(int(subnet)),
                "Subnet mask decimal representation": str(int(subnet_mask)),
                "Host mask decimal representation": str(int(host_mask_bin, 2))
            }
        
        except Exception as e:
            logger.error(f"Error processing {ip_address}/{cidr}: {e}")
            raise IPAddressError(f"Processing failed: {e}", ip_address)


class CommandLineInterface:
    """Handles command-line interface and user interactions."""
    @staticmethod
    def parse_arguments():
        """Parse command line arguments."""
        parser = argparse.ArgumentParser(
            description="Industrial-Grade IPv6 Address and Subnet Calculator",
            formatter_class=argparse.ArgumentDefaultsHelpFormatter
        )
        parser.add_argument(
            '--ip',
            help="IPv6 address with CIDR (e.g., 2001:db8::/64)"
        )
        parser.add_argument(
            '--file',
            help="File containing list of IPv6 addresses to process"
        )
        parser.add_argument(
            '--output-format',
            choices=SUPPORTED_OUTPUT_FORMATS,
            default='json',
            help="Output format for results"
        )
        parser.add_argument(
            '--save',
            action='store_true',
            help="Save results to file instead of displaying"
        )
        parser.add_argument(
            '--log-level',
            choices=['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'],
            default='INFO',
            help="Set the logging level"
        )
        return parser.parse_args()
    
    @staticmethod
    def handle_interactive_mode() -> None:
        """Run the interactive mode."""
        ScreenManager().clear_screen()
        print("Industrial-Grade IPv6 Address and Subnet Calculator")
        print("Commands: 'clear' to clear screen, 'exit' to quit, 'batch' to process multiple IPs\n")
        
        while True:
            try:
                user_input = input("Enter IPv6 address and CIDR notation (e.g., 2001:db8::/64): ").strip()
                
                if not user_input:
                    continue
                elif user_input.lower() == "clear":
                    ScreenManager().clear_screen()
                elif user_input.lower() == "exit":
                    print("Exiting...")
                    sys.exit(0)
                elif user_input.lower() == "batch":
                    file_path = input("Enter file path with IPv6 addresses: ").strip()
                    output_format = input(
                        f"Output format ({'/'.join(SUPPORTED_OUTPUT_FORMATS)}): "
                    ).strip().lower()
                    save = input("Save results to file? (y/n): ").strip().lower() == 'y'
                    BatchProcessor.process_file(file_path, output_format, save)
                else:
                    ip, cidr = user_input.split('/')
                    output_format = input(
                        f"Output format ({'/'.join(SUPPORTED_OUTPUT_FORMATS)}): "
                    ).strip().lower()
                    save = input("Save results to file? (y/n): ").strip().lower() == 'y'
                    
                    results = DataProcessor.process_single_ip(ip, int(cidr))
                    
                    if save:
                        file_name = f"{ip.replace(':', '_')}_{cidr}"
                        OutputFormatter.save_to_file(file_name, results, output_format)
                    else:
                        OutputFormatter.display_results(results, output_format)
            
            except KeyboardInterrupt:
                print("\nOperation cancelled by user")
                sys.exit(0)
            except Exception as e:
                logger.error(f"Error in interactive mode: {e}")
                print(f"Error: {e}")


def signal_handler(sig, frame):
    """Handle interrupt signals gracefully."""
    print("\nReceived interrupt signal. Exiting gracefully...")
    sys.exit(0)


def configure_logging(log_level: str) -> None:
    """Configure logging based on command line argument."""
    logging.basicConfig(
        level=getattr(logging, log_level),
        format=LOG_FORMAT,
        handlers=[
            logging.FileHandler(LOG_FILE),
            logging.StreamHandler()
        ]
    )


def main():
    """Main entry point for the application."""
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    args = CommandLineInterface.parse_arguments()
    configure_logging(args.log_level)
    
    try:
        if args.file:
            BatchProcessor.process_file(args.file, args.output_format, args.save)
        elif args.ip:
            ip, cidr = args.ip.split('/')
            results = DataProcessor.process_single_ip(ip, int(cidr))
            
            if args.save:
                file_name = f"{ip.replace(':', '_')}_{cidr}"
                OutputFormatter.save_to_file(file_name, results, args.output_format)
            else:
                OutputFormatter.display_results(results, args.output_format)
        else:
            CommandLineInterface.handle_interactive_mode()
    except Exception as e:
        logger.error(f"Application error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
