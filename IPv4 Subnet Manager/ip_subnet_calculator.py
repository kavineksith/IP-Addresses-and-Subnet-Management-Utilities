#!/usr/bin/env python3
"""
Industrial-Grade IP Subnet Calculator

Features:
- Comprehensive IPv4 subnet calculations
- Batch processing of IP addresses
- Multiple output formats (JSON, CSV, TXT)
- Threaded processing for performance
- Detailed logging
- Graceful error handling
- Configurable export options
- Interactive and CLI modes
- IP list generation
"""

import ipaddress
import datetime
import json
import logging
import os
import sys
import argparse
import csv
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Tuple, List, Dict, Union, Optional
import signal

# Constants
DEFAULT_EXPORT_DIR = './exports'
MAX_WORKERS = 4
SUPPORTED_IP_VERSIONS = ['ipv4']
SUPPORTED_OUTPUT_FORMATS = ['txt', 'csv', 'json']
DEFAULT_LOG_LEVEL = logging.INFO

# Configure logging
logging.basicConfig(
    level=DEFAULT_LOG_LEVEL,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('ip_subnet_calculator.log'),
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
    """Handles IP address conversion operations."""
    def __init__(self, ip: str):
        self.ip = ip
        self.validate_ip()
    
    def validate_ip(self) -> None:
        """Validate the IP address."""
        try:
            ipaddress.ip_address(self.ip)
        except ValueError as ve:
            logger.error(f"Invalid IP address {self.ip}: {ve}")
            raise IPAddressError(f"Invalid IP address: {self.ip}", self.ip)
    
    def to_decimal_and_hex(self) -> Tuple[int, str]:
        """Convert IP to decimal and hexadecimal representations."""
        try:
            decimal_ip = int(ipaddress.ip_address(self.ip))
            hex_ip = hex(decimal_ip)
            return decimal_ip, hex_ip
        except ValueError as ve:
            logger.error(f"Conversion error for {self.ip}: {ve}")
            raise IPAddressError(f"Conversion error for IP {self.ip}", self.ip)
    
    def to_binary(self) -> str:
        """Convert IP to binary representation."""
        try:
            return format(int(ipaddress.ip_address(self.ip)), '032b')
        except ValueError as ve:
            logger.error(f"Binary conversion error for {self.ip}: {ve}")
            raise IPAddressError(f"Binary conversion error for IP {self.ip}", self.ip)


class SubnetCalculator:
    """Performs subnet calculations for a given IP and CIDR."""
    def __init__(self, ip: str, cidr: int):
        self.ip = ip
        self.cidr = cidr
        self.validate_inputs()
    
    def validate_inputs(self) -> None:
        """Validate IP and CIDR inputs."""
        try:
            ipaddress.ip_address(self.ip)
            if not 0 <= self.cidr <= 32:
                raise ValueError("CIDR must be between 0 and 32")
        except ValueError as ve:
            logger.error(f"Validation error for {self.ip}/{self.cidr}: {ve}")
            raise IPAddressError(f"Invalid input: {ve}", self.ip)
    
    def get_network(self) -> ipaddress.IPv4Network:
        """Return the network object for the IP/CIDR."""
        try:
            return ipaddress.ip_network(f"{self.ip}/{self.cidr}", strict=False)
        except ValueError as ve:
            logger.error(f"Network creation error for {self.ip}/{self.cidr}: {ve}")
            raise IPAddressError(f"Network error: {ve}", self.ip)
    
    def calculate_subnet(self) -> Tuple[ipaddress.IPv4Address, ipaddress.IPv4Address]:
        """Calculate subnet network address and netmask."""
        network = self.get_network()
        return network.network_address, network.netmask
    
    def subnet_mask_binary(self) -> str:
        """Return binary representation of subnet mask."""
        return bin(int(self.get_network().netmask))
    
    def host_mask_calculator(self) -> ipaddress.IPv4Address:
        """Calculate the host mask."""
        return self.get_network().hostmask
    
    def host_mask_binary(self) -> str:
        """Return binary representation of host mask."""
        host_mask = self.host_mask_calculator()
        return "{0:032b}".format(int(host_mask))
    
    def subnet_binary(self) -> str:
        """Return binary representation of subnet."""
        return format(int(self.get_network().network_address), '032b')
    
    def usable_host_ip_range(self) -> str:
        """Calculate the range of usable host IPs."""
        network = self.get_network()
        if network.num_addresses <= 2:
            return "No usable hosts (network too small)"
        
        usable_hosts = list(network.hosts())
        if not usable_hosts:
            return "No usable hosts"
        return f"{usable_hosts[0]} - {usable_hosts[-1]}"
    
    def broadcast_address(self) -> ipaddress.IPv4Address:
        """Return the broadcast address."""
        return self.get_network().broadcast_address
    
    def total_number_of_hosts(self) -> int:
        """Return total number of host addresses."""
        return self.get_network().num_addresses
    
    def number_of_usable_hosts(self) -> int:
        """Return number of usable host addresses."""
        num_addresses = self.get_network().num_addresses
        return max(0, num_addresses - 2)
    
    def network_address(self) -> ipaddress.IPv4Address:
        """Return the network address."""
        return self.get_network().network_address
    
    def ip_type(self) -> str:
        """Determine the type of the IP address."""
        ip_obj = ipaddress.ip_address(self.ip)
        
        if ip_obj.is_private:
            return "Private IPv4"
        elif ip_obj.is_loopback:
            return "Loopback IPv4"
        elif ip_obj.is_link_local:
            return "Link-local IPv4"
        elif ip_obj.is_reserved:
            return "Reserved IPv4"
        elif ip_obj.is_unspecified:
            return "APIPA (Automatic Private IP Addressing) IPv4"
        elif ip_obj.is_multicast:
            return "Multicast IPv4"
        elif ip_obj.is_global:
            return "Public IPv4"
        return "Other IPv4"
    
    def generate_ip_list(self, output_file: str = './list.txt') -> None:
        """Generate a list of all IPs in the subnet."""
        try:
            network = self.get_network()
            os.makedirs(os.path.dirname(output_file), exist_ok=True)
            
            with open(output_file, 'w', encoding='utf-8') as ip_list:
                for host_ip in network.hosts():
                    ip_list.write(f"{host_ip}\n")
            logger.info(f"IP list generated at {output_file}")
        except Exception as e:
            logger.error(f"Error generating IP list: {e}")
            raise IPAddressError(f"Failed to generate IP list: {e}", self.ip)


class IPAddressManager:
    """Manages IP address operations and validations."""
    @staticmethod
    def validate_ip_address(ip: str) -> bool:
        """Validate an IP address."""
        try:
            ipaddress.ip_address(ip)
            return True
        except ValueError:
            return False
    
    @staticmethod
    def validate_ipv4_class(ip: str) -> Optional[str]:
        """Determine the class of an IPv4 address."""
        if not IPAddressManager.validate_ip_address(ip):
            return None
        
        try:
            first_octet = int(ip.split('.')[0])
            if 1 <= first_octet <= 126:
                return 'A'
            elif 128 <= first_octet <= 191:
                return 'B'
            elif 192 <= first_octet <= 223:
                return 'C'
            elif first_octet == 127:
                return 'Loopback'
            elif first_octet == 0 or first_octet == 255:
                return 'Reserved'
            return 'Unknown'
        except (IndexError, ValueError):
            return None
    
    @staticmethod
    def validate_input(ip_version: str, ip_address: str, cidr: str) -> Tuple[str, int]:
        """Validate user input for IP processing."""
        try:
            if ip_version.lower() not in SUPPORTED_IP_VERSIONS:
                raise ValueError(f"Unsupported IP version: {ip_version}")
            
            if not IPAddressManager.validate_ip_address(ip_address):
                raise ValueError(f"Invalid IP address: {ip_address}")
            
            cidr_int = int(cidr)
            if not (0 <= cidr_int <= 32):
                raise ValueError("CIDR must be between 0 and 32")
            
            return ip_address, cidr_int
        except ValueError as ve:
            logger.error(f"Input validation error: {ve}")
            raise IPAddressError(f"Input validation failed: {ve}", ip_address)


class OutputFormatter:
    """Handles formatting and output of results."""
    @staticmethod
    def chunkstring(string: str, length: int) -> List[str]:
        """Split a string into chunks of specified length."""
        return [string[i:i+length] for i in range(0, len(string), length)]
    
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
    def save_to_file(file_name: str, labels: List[str], data: List[str], file_type: str) -> str:
        """Save data to a file in the specified format."""
        try:
            OutputFormatter.ensure_export_dir()
            timestamp = OutputFormatter.timestamp_for_export()
            file_path = os.path.join(DEFAULT_EXPORT_DIR, f"{timestamp}_{file_name}.{file_type}")
            
            if file_type == 'json':
                json_data = dict(zip(labels, data))
                with open(file_path, 'w', encoding='utf-8') as f:
                    json.dump(json_data, f, indent=4)
            elif file_type == 'csv':
                with open(file_path, 'w', encoding='utf-8', newline='') as f:
                    writer = csv.writer(f)
                    writer.writerow(labels)
                    writer.writerow(data)
            else:  # txt
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write('\n'.join(f"{label}: {value}" for label, value in zip(labels, data)))
            
            logger.info(f"Results saved to {file_path}")
            return file_path
        except Exception as e:
            logger.error(f"Error saving to file: {e}")
            raise IPAddressError(f"Failed to save results: {e}")
    
    @staticmethod
    def display_results(labels: List[str], data: List[str], format_type: str) -> None:
        """Display results in the specified format."""
        try:
            if len(labels) != len(data):
                raise ValueError("Labels and data length mismatch")
            
            if format_type == 'txt':
                print("\n".join(f"{label}: {value}" for label, value in zip(labels, data)))
            elif format_type == 'csv':
                print(",".join(labels))
                print(",".join(data))
            elif format_type == 'json':
                print(json.dumps(dict(zip(labels, data)), indent=4))
            else:
                raise ValueError(f"Unsupported format: {format_type}")
        except Exception as e:
            logger.error(f"Error displaying results: {e}")
            raise IPAddressError(f"Failed to display results: {e}")


class BatchProcessor:
    """Processes multiple IP addresses in batch."""
    @staticmethod
    def process_ip(ip_cidr: str, output_format: str = 'json', save_results: bool = False) -> Optional[Dict]:
        """Process a single IP/CIDR from batch input."""
        try:
            ip, cidr = ip_cidr.strip().split('/')
            ip_address, cidr_int = IPAddressManager.validate_input("ipv4", ip, cidr)
            
            ip_class = IPAddressManager.validate_ipv4_class(ip_address)
            subnet_calc = SubnetCalculator(ip_address, cidr_int)
            ip_converter = IPAddressConverter(ip_address)

            # Gather all data
            results = {
                "IPv4 address": ip_address,
                "IPv4 class": ip_class,
                "IPv4 Type": subnet_calc.ip_type(),
                "Network Address": str(subnet_calc.network_address()),
                "Broadcast Address": str(subnet_calc.broadcast_address()),
                "Total Number of Hosts": str(subnet_calc.total_number_of_hosts()),
                "Number of Usable Hosts": str(subnet_calc.number_of_usable_hosts()),
                "CIDR Notation": f"/{cidr_int}",
                "Usable Host IP Range": subnet_calc.usable_host_ip_range(),
                "Decimal representation": str(ip_converter.to_decimal_and_hex()[0]),
                "Hexadecimal representation": ip_converter.to_decimal_and_hex()[1],
                "Binary representation": ".".join(OutputFormatter.chunkstring(ip_converter.to_binary(), 8)),
                "Subnet": f"{subnet_calc.calculate_subnet()[0]}/{cidr_int}",
                "Subnet mask": str(subnet_calc.calculate_subnet()[1]),
                "Host mask": str(subnet_calc.host_mask_calculator()),
                "Subnet binary": ".".join(OutputFormatter.chunkstring(subnet_calc.subnet_binary(), 8)),
                "Subnet mask binary": ".".join(OutputFormatter.chunkstring(subnet_calc.subnet_mask_binary()[2:], 8)),
                "Host mask binary": ".".join(OutputFormatter.chunkstring(subnet_calc.host_mask_binary(), 8))
            }

            if save_results:
                labels = list(results.keys())
                data = list(results.values())
                file_name = f"{ip_address.replace('.', '_')}_{cidr_int}"
                OutputFormatter.save_to_file(file_name, labels, data, output_format)
            
            return results
        
        except Exception as e:
            logger.error(f"Error processing {ip_cidr}: {e}")
            return None
    
    @staticmethod
    def process_file(file_path: str, output_format: str = 'json', save_results: bool = True) -> List[Dict]:
        """Process IP addresses from a file."""
        try:
            if not os.path.exists(file_path):
                raise FileNotFoundError(f"File not found: {file_path}")
            
            with open(file_path, 'r', encoding='utf-8') as f:
                ip_list = [line.strip() for line in f if line.strip()]
            
            logger.info(f"Processing {len(ip_list)} IP addresses from {file_path}")
            
            results = []
            with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
                futures = {executor.submit(BatchProcessor.process_ip, ip, output_format, save_results): ip for ip in ip_list}
                
                for future in as_completed(futures):
                    ip = futures[future]
                    try:
                        result = future.result()
                        if result:
                            results.append(result)
                    except Exception as e:
                        logger.error(f"Error processing {ip}: {e}")
            
            return results
        
        except Exception as e:
            logger.error(f"Error processing file {file_path}: {e}")
            raise IPAddressError(f"Batch processing failed: {e}")


class DataProcessor:
    """Processes IP address data and generates results."""
    @staticmethod
    def process_single_ip(ip_address: str, cidr: int) -> None:
        """Process a single IP address and CIDR."""
        try:
            ip_class = IPAddressManager.validate_ipv4_class(ip_address)
            subnet_calc = SubnetCalculator(ip_address, cidr)
            ip_converter = IPAddressConverter(ip_address)

            # Gather all data
            results = {
                "IPv4 address": ip_address,
                "IPv4 class": ip_class,
                "IPv4 Type": subnet_calc.ip_type(),
                "Network Address": str(subnet_calc.network_address()),
                "Broadcast Address": str(subnet_calc.broadcast_address()),
                "Total Number of Hosts": str(subnet_calc.total_number_of_hosts()),
                "Number of Usable Hosts": str(subnet_calc.number_of_usable_hosts()),
                "CIDR Notation": f"/{cidr}",
                "Usable Host IP Range": subnet_calc.usable_host_ip_range(),
                "Decimal representation": str(ip_converter.to_decimal_and_hex()[0]),
                "Hexadecimal representation": ip_converter.to_decimal_and_hex()[1],
                "Binary representation": ".".join(OutputFormatter.chunkstring(ip_converter.to_binary(), 8)),
                "Subnet": f"{subnet_calc.calculate_subnet()[0]}/{cidr}",
                "Subnet mask": str(subnet_calc.calculate_subnet()[1]),
                "Host mask": str(subnet_calc.host_mask_calculator()),
                "Subnet binary": ".".join(OutputFormatter.chunkstring(subnet_calc.subnet_binary(), 8)),
                "Subnet mask binary": ".".join(OutputFormatter.chunkstring(subnet_calc.subnet_mask_binary()[2:], 8)),
                "Host mask binary": ".".join(OutputFormatter.chunkstring(subnet_calc.host_mask_binary(), 8))
            }

            # Prepare labels and data for output
            labels = list(results.keys())
            data = list(results.values())

            # Handle output
            while True:
                output_action = input("Which method would you like (view/save/both): ").strip().lower()
                if output_action in ['view', 'save', 'both']:
                    break
                print("Invalid option. Please choose 'view', 'save', or 'both'.")

            while True:
                output_format = input(f"Which output format would you like ({'/'.join(SUPPORTED_OUTPUT_FORMATS)}): ").strip().lower()
                if output_format in SUPPORTED_OUTPUT_FORMATS:
                    break
                print(f"Invalid format. Please choose from {SUPPORTED_OUTPUT_FORMATS}")
            
            if output_action in ['view', 'both']:
                OutputFormatter.display_results(labels, data, output_format)
            
            if output_action in ['save', 'both']:
                file_name = f"{ip_address.replace('.', '_')}_{cidr}"
                saved_path = OutputFormatter.save_to_file(file_name, labels, data, output_format)
                print(f"Results saved to: {saved_path}")
        
        except Exception as e:
            logger.error(f"Error processing {ip_address}/{cidr}: {e}")
            raise IPAddressError(f"Processing failed: {e}", ip_address)
    
    @staticmethod
    def generate_ip_list() -> None:
        """Generate a list of IP addresses in a subnet."""
        try:
            ip_cidr = input("Enter IP address and CIDR notation (e.g., 192.168.1.1/24): ").strip()
            ip, cidr = ip_cidr.split('/')
            ip_address, cidr_int = IPAddressManager.validate_input("ipv4", ip, cidr)
            
            default_output = f"./exports/ip_list_{ip_address.replace('.', '_')}_{cidr_int}.txt"
            output_file = input(f"Enter output file path (default: {default_output}): ").strip() or default_output
            
            SubnetCalculator(ip_address, cidr_int).generate_ip_list(output_file)
            logger.info(f"IP list generated at {output_file}")
            print(f"IP list generated at: {output_file}")
        except Exception as e:
            logger.error(f"Error generating IP list: {e}")
            raise IPAddressError(f"Failed to generate IP list: {e}")


class CommandLineInterface:
    """Handles command-line interface and user interactions."""
    @staticmethod
    def parse_arguments():
        """Parse command line arguments."""
        parser = argparse.ArgumentParser(description="IP Address and Subnet Calculator")
        parser.add_argument('--ip', help="IP address with CIDR (e.g., 192.168.1.1/24)")
        parser.add_argument('--file', help="File containing list of IPs to process")
        parser.add_argument('--generate', action='store_true', help="Generate IP list mode")
        parser.add_argument('--format', choices=SUPPORTED_OUTPUT_FORMATS, default='json',
                          help="Output format for batch processing")
        parser.add_argument('--quiet', action='store_true', help="Suppress non-essential output")
        return parser.parse_args()
    
    @staticmethod
    def handle_interactive_mode() -> None:
        """Run the interactive mode."""
        ScreenManager().clear_screen()
        print("IP Address and Subnet Calculator")
        print("Commands: 'clear' to clear screen, 'exit' to quit, 'multiple' to process multiple IPs, 'addresses' to generate IP list\n")
        
        while True:
            try:
                user_input = input("Enter IP address and CIDR notation (e.g., 192.168.1.1/24) or command: ").strip()
                
                if not user_input:
                    continue
                elif user_input.lower() == "clear":
                    ScreenManager().clear_screen()
                elif user_input.lower() == "exit":
                    print("Exiting...")
                    sys.exit(0)
                elif user_input.lower() == "multiple":
                    file_path = input("Enter file path with IP addresses: ").strip()
                    output_format = input(f"Enter output format ({'/'.join(SUPPORTED_OUTPUT_FORMATS)}): ").strip().lower()
                    if output_format not in SUPPORTED_OUTPUT_FORMATS:
                        print(f"Invalid format. Using default (json)")
                        output_format = 'json'
                    BatchProcessor.process_file(file_path, output_format)
                elif user_input.lower() == "addresses":
                    DataProcessor.generate_ip_list()
                else:
                    ip, cidr = user_input.split('/')
                    ip_address, cidr_int = IPAddressManager.validate_input("ipv4", ip, cidr)
                    DataProcessor.process_single_ip(ip_address, cidr_int)
            
            except KeyboardInterrupt:
                print("\nOperation cancelled by user")
                sys.exit(0)
            except ValueError as ve:
                print(f"Error: {ve}")
            except Exception as e:
                logger.error(f"Error in interactive mode: {e}")
                print(f"Error: {e}")


def signal_handler(sig, frame):
    """Handle interrupt signals gracefully."""
    print("\nReceived interrupt signal. Exiting gracefully...")
    sys.exit(0)


def configure_logging(quiet_mode: bool = False) -> None:
    """Configure logging based on quiet mode."""
    level = logging.WARNING if quiet_mode else DEFAULT_LOG_LEVEL
    logging.basicConfig(
        level=level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler('ip_subnet_calculator.log'),
            logging.StreamHandler()
        ]
    )


def main():
    """Main entry point for the application."""
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    args = CommandLineInterface.parse_arguments()
    configure_logging(args.quiet)
    
    try:
        if args.generate:
            DataProcessor.generate_ip_list()
        elif args.file:
            BatchProcessor.process_file(args.file, args.format)
        elif args.ip:
            ip, cidr = args.ip.split('/')
            ip_address, cidr_int = IPAddressManager.validate_input("ipv4", ip, cidr)
            DataProcessor.process_single_ip(ip_address, cidr_int)
        else:
            CommandLineInterface.handle_interactive_mode()
    except Exception as e:
        logger.error(f"Application error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
