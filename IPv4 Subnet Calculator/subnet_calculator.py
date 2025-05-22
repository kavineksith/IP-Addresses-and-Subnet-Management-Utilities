#!/usr/bin/env python3
"""
Industrial-Grade Subnet Calculator

Features:
- Supports both network-based and host-based subnetting
- Comprehensive error handling
- Multiple output formats (text, JSON)
- Configuration file support
- Logging
- Unit test scaffolding
"""

import ipaddress
import json
import logging
import math
import re
import sys
from argparse import ArgumentParser, Namespace
from dataclasses import dataclass
from enum import Enum, auto
from pathlib import Path
from typing import List, Optional, Tuple, Union

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('subnet_calculator.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class CalculationMode(Enum):
    """Enumeration for calculation modes."""
    NETWORK_BASED = auto()
    HOST_BASED = auto()

class OutputFormat(Enum):
    """Enumeration for output formats."""
    TEXT = auto()
    JSON = auto()

@dataclass
class SubnetInfo:
    """Dataclass to hold subnet information."""
    subnet: str
    network_address: str
    first_usable: str
    last_usable: str
    broadcast_address: str
    subnet_mask: str
    host_mask: str
    usable_hosts: int

@dataclass
class NetworkInfo:
    """Dataclass to hold network information."""
    network_ip: str
    subnet_mask: str
    host_mask: str
    network_address: str
    broadcast_address: str
    total_usable_hosts: int
    total_subnets: int
    new_prefix: int

# Define custom exceptions
class SubnetCalculatorError(Exception):
    """Base class for all subnet calculator exceptions."""
    def __init__(self, message, error_code = None):
        super().__init__(message, error_code)

class InvalidNetworkCountError(SubnetCalculatorError):
    """Raised when the number of networks is invalid."""
    def __init__(self, message: str = "Number of networks must be at least 1."):
        self.message = message
        super().__init__(self.message)

class InvalidHostCountError(SubnetCalculatorError):
    """Raised when the number of hosts is invalid."""
    def __init__(self, message: str = "Number of hosts must be at least 1."):
        self.message = message
        super().__init__(self.message)

class InvalidIPError(SubnetCalculatorError):
    """Raised when the IP address is invalid."""
    def __init__(self, message: str = "Invalid IP address format."):
        self.message = message
        super().__init__(self.message)

class InvalidPrefixError(SubnetCalculatorError):
    """Raised when the subnet prefix is invalid."""
    def __init__(self, message: str = "Invalid subnet prefix. Prefix must be between 0 and 32."):
        self.message = message
        super().__init__(self.message)

class InvalidNetworkError(SubnetCalculatorError):
    """Raised when the network is invalid."""
    def __init__(self, message: str = "The IP address and prefix do not form a valid network."):
        self.message = message
        super().__init__(self.message)

class ConfigurationError(SubnetCalculatorError):
    """Raised when there's a configuration error."""
    def __init__(self, message, error_code = None):
        super().__init__(message, error_code)

class SubnetCalculator:
    """Industrial-grade subnet calculator supporting both network-based and host-based calculations."""
    
    def __init__(self, config_path: Optional[str] = None):
        """Initialize the subnet calculator with optional configuration."""
        self.config = self._load_config(config_path) if config_path else None
        self.network: Optional[ipaddress.IPv4Network] = None
        self.subnets: List[ipaddress.IPv4Network] = []
        self.mode: Optional[CalculationMode] = None
        self.output_format: OutputFormat = OutputFormat.TEXT

    def _load_config(self, config_path: str) -> dict:
        """Load configuration from file."""
        try:
            with open(config_path, 'r') as f:
                return json.load(f)
        except (IOError, json.JSONDecodeError) as e:
            raise ConfigurationError(f"Failed to load configuration: {e}")

    def validate_ipv4(self, ip: str) -> bool:
        """Validate if the given IP address is a valid IPv4 address."""
        pattern = re.compile(
            r'^(25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)\.'
            r'(25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)\.'
            r'(25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)\.'
            r'(25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)$'
        )
        return pattern.match(ip) is not None

    def validate_network_ip(self, network_ip: str) -> None:
        """Validate if the network IP and prefix form a valid network."""
        try:
            network = ipaddress.IPv4Network(network_ip, strict=False)
        except ValueError as e:
            logger.error(f"Invalid network IP: {network_ip}")
            raise InvalidIPError(f"Invalid network IP format: {e}") from e
        
        if not (0 <= network.prefixlen <= 32):
            logger.error(f"Invalid prefix length: {network.prefixlen}")
            raise InvalidPrefixError()
        
        ip_part = network_ip.split('/')[0]
        if not self.validate_ipv4(ip_part):
            logger.error(f"Invalid IPv4 address: {ip_part}")
            raise InvalidIPError()

    def calculate_network_based_subnets(self, network_ip: str, num_networks: int) -> None:
        """Calculate subnets based on the number of required networks."""
        self.mode = CalculationMode.NETWORK_BASED
        self.validate_network_ip(network_ip)
        
        if num_networks < 1:
            logger.error(f"Invalid network count: {num_networks}")
            raise InvalidNetworkCountError()
        
        network = ipaddress.IPv4Network(network_ip, strict=False)
        required_bits = math.ceil(math.log2(num_networks))
        new_prefix = network.prefixlen + required_bits
        
        if new_prefix > 32:
            logger.error(f"Prefix too large: {new_prefix}")
            raise InvalidPrefixError("Not enough address space to create the requested number of networks.")
        
        self.network = network
        self.subnets = list(network.subnets(new_prefix=new_prefix))
        logger.info(f"Calculated {len(self.subnets)} subnets with prefix /{new_prefix}")

    def calculate_host_based_subnets(self, network_ip: str, num_hosts: int) -> None:
        """Calculate subnets based on the number of required hosts per subnet."""
        self.mode = CalculationMode.HOST_BASED
        self.validate_network_ip(network_ip)
        
        if num_hosts < 1:
            logger.error(f"Invalid host count: {num_hosts}")
            raise InvalidHostCountError()
        
        network = ipaddress.IPv4Network(network_ip, strict=False)
        new_prefix = 32 - math.ceil(math.log2(num_hosts + 2))
        
        if new_prefix < network.prefixlen:
            logger.error(f"Prefix too small: {new_prefix}")
            raise InvalidPrefixError("Requested host count requires a larger network.")
        
        self.network = network
        self.subnets = list(network.subnets(new_prefix=new_prefix))
        logger.info(f"Calculated {len(self.subnets)} subnets with prefix /{new_prefix}")

    def get_subnet_info(self, subnet: ipaddress.IPv4Network) -> SubnetInfo:
        """Get detailed information about a subnet."""
        subnet_mask, host_mask = self._format_ip_mask(subnet)
        first_usable = subnet.network_address + 1
        last_usable = subnet.broadcast_address - 1
        
        return SubnetInfo(
            subnet=str(subnet),
            network_address=str(subnet.network_address),
            first_usable=str(first_usable),
            last_usable=str(last_usable),
            broadcast_address=str(subnet.broadcast_address),
            subnet_mask=str(subnet_mask),
            host_mask=str(host_mask),
            usable_hosts=2**(32 - subnet.prefixlen) - 2
        )

    def get_network_info(self) -> NetworkInfo:
        """Get detailed information about the parent network."""
        if not self.network:
            raise InvalidNetworkError("Network not initialized")
            
        subnet_mask, host_mask = self._format_ip_mask(self.network)
        
        return NetworkInfo(
            network_ip=str(self.network),
            subnet_mask=str(subnet_mask),
            host_mask=str(host_mask),
            network_address=str(self.network.network_address),
            broadcast_address=str(self.network.broadcast_address),
            total_usable_hosts=2**(32 - self.network.prefixlen) - 2,
            total_subnets=len(self.subnets),
            new_prefix=self.subnets[0].prefixlen if self.subnets else self.network.prefixlen
        )

    def _format_ip_mask(self, network: ipaddress.IPv4Network) -> Tuple[ipaddress.IPv4Address, ipaddress.IPv4Address]:
        """Return the subnet mask and host mask in a human-readable format."""
        subnet_mask = network.netmask
        host_mask = ipaddress.IPv4Address(int(~int(subnet_mask)) & (2**32 - 1))
        return subnet_mask, host_mask

    def print_results(self) -> None:
        """Print results in the configured output format."""
        if self.output_format == OutputFormat.JSON:
            print(self.get_json_output())
        else:
            print(self.get_text_output())

    def get_text_output(self) -> str:
        """Generate text output for the results."""
        if not self.network or not self.subnets:
            return "No results to display."
        
        output = []
        network_info = self.get_network_info()
        
        # Network summary
        output.append("\nSummary of the Network Information:")
        output.append(f"Network IP: {network_info.network_ip}")
        output.append(f"Subnet Mask: {network_info.subnet_mask}")
        output.append(f"Host Mask: {network_info.host_mask}")
        output.append(f"Network Address: {network_info.network_address}")
        output.append(f"Broadcast Address: {network_info.broadcast_address}")
        output.append(f"Total Usable Hosts: {network_info.total_usable_hosts}")
        
        # Subnet summary
        output.append("\nSummary of the Subnet Information:")
        output.append(f"Number of Subnets: {network_info.total_subnets}")
        output.append(f"New Prefix: /{network_info.new_prefix}")
        
        if self.mode == CalculationMode.HOST_BASED:
            output.append(f"Usable Hosts per Subnet: {2**(32 - network_info.new_prefix) - 2}")
        else:
            output.append(f"Subnets Created: {network_info.total_subnets}")
        
        # Detailed subnet information
        output.append("\nComplete List of Subnets:")
        for subnet in self.subnets:
            info = self.get_subnet_info(subnet)
            output.append(f"\nSubnet: {info.subnet}")
            output.append(f"Network Address: {info.network_address}")
            output.append(f"First Usable IP: {info.first_usable}")
            output.append(f"Last Usable IP: {info.last_usable}")
            output.append(f"Broadcast Address: {info.broadcast_address}")
            output.append(f"Subnet Mask: {info.subnet_mask}")
            output.append(f"Host Mask: {info.host_mask}")
            output.append(f"Usable Hosts: {info.usable_hosts}")
        
        return "\n".join(output)

    def get_json_output(self) -> str:
        """Generate JSON output for the results."""
        if not self.network or not self.subnets:
            return json.dumps({"error": "No results to display."}, indent=2)
        
        network_info = self.get_network_info()
        subnets_info = [self.get_subnet_info(subnet) for subnet in self.subnets]
        
        result = {
            "network": {
                "network_ip": network_info.network_ip,
                "subnet_mask": network_info.subnet_mask,
                "host_mask": network_info.host_mask,
                "network_address": network_info.network_address,
                "broadcast_address": network_info.broadcast_address,
                "total_usable_hosts": network_info.total_usable_hosts,
                "total_subnets": network_info.total_subnets,
                "new_prefix": network_info.new_prefix
            },
            "subnets": [
                {
                    "subnet": info.subnet,
                    "network_address": info.network_address,
                    "first_usable_ip": info.first_usable,
                    "last_usable_ip": info.last_usable,
                    "broadcast_address": info.broadcast_address,
                    "subnet_mask": info.subnet_mask,
                    "host_mask": info.host_mask,
                    "usable_hosts": info.usable_hosts
                } for info in subnets_info
            ],
            "calculation_mode": self.mode.name.lower()
        }
        
        return json.dumps(result, indent=2)

def parse_args() -> Namespace:
    """Parse command line arguments."""
    parser = ArgumentParser(description="Industrial-Grade Subnet Calculator")
    
    parser.add_argument(
        "network_ip",
        help="Network IP address with prefix (e.g., 192.168.1.0/24)"
    )
    
    mode_group = parser.add_mutually_exclusive_group(required=True)
    mode_group.add_argument(
        "-n", "--networks",
        type=int,
        help="Number of networks required"
    )
    mode_group.add_argument(
        "-H", "--hosts",
        type=int,
        help="Number of hosts required per subnet"
    )
    
    parser.add_argument(
        "-o", "--output",
        choices=["text", "json"],
        default="text",
        help="Output format (default: text)"
    )
    
    parser.add_argument(
        "-c", "--config",
        help="Path to configuration file"
    )
    
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose logging"
    )
    
    return parser.parse_args()

def main() -> None:
    """Main function to handle command line execution."""
    try:
        args = parse_args()
        
        if args.verbose:
            logger.setLevel(logging.DEBUG)
        
        calculator = SubnetCalculator(args.config)
        calculator.output_format = OutputFormat[args.output.upper()]
        
        if args.networks:
            calculator.calculate_network_based_subnets(args.network_ip, args.networks)
        else:
            calculator.calculate_host_based_subnets(args.network_ip, args.hosts)
        
        calculator.print_results()
        
    except SubnetCalculatorError as e:
        logger.error(f"Subnet calculation error: {e}")
        sys.exit(1)
    except KeyboardInterrupt:
        logger.info("Operation interrupted by user.")
        sys.exit(0)
    except Exception as e:
        logger.error(f"An unexpected error occurred: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
