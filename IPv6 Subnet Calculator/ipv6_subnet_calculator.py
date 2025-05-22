#!/usr/bin/env python3
"""
Industrial-Grade IPv6 Subnet Calculator

This tool provides comprehensive IPv6 subnet calculation capabilities including:
- Subnetting based on required number of hosts
- Subnetting based on required number of networks
- Detailed network information display
- Robust error handling and validation
"""

import ipaddress
import logging
import math
import sys
from enum import Enum
from typing import List, Tuple, Union

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('ipv6_subnet_calculator.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class CalculationMode(Enum):
    """Enumeration for calculation modes."""
    BY_HOSTS = 1
    BY_NETWORKS = 2

class InvalidHostCountError(Exception):
    """Exception raised when the number of hosts is invalid."""
    def __init__(self, message: str = "Number of hosts must be at least 1."):
        self.message = message
        super().__init__(self.message)

class InvalidNetworkCountError(Exception):
    """Exception raised when the number of networks is invalid."""
    def __init__(self, message: str = "Number of networks must be at least 1."):
        self.message = message
        super().__init__(self.message)

class InvalidIPError(Exception):
    """Exception raised when the IP address is invalid."""
    def __init__(self, message: str = "Invalid IP address format."):
        self.message = message
        super().__init__(self.message)

class InvalidPrefixError(Exception):
    """Exception raised when the prefix is invalid."""
    def __init__(self, message: str = "Invalid subnet prefix. Prefix must be between 0 and 128."):
        self.message = message
        super().__init__(self.message)

class InvalidNetworkError(Exception):
    """Exception raised when the network is invalid."""
    def __init__(self, message: str = "The IP address and prefix do not form a valid network."):
        self.message = message
        super().__init__(self.message)

class InsufficientAddressSpaceError(Exception):
    """Exception raised when there's insufficient address space."""
    def __init__(self, message: str = "Insufficient address space for the requested operation."):
        self.message = message
        super().__init__(self.message)

class IPv6SubnetCalculator:
    """Main class for IPv6 subnet calculations."""
    
    def __init__(self, network_ip: str):
        """Initialize the calculator with a network IP."""
        self.network_ip = network_ip
        self.network = self._validate_network_ip()
        self.prefix = self.network.prefixlen
        logger.info(f"Initialized calculator with network: {self.network}")
    
    def _validate_network_ip(self) -> ipaddress.IPv6Network:
        """Validate the network IP and return an IPv6Network object."""
        try:
            # Split to get the IP part without prefix for validation
            ip_part = self.network_ip.split('/')[0]
            if not self._validate_ipv6(ip_part):
                raise InvalidIPError()
            
            network = ipaddress.IPv6Network(self.network_ip, strict=False)
            
            if not (0 <= network.prefixlen <= 128):
                raise InvalidPrefixError()
            
            return network
        except ValueError as ve:
            logger.error(f"Network validation failed: {ve}")
            if "prefix length" in str(ve):
                raise InvalidPrefixError()
            raise InvalidNetworkError()
    
    @staticmethod
    def _validate_ipv6(ip: str) -> bool:
        """Validate if the given IP address is a valid IPv6 address."""
        try:
            ipaddress.IPv6Address(ip)
            return True
        except ValueError:
            return False
    
    def calculate_by_hosts(self, num_hosts: int) -> List[ipaddress.IPv6Network]:
        """Calculate subnets based on required number of hosts."""
        logger.info(f"Calculating subnets for {num_hosts} hosts")
        if num_hosts < 1:
            raise InvalidHostCountError()
        
        # For IPv6, calculate prefix to accommodate the given number of hosts
        try:
            prefix = 128 - math.ceil(math.log2(num_hosts + 2))
            prefix = min(max(prefix, 0), 128)
            
            if prefix < self.prefix:
                raise InsufficientAddressSpaceError(
                    f"Required prefix /{prefix} is smaller than network prefix /{self.prefix}"
                )
            
            self.prefix = prefix
            self.subnets = list(self.network.subnets(new_prefix=self.prefix))
            return self.subnets
        except Exception as e:
            logger.error(f"Error calculating by hosts: {e}")
            raise
    
    def calculate_by_networks(self, num_networks: int) -> List[ipaddress.IPv6Network]:
        """Calculate subnets based on required number of networks."""
        logger.info(f"Calculating subnets for {num_networks} networks")
        if num_networks < 1:
            raise InvalidNetworkCountError()
        
        try:
            required_bits = math.ceil(math.log2(num_networks))
            new_prefix = self.prefix + required_bits
            
            if new_prefix > 128:
                raise InsufficientAddressSpaceError(
                    f"Required prefix /{new_prefix} exceeds maximum IPv6 prefix length"
                )
            
            self.prefix = new_prefix
            self.subnets = list(self.network.subnets(new_prefix=self.prefix))
            return self.subnets
        except Exception as e:
            logger.error(f"Error calculating by networks: {e}")
            raise
    
    def get_subnet_details(self, subnet: ipaddress.IPv6Network) -> dict:
        """Get detailed information about a specific subnet."""
        return {
            'subnet': str(subnet),
            'network_address': str(subnet.network_address),
            'first_usable': str(subnet.network_address + 1),
            'last_usable': str(subnet.broadcast_address - 1),
            'broadcast_address': str(subnet.broadcast_address),
            'prefix_length': subnet.prefixlen,
            'total_addresses': subnet.num_addresses,
            'usable_addresses': subnet.num_addresses - 2 if subnet.num_addresses > 2 else 0
        }
    
    def get_network_summary(self) -> dict:
        """Get summary information about the main network."""
        return {
            'network': str(self.network),
            'network_address': str(self.network.network_address),
            'broadcast_address': str(self.network.broadcast_address),
            'prefix_length': self.network.prefixlen,
            'total_addresses': self.network.num_addresses,
            'usable_addresses': self.network.num_addresses - 2 if self.network.num_addresses > 2 else 0
        }

class SubnetCalculatorCLI:
    """Command Line Interface for the IPv6 Subnet Calculator."""
    
    def __init__(self):
        """Initialize the CLI interface."""
        self.calculator = None
        self.mode = None
    
    def run(self):
        """Run the CLI application."""
        try:
            self._print_banner()
            network_ip = self._get_network_input()
            self.calculator = IPv6SubnetCalculator(network_ip)
            
            self.mode = self._get_mode_input()
            
            if self.mode == CalculationMode.BY_HOSTS:
                num_hosts = self._get_num_hosts_input()
                subnets = self.calculator.calculate_by_hosts(num_hosts)
            else:
                num_networks = self._get_num_networks_input()
                subnets = self.calculator.calculate_by_networks(num_networks)
            
            self._display_results(subnets)
        
        except KeyboardInterrupt:
            print("\nOperation interrupted by user.")
            logger.info("User interrupted the operation")
            sys.exit(0)
        except Exception as e:
            logger.error(f"Error in CLI execution: {e}")
            print(f"\nError: {e}")
            sys.exit(1)
    
    def _print_banner(self):
        """Print the application banner."""
        print("\n" + "=" * 50)
        print("IPv6 Subnet Calculator".center(50))
        print("Industrial-Grade Network Tool".center(50))
        print("=" * 50 + "\n")
    
    def _get_network_input(self) -> str:
        """Get and validate network IP input from user."""
        while True:
            try:
                network_ip = input("Enter the network IP address with prefix (e.g., 2001:db8::/32): ").strip()
                # Basic validation before creating the calculator
                if '/' not in network_ip:
                    raise InvalidIPError("Missing prefix length")
                ip_part = network_ip.split('/')[0]
                if not IPv6SubnetCalculator._validate_ipv6(ip_part):
                    raise InvalidIPError()
                return network_ip
            except InvalidIPError as ipe:
                print(f"Invalid input: {ipe}. Please try again.")
            except Exception as e:
                print(f"Error: {e}. Please try again.")
    
    def _get_mode_input(self) -> CalculationMode:
        """Get calculation mode from user."""
        while True:
            try:
                print("\nCalculation Mode:")
                print("1. Calculate by number of hosts per subnet")
                print("2. Calculate by number of networks")
                choice = input("Enter your choice (1 or 2): ").strip()
                
                if choice == '1':
                    return CalculationMode.BY_HOSTS
                elif choice == '2':
                    return CalculationMode.BY_NETWORKS
                else:
                    print("Invalid choice. Please enter 1 or 2.")
            except Exception as e:
                print(f"Error: {e}. Please try again.")
    
    def _get_num_hosts_input(self) -> int:
        """Get number of hosts input from user."""
        while True:
            try:
                num_hosts = int(input("Enter the number of hosts required per subnet: ").strip())
                if num_hosts < 1:
                    raise InvalidHostCountError()
                return num_hosts
            except ValueError:
                print("Invalid input. Please enter a valid integer.")
            except InvalidHostCountError as ihce:
                print(ihce)
    
    def _get_num_networks_input(self) -> int:
        """Get number of networks input from user."""
        while True:
            try:
                num_networks = int(input("Enter the number of networks required: ").strip())
                if num_networks < 1:
                    raise InvalidNetworkCountError()
                return num_networks
            except ValueError:
                print("Invalid input. Please enter a valid integer.")
            except InvalidNetworkCountError as ince:
                print(ince)
    
    def _display_results(self, subnets: List[ipaddress.IPv6Network]):
        """Display the calculation results to the user."""
        print("\n" + "=" * 50)
        print("CALCULATION RESULTS".center(50))
        print("=" * 50)
        
        # Display network summary
        summary = self.calculator.get_network_summary()
        print("\nOriginal Network Summary:")
        print(f"Network: {summary['network']}")
        print(f"Network Address: {summary['network_address']}")
        print(f"Broadcast Address: {summary['broadcast_address']}")
        print(f"Prefix Length: /{summary['prefix_length']}")
        print(f"Total Addresses: {summary['total_addresses']:,}")
        print(f"Usable Addresses: {summary['usable_addresses']:,}")
        
        # Display subnet summary
        print("\nSubnet Summary:")
        if self.mode == CalculationMode.BY_HOSTS:
            hosts_per_subnet = subnets[0].num_addresses - 2 if subnets[0].num_addresses > 2 else 0
            print(f"Number of Subnets: {len(subnets)}")
            print(f"Hosts per Subnet: {hosts_per_subnet:,}")
        else:
            print(f"Number of Subnets: {len(subnets)}")
        
        print(f"New Prefix Length: /{self.calculator.prefix}")
        
        # Display first few subnets (limit to 5 for display)
        display_limit = 5
        print(f"\nSubnet Details (showing first {min(display_limit, len(subnets))} of {len(subnets)}):")
        for i, subnet in enumerate(subnets[:display_limit]):
            details = self.calculator.get_subnet_details(subnet)
            print(f"\nSubnet {i + 1}:")
            print(f"Network Address: {details['network_address']}")
            print(f"First Usable: {details['first_usable']}")
            print(f"Last Usable: {details['last_usable']}")
            print(f"Broadcast Address: {details['broadcast_address']}")
            print(f"Prefix Length: /{details['prefix_length']}")
            print(f"Usable Addresses: {details['usable_addresses']:,}")
        
        if len(subnets) > display_limit:
            print(f"\n... and {len(subnets) - display_limit} more subnets not displayed ...")
        
        print("\nCalculation complete.")

def main():
    """Main entry point for the application."""
    try:
        cli = SubnetCalculatorCLI()
        cli.run()
    except Exception as e:
        logger.critical(f"Application error: {e}")
        print(f"\nA critical error occurred: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
