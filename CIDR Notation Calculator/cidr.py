import ipaddress
import json
import sys
import argparse
from typing import Optional, Tuple, Union
from enum import Enum, auto
from dataclasses import dataclass
import logging
from logging.handlers import RotatingFileHandler

class ConversionType(Enum):
    """Supported conversion types"""
    SUBNET_MASK = auto()
    SUBNET = auto()
    IP_RANGE = auto()

class CIDRError(Exception):
    """Base exception for CIDR conversion errors"""
    def __init__(self, message, error_code = None):
        super().__init__(message, error_code)

class ValidationError(CIDRError):
    """Raised for invalid input"""
    def __init__(self, message, error_code = None):
        super().__init__(message, error_code)

class ConversionError(CIDRError):
    """Raised when conversion fails"""
    def __init__(self, message, error_code = None):
        super().__init__(message, error_code)

class IPVersion(Enum):
    """IP protocol versions"""
    IPV4 = auto()
    IPV6 = auto()

@dataclass
class CIDRConverterConfig:
    """Configuration for CIDR converter"""
    log_file: str = 'cidr_converter.log'
    log_level: str = 'INFO'
    max_network_size: int = 24  # Maximum allowed network size for IPv4 (/24)

class CIDRConverter:
    """Industrial-grade CIDR notation converter"""
    
    def __init__(self, config: Optional[CIDRConverterConfig] = None):
        """
        Initialize CIDR converter with configuration
        
        Args:
            config: CIDRConverterConfig instance (uses defaults if None)
        """
        self.config = config or CIDRConverterConfig()
        self._setup_logging()
    
    def _setup_logging(self) -> None:
        """Configure logging system"""
        logging.basicConfig(
            level=self.config.log_level,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                RotatingFileHandler(
                    self.config.log_file,
                    maxBytes=5*1024*1024,  # 5MB
                    backupCount=3
                ),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger(__name__)
    
    def _validate_input(self, input_str: str, conversion_type: ConversionType) -> None:
        """
        Validate input based on conversion type
        
        Args:
            input_str: Input to validate
            conversion_type: Type of conversion
            
        Raises:
            ValidationError: If input is invalid
        """
        if not input_str:
            raise ValidationError("Input cannot be empty")
        
        if conversion_type == ConversionType.SUBNET_MASK:
            try:
                ipaddress.IPv4Address(input_str)
            except ipaddress.AddressValueError:
                raise ValidationError("Invalid subnet mask format")
            
            # Validate it's actually a valid subnet mask
            octets = list(map(int, input_str.split('.')))
            bitmask = (octets[0] << 24) | (octets[1] << 16) | (octets[2] << 8) | octets[3]
            if not all((bitmask << i) & 0x80000000 == 0 for i in range(32 - bin(bitmask).count('1'))):
                raise ValidationError("Invalid subnet mask (not contiguous ones)")
        
        elif conversion_type in (ConversionType.SUBNET, ConversionType.IP_RANGE):
            try:
                if '/' in input_str and conversion_type == ConversionType.SUBNET:
                    network = ipaddress.ip_network(input_str, strict=False)
                    if network.version == 4 and network.prefixlen < self.config.max_network_size:
                        self.logger.warning(
                            f"Large IPv4 network detected: {input_str}. "
                            f"Maximum recommended size is /{self.config.max_network_size}"
                        )
                elif conversion_type == ConversionType.IP_RANGE:
                    if '-' in input_str:
                        start, end = input_str.split('-', 1)
                        ipaddress.IPv4Address(start.strip())
                        ipaddress.IPv4Address(end.strip())
                    else:
                        ipaddress.IPv4Address(input_str)
            except ValueError as e:
                raise ValidationError(f"Invalid input format: {str(e)}")
    
    def convert_subnet_mask(self, subnet_mask: str) -> int:
        """
        Convert subnet mask to CIDR notation (prefix length)
        
        Args:
            subnet_mask: Subnet mask (e.g., "255.255.255.0")
            
        Returns:
            Prefix length (e.g., 24)
            
        Raises:
            ValidationError: If subnet mask is invalid
            ConversionError: If conversion fails
        """
        try:
            self._validate_input(subnet_mask, ConversionType.SUBNET_MASK)
            network = ipaddress.ip_network(f'0.0.0.0/{subnet_mask}', strict=False)
            self.logger.info(f"Converted subnet mask {subnet_mask} to /{network.prefixlen}")
            return network.prefixlen
        except ValidationError:
            raise
        except Exception as e:
            self.logger.error(f"Subnet mask conversion failed: {str(e)}")
            raise ConversionError(f"Could not convert subnet mask: {str(e)}")
    
    def convert_subnet(self, subnet: str) -> Tuple[int, IPVersion]:
        """
        Extract CIDR notation from a given subnet
        
        Args:
            subnet: Subnet in CIDR notation (e.g., "192.168.1.0/24")
            
        Returns:
            Tuple of (prefix_length, IPVersion)
            
        Raises:
            ValidationError: If subnet is invalid
            ConversionError: If conversion fails
        """
        try:
            self._validate_input(subnet, ConversionType.SUBNET)
            network = ipaddress.ip_network(subnet, strict=False)
            version = IPVersion.IPV4 if network.version == 4 else IPVersion.IPV6
            self.logger.info(f"Extracted CIDR /{network.prefixlen} from subnet {subnet}")
            return network.prefixlen, version
        except ValidationError:
            raise
        except Exception as e:
            self.logger.error(f"Subnet conversion failed: {str(e)}")
            raise ConversionError(f"Could not convert subnet: {str(e)}")
    
    def convert_ip_range(self, ip_range: str) -> Tuple[str, IPVersion]:
        """
        Convert IP range to CIDR notation
        
        Args:
            ip_range: IP range (e.g., "192.168.1.1-192.168.1.254" or "192.168.1.1")
            
        Returns:
            Tuple of (CIDR_notation, IPVersion)
            
        Raises:
            ValidationError: If IP range is invalid
            ConversionError: If conversion fails
        """
        try:
            self._validate_input(ip_range, ConversionType.IP_RANGE)
            
            if '-' in ip_range:
                start_ip, end_ip = ip_range.split('-', 1)
                start_ip = ipaddress.IPv4Address(start_ip.strip())
                end_ip = ipaddress.IPv4Address(end_ip.strip())
                
                if start_ip > end_ip:
                    start_ip, end_ip = end_ip, start_ip
                
                networks = list(ipaddress.summarize_address_range(start_ip, end_ip))
                if len(networks) > 1:
                    self.logger.warning(
                        f"IP range {ip_range} spans multiple CIDR blocks. "
                        "Using the smallest encompassing network."
                    )
                
                best_network = networks[0]
                for net in networks[1:]:
                    if net.prefixlen < best_network.prefixlen:
                        best_network = net
                
                version = IPVersion.IPV4 if best_network.version == 4 else IPVersion.IPV6
                self.logger.info(f"Converted IP range {ip_range} to {best_network}")
                return str(best_network), version
            else:
                # Single IP address
                ip = ipaddress.IPv4Address(ip_range.strip())
                network = ipaddress.ip_network(f"{ip}/32", strict=False)
                self.logger.info(f"Converted single IP {ip_range} to {network}")
                return str(network), IPVersion.IPV4
        except ValidationError:
            raise
        except Exception as e:
            self.logger.error(f"IP range conversion failed: {str(e)}")
            raise ConversionError(f"Could not convert IP range: {str(e)}")

class CIDRConverterCLI:
    """Command-line interface for CIDR converter"""
    
    @staticmethod
    def run_interactive():
        """Run interactive CIDR conversion session"""
        try:
            print("Industrial CIDR Notation Converter")
            print("=" * 40)
            
            # Initialize with default config
            converter = CIDRConverter()
            
            while True:
                print("\nConversion types:")
                print("1. Subnet Mask to CIDR")
                print("2. Subnet to CIDR")
                print("3. IP Range to CIDR")
                print("4. Exit")
                
                choice = input("Select an option (1-4): ").strip()
                
                if choice == '1':
                    subnet_mask = input("Enter subnet mask (e.g., 255.255.255.0): ").strip()
                    try:
                        prefix_len = converter.convert_subnet_mask(subnet_mask)
                        print(f"\nCIDR Notation: /{prefix_len}")
                    except CIDRError as e:
                        print(f"\nError: {str(e)}")
                
                elif choice == '2':
                    subnet = input("Enter subnet (e.g., 192.168.1.0/24): ").strip()
                    try:
                        prefix_len, version = converter.convert_subnet(subnet)
                        print(f"\nCIDR Notation: /{prefix_len} ({version.name})")
                    except CIDRError as e:
                        print(f"\nError: {str(e)}")
                
                elif choice == '3':
                    ip_range = input("Enter IP range (e.g., 192.168.1.1-192.168.1.254): ").strip()
                    try:
                        cidr, version = converter.convert_ip_range(ip_range)
                        print(f"\nCIDR Notation: {cidr} ({version.name})")
                    except CIDRError as e:
                        print(f"\nError: {str(e)}")
                
                elif choice == '4':
                    print("Exiting...")
                    break
                
                else:
                    print("\nError: Invalid choice. Please try again.")
        
        except KeyboardInterrupt:
            print("\nOperation cancelled by user")
            sys.exit(0)
        except Exception as e:
            print(f"\nUnexpected error: {str(e)}")
            sys.exit(1)
    
    @staticmethod
    def run_from_args():
        """Run CIDR converter from command-line arguments"""
        parser = argparse.ArgumentParser(
            description='Industrial CIDR Notation Converter',
            epilog='Example: cidr.py subnet-mask 255.255.255.0'
        )
        
        # Subcommands
        subparsers = parser.add_subparsers(dest='command', required=True)
        
        # Subnet mask command
        mask_parser = subparsers.add_parser(
            'subnet-mask',
            help='Convert subnet mask to CIDR notation'
        )
        mask_parser.add_argument(
            'mask',
            help='Subnet mask (e.g., 255.255.255.0)'
        )
        
        # Subnet command
        subnet_parser = subparsers.add_parser(
            'subnet',
            help='Extract CIDR notation from subnet'
        )
        subnet_parser.add_argument(
            'subnet',
            help='Subnet in CIDR notation (e.g., 192.168.1.0/24)'
        )
        
        # IP range command
        range_parser = subparsers.add_parser(
            'ip-range',
            help='Convert IP range to CIDR notation'
        )
        range_parser.add_argument(
            'range',
            help='IP range (e.g., 192.168.1.1-192.168.1.254)'
        )
        
        # Output options
        parser.add_argument(
            '--output',
            help='Output file for results'
        )
        parser.add_argument(
            '--log-level',
            choices=['DEBUG', 'INFO', 'WARNING', 'ERROR'],
            default='INFO',
            help='Logging level'
        )
        
        args = parser.parse_args()
        
        try:
            # Initialize with custom config
            config = CIDRConverterConfig(log_level=args.log_level)
            converter = CIDRConverter(config)
            
            result = {}
            
            if args.command == 'subnet-mask':
                prefix_len = converter.convert_subnet_mask(args.mask)
                result = {
                    'input': args.mask,
                    'type': 'subnet_mask',
                    'cidr_notation': f"/{prefix_len}",
                    'prefix_length': prefix_len
                }
            
            elif args.command == 'subnet':
                prefix_len, version = converter.convert_subnet(args.subnet)
                result = {
                    'input': args.subnet,
                    'type': 'subnet',
                    'cidr_notation': f"/{prefix_len}",
                    'prefix_length': prefix_len,
                    'ip_version': version.name
                }
            
            elif args.command == 'ip-range':
                cidr, version = converter.convert_ip_range(args.range)
                result = {
                    'input': args.range,
                    'type': 'ip_range',
                    'cidr_notation': cidr,
                    'ip_version': version.name
                }
            
            # Output results
            if args.output:
                with open(args.output, 'w') as f:
                    json.dump(result, f, indent=2)
                print(f"Results saved to {args.output}")
            else:
                print(json.dumps(result, indent=2))
        
        except KeyboardInterrupt:
            print("\nOperation cancelled by user", file=sys.stderr)
            sys.exit(0)
        except CIDRError as e:
            print(f"Error: {str(e)}", file=sys.stderr)
            sys.exit(1)
        except Exception as e:
            print(f"Unexpected error: {str(e)}", file=sys.stderr)
            sys.exit(1)

if __name__ == "__main__":
    if len(sys.argv) > 1:
        CIDRConverterCLI.run_from_args()
    else:
        CIDRConverterCLI.run_interactive()
