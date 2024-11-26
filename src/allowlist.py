import ipaddress
import logging
from ipaddress import IPv4Network, IPv4Address

# Get the logger for the current module
logger = logging.getLogger('allowlist')


def _load_list(filepath: str) -> set[str]:
    """
    Load a list of IP addresses or domains from a file into a set.

    Each line in the file is stripped of leading/trailing whitespace and empty lines are ignored.

    Silently ignores errors and returns an empty set if the file is not found, permission is denied, or an error occurs

    :param filepath: Path to the file containing IP addresses or domains, one per line.
    :return: A set of non-empty strings representing the IP addresses or domains.
    """
    try:
        with open(filepath, 'r') as f:
            return set(line.strip() for line in f if line.strip())
    except FileNotFoundError:
        logger.error("File not found: %s", filepath)
        return set()
    except PermissionError:
        logger.error("Permission denied: %s", filepath)
        return set()
    except Exception as e:
        logger.error("Error reading file: %s", e)
        return set()


def _match_ip(address: str, cidr: str) -> bool:
    """
    Check if an IP address matches a CIDR range.
    :param address: The IP address to check.
    :param cidr: The CIDR range to check against.
    :return: True if the IP address is in the CIDR range, False otherwise.
    """

    try:
        network: IPv4Network = ipaddress.ip_network(cidr, strict=False)
        ip_address: IPv4Address = ipaddress.ip_address(address)
        return ip_address in network  # Check if the IP address is in the network

    # If the CIDR range is invalid, return False
    except ValueError:
        return False


class AccessControl:
    def __init__(self):
        """
        Initialize the AccessControl object with the contents of the whitelist and blacklist files.
        """
        self._whitelist = _load_list('../whitelist.txt')
        self._blacklist = _load_list('../blacklist.txt')

    def is_allowed(self, domain_or_ip: str) -> bool:
        """
        Check if a domain or IP address is allowed based on the whitelist and blacklist.

        Whitelist takes precedence over blacklist.

        Note that this function does not check if the passed domain/IP is in a valid format

        :param domain_or_ip: The IP address or domain to check.
        :return: True if the address is whitelisted, False if it is blacklisted.
        """
        try:
            _ = ipaddress.ip_address(domain_or_ip)
            is_ip = True
        except ValueError:
            is_ip = False

        # If it's an IP, we check against IPs and CIDR ranges
        if is_ip:
            ip = domain_or_ip
            for address in self._whitelist:  # Whitelist takes precedence
                if ip == address or _match_ip(ip, address):
                    return True

            for address in self._blacklist:
                if ip == address or _match_ip(ip, address):
                    return False

        # It's a domain, direct check against domains
        else:
            domain = domain_or_ip
            if domain in self._whitelist:
                return True

            if domain in self._blacklist:
                return False

        return True  # Default to allowing access if not found in either list


# Instantiate a global object to access from other modules
access_control = AccessControl()

# Example usage
if __name__ == '__main__':
    from setup_log import setup_logging

    setup_logging()

    # Example usage
    test = '192.168.1.2'
    if access_control.is_allowed(test):
        logger.debug(f'{test} is allowed')
    else:
        logger.debug(f'{test} is not allowed')
