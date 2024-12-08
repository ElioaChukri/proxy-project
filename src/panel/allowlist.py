# Author: Elio Anthony Chucri

import ipaddress
import logging
from ipaddress import IPv4Network, IPv4Address
from sys import exit

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
            return set(
                line.strip()
                .replace("http://", "")
                .replace("https://", "")
                for line in f if line.strip()
            )
    except FileNotFoundError:
        logger.error("File not found: %s", filepath)
        return set()
    except PermissionError:
        logger.error("Permission denied: %s", filepath)
        return set()
    except Exception as e:
        logger.error("Error reading file: %s", e)
        return set()


def _load_cidr(addresses: set[str]) -> set[IPv4Network]:
    """
    Loads a list of CIDR ranges from a file into a set.

    Checks if the entry has '/' in it and then processes it as CIDR
    :param addresses: A set of non-empty strings containing potential CIDR ranges
    :return: A set of non-empty strings representing the CIDR ranges.
    """
    return {ipaddress.ip_network(addr, strict=False) for addr in addresses if '/' in addr}


class AccessControl:
    def __init__(self):
        """
        Initialize the AccessControl object with the contents of the whitelist and blacklist files.
        """

        try:
            self._whitelist = _load_list('../whitelist.txt')
            self._blacklist = _load_list('../blacklist.txt')
            self._whitelist_cidr = _load_cidr(self._whitelist)
            self._blacklist_cidr = _load_cidr(self._blacklist)
        except ValueError:
            logger.error(
                "Invalid entries found in whitelist/blacklist files. Make sure to only use IP addresses, CIDR ranges, and hostnames (without http:// or https://")
            exit(1)

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
            ip: str = domain_or_ip
            ipv4: IPv4Address = ipaddress.ip_address(ip)
            for address in self._whitelist:  # Whitelist takes precedence
                if ip == address or any(ipv4 in cidr for cidr in self._whitelist_cidr):
                    logger.debug(f'IP {ip} is whitelisted')
                    return True

            for address in self._blacklist:
                if ip == address or any(ipv4 in cidr for cidr in self._blacklist_cidr):
                    logger.debug(f'IP {ip} is blacklisted')
                    return False

        # It's a domain, direct check against domains
        else:
            domain = domain_or_ip
            if domain in self._whitelist:
                logger.debug(f'DOMAIN {domain} is whitelisted')
                return True

            if domain in self._blacklist:
                logger.debug(f'DOMAIN {domain} is blacklisted')
                return False

        logger.debug(f'{domain_or_ip} is not in either list, allowing by default')
        return True  # Default to allowing access if not found in either list

    def refresh_whitelist(self):
        """
        Refresh the whitelist by reloading the whitelist file.
        """
        logger.debug("Refreshing whitelist")
        self._whitelist = _load_list('../whitelist.txt')
        self._whitelist_cidr = _load_cidr(self._whitelist)

    def refresh_blacklist(self):
        """
        Refresh the blacklist by reloading the blacklist file.
        """
        logger.debug("Refreshing blacklist")
        self._blacklist = _load_list('../blacklist.txt')
        self._blacklist_cidr = _load_cidr(self._blacklist)

# Instantiate a global object to access from other modules
access_control = AccessControl()
