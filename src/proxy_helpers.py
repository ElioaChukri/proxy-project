# Author: Bryan El Medawar

import logging
import ssl
import time

BUFFER_SIZE = 4096
TIMEOUT_INTERVAL = 10  # This is the timeout used for all sockets in seconds
CACHE_TIMEOUT = 60  # Cache expiration time in seconds (for simplicity)

logger = logging.getLogger('proxyhelpers')

cache = {}


def forward_data(source: ssl.SSLSocket, destination: ssl.SSLSocket):
    """
    Forward data from a source socket to a destination socket. This function reads data from the source socket
    and writes it to the destination socket until there is no more data to read. It then closes both sockets.

    :param source: The socket object to read data from.
    :param destination: The socket object to write data to.
    :return: None
    """
    try:
        while True:
            data = source.recv(BUFFER_SIZE)
            if not data:
                break
            logger.debug(f"Forwarding {len(data)} bytes")
            logger.debug(data)
            destination.sendall(data)
    except Exception:
        pass
    finally:
        source.close()
        destination.close()


def check_cache(key):
    """
    Check the cache for a given key and return the cached response if it exists and is not expired.
    :param key: The key to check in the cache.
    :return: The cached response if it exists and is not expired, otherwise None.
    """
    cached_data = cache.get(key)
    if cached_data and time.time() - cached_data['timestamp'] < CACHE_TIMEOUT:
        return cached_data['response']
    return None


def cache_response(key, response) -> None:
    """
    Cache the response for a given key, storing the response and timestamp.
    :param key: The key to store in the cache.
    :param response: The response to cache.
    :return: None
    """
    cache[key] = {
        'response': response,
        'timestamp': time.time()
    }
