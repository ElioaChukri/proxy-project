import logging

from allowlist import access_control
from setup_log import setup_logging

if __name__ == '__main__':

    # Function to set up the global logger
    setup_logging()

    # Get the logger for current module
    logger = logging.getLogger('main')

    # Example usage
    ip = '192.168.1.1'
    if access_control.is_allowed(ip):
        logger.info(f'{ip} is allowed')
    else:
        logger.info(f'{ip} is not allowed')
