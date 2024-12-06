# Author: Elio Anthony Chucri

import logging
from logging.handlers import RotatingFileHandler

LOG_LEVEL = logging.DEBUG
FORMAT = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
DATEFMT = '%Y-%m-%d %H:%M:%S'


def setup_logging() -> None:
    """
    Configure global logging settings for the application.

    Sets up logging to output messages to both a file ('../logs/app.log') and the console.
    If file logging fails (e.g., due to directory or permission issues), it falls back to console-only logging.

    :return: None
    """
    try:
        log_formatter = logging.Formatter(
            FORMAT,
            datefmt=DATEFMT
        )

        # Rotating file handler
        file_handler = RotatingFileHandler(
            '../logs/app.log',  # Log file path, may raise FileNotFoundError or PermissionError
            maxBytes=5 * 1024 * 1024,  # 5 MB
            backupCount=3  # Keep 3 backup files
        )

        file_handler.setFormatter(log_formatter)

        # Stream handler for console output
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(log_formatter)
        logging.basicConfig(
            level=LOG_LEVEL,
            handlers=[file_handler, console_handler]
        )

    except FileNotFoundError as e:
        # Fallback to console-only logging
        logging.basicConfig(
            level=LOG_LEVEL,
            format=FORMAT,
            datefmt=DATEFMT
        )
        logging.error("File logging setup failed. Falling back to console-only logging. Error: %s", e)

    except PermissionError as e:
        # Fallback to console-only logging
        logging.basicConfig(
            level=LOG_LEVEL,
            format=FORMAT,
            datefmt=DATEFMT
        )
        logging.error("File logging setup failed. Falling back to console-only logging. Error: %s", e)


# Example usage
if __name__ == '__main__':
    # Run the setup_logging function if the script is run directly
    setup_logging()

    logger = logging.getLogger('setup')

    # Log a message with the DEBUG level
    logger.debug('This is a debug message')

    # Log a message with the INFO level
    logger.info('This is an info message')

    # Log a message with the WARNING level
    logger.warning('This is a warning message')

    # Log a message with the ERROR level
    logger.error('This is an error message')

    # Log a message with the CRITICAL level
    logger.critical('This is a critical message')
