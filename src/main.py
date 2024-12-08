import logging
from multiprocessing import Process

import uvicorn

from proxy_server import start_proxy
from setup_log import setup_logging

setup_logging()
logger = logging.getLogger('main')


def start_admin_interface():
    """
    Start the admin interface for the proxy server.
    """
    logger.info("Starting admin interface on http://localhost:8000")
    uvicorn.run("panel.interface:app", host="localhost", port=8000)


if __name__ == '__main__':
    # Start the admin interface in a separate process
    admin_interface_process = Process(target=start_admin_interface).start()

    # Start the proxy server in the main process
    start_proxy()
