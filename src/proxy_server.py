# Author: Ghady Nasrallah

import logging
import socket
import threading

from panel.allowlist import access_control
from https import handle_https
from proxy_helpers import check_cache, cache_response
from setup_log import setup_logging

BUFFER_SIZE = 4096
TIMEOUT_INTERVAL = 10  # This is the timeout used for all sockets in seconds
CACHE_TIMEOUT = 60  # Cache expiration time in seconds (for simplicity)
HOST_IP = '127.0.0.1'
PORT_NUMBER = 12345

logger = logging.getLogger('proxy_server')


def handle_client(client_socket):
    """
    This function handles incoming client requests. It processes both HTTP and HTTPS traffic
    by adding the client's request, determining the target server and establishing a connection with it
    in order to forward the request to it.
    For HTTPS requests, it sets up a secure tunnel to forward encrypted traffic without decrypting it.
    For HTTP requests, it forwards the client's request to the target server, retrieves the response,
    and sends it back to the client.

    :param client_socket: The socket object representing the client connection.
    :return: None
    """
    try:
        client_socket.settimeout(TIMEOUT_INTERVAL)
        request = client_socket.recv(BUFFER_SIZE)
        if not request:
            raise ValueError("Empty request received.")
        try:
            lines = request.split(b'\r\n')
            first_line = lines[0].decode('utf-8')
            method, full_url, http_version = first_line.split()
        except Exception:
            client_socket.sendall(b"HTTP/1.1 400 Bad Request\r\n\r\nInvalid request format.")
            return

        # Here we extract Hostname and port from the URL
        if '://' in full_url:
            url = full_url.split('://', 1)[1]
            host_port_path = url.split('/', 1)
            host_port = host_port_path[0]
            path = '/' + host_port_path[1] if len(host_port_path) > 1 else '/'
        else:
            path = full_url
            host_port = \
                next((line for line in lines if line.lower().startswith(b'host:')), b'').decode('utf-8').split(': ')[1]

        if ':' in host_port:
            host, port = host_port.split(':')
            port = int(port)
        else:
            host = host_port
            port = 443 if method == 'CONNECT' else 80

        if host == 'localhost' or host == '127.0.0.1':
            client_socket.sendall(b"HTTP/1.1 403 Forbidden\r\n\r\nAccess to localhost is not allowed.")
            return


        # Check if the target host is allowed
        if not access_control.is_allowed(host):
            logger.info(f"Blocked request to {host}")
            client_socket.sendall(b"HTTP/1.1 403 Forbidden\r\n\r\nAccess to this host is not allowed.")
            return

        # Cache handling for HTTP method GET
        cache_key = f"{method} {full_url}   "
        cached_response = check_cache(cache_key)
        if cached_response:
            # Serve from cache if available
            logger.info(f"Cache hit for {cache_key}")
            client_socket.sendall(cached_response)
            return

        # HTTPS request handling
        if method == 'CONNECT':
            host_port = full_url.split(':')
            host = host_port[0]
            port = int(host_port[1]) if len(host_port) > 1 else 443
            handle_https(client_socket, host, port)
            return
        else:
            # HTTP request handling
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as target_socket:
                target_socket.settimeout(TIMEOUT_INTERVAL)
                target_socket.connect((host, port))
                updated_request_line = f"{method} {path} {http_version}\r\n".encode('utf-8')
                updated_request = updated_request_line + b'\r\n'.join(lines[1:])
                target_socket.sendall(updated_request)

                # Here we receive the response from the target server and send all the data to client
                while True:
                    data = target_socket.recv(BUFFER_SIZE)
                    if not data:
                        break
                    if method == 'GET':
                        logger.debug(f"Caching response for {cache_key}")
                        cache_response(cache_key, data)
                    client_socket.sendall(data)

    except socket.timeout:
        client_socket.sendall(b"HTTP/1.1 504 Gateway Timeout\r\n\r\nThe connection timed out.")
    except ValueError as ve:
        client_socket.sendall(b"HTTP/1.1 400 Bad Request\r\n\r\n" + str(ve).encode('utf-8'))
    except Exception as e:
        logger.error(f"Error handling client request - {e}")
        client_socket.sendall(b"HTTP/1.1 500 Internal Server Error\r\n\r\nAn error occurred.")
    finally:
        client_socket.close()


def start_proxy():
    """
    This function initializes and starts the proxy server. It binds to the specified host
    and port, listens for incoming client connections, and spawns a new thread for each
    client to handle their requests concurrently. The server runs indefinitely until
    interrupted by the user.
    """
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind((HOST_IP, PORT_NUMBER))
        server_socket.listen(5)
        logger.info(f"[*] Proxy server listening on {HOST_IP}:{PORT_NUMBER}")

        while True:
            try:
                client_socket, addr = server_socket.accept()
                logger.debug(f"[+] Connection established from {addr}")
                client_thread = threading.Thread(target=handle_client, args=(client_socket,))
                client_thread.start()
            except KeyboardInterrupt:
                logger.error("[*] Shutting down server.")
                break


if __name__ == "__main__":
    setup_logging()
    start_proxy()
