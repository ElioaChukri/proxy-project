# Author: Elio Anthony Chucri

import logging
import socket
import ssl
import threading
import time
from OpenSSL import crypto
from proxy_helpers import forward_data

# Create a logger for the HTTPS module
logger = logging.getLogger('https')

def generate_certificate_for_host(hostname) -> str:
    """
    Dynamically generate a certificate for the specified hostname using the proxy's CA.
    The certificate is valid for 10 years.
    :param hostname: The hostname for which to generate the certificate.
    :return: The path to the generated certificate file.
    """
    ca_cert_file = "../certs/proxy.crt"
    ca_key_file = "../certs/proxy.key"

    # Load CA certificate and key
    with open(ca_cert_file, "rb") as f:
        ca_cert = crypto.load_certificate(crypto.FILETYPE_PEM, f.read())
    with open(ca_key_file, "rb") as f:
        ca_key = crypto.load_privatekey(crypto.FILETYPE_PEM, f.read())

    # Generate a new key pair for the host
    key = crypto.PKey()
    key.generate_key(crypto.TYPE_RSA, 2048)

    # Create a new certificate
    cert = crypto.X509()
    cert.set_serial_number(int(time.time() * 1000))
    cert.gmtime_adj_notBefore(0)
    cert.gmtime_adj_notAfter(315360000)  # 10 years
    cert.set_issuer(ca_cert.get_subject())
    cert.get_subject().CN = hostname
    cert.set_pubkey(key)

    # Add Subject Alternative Name (SAN) extension
    san = f"DNS:{hostname}"
    cert.add_extensions([
        crypto.X509Extension(b"subjectAltName", False, san.encode())
    ])

    # Sign the certificate with the CA's key
    cert.sign(ca_key, "sha256")

    # Save the certificate and key to a file
    cert_file = f"../certs/{hostname}.pem"
    with open(cert_file, "wb") as f:
        f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert))
        f.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, key))

    return cert_file


def handle_https(client_socket, host, port) -> None:
    """
    Handle HTTPS requests by decrypting traffic from the client and forwarding it to the server.
    :param client_socket: The client socket connected to the proxy.
    :param host: The hostname of the target server.
    :param port: The port of the target server.
    """
    try:
        # Send HTTP 200 response to the client
        client_socket.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")

        # Create a certificate for the target hostname
        cert_file = generate_certificate_for_host(host)

        # Wrap the client socket with SSL to decrypt traffic
        client_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        client_context.load_cert_chain(certfile=cert_file)

        # Perform TLS handshake with the client
        client_tls_socket = client_context.wrap_socket(client_socket, server_side=True)

        # Connect to the target server
        with socket.create_connection((host, port)) as target_socket:
            server_context = ssl.create_default_context()
            with server_context.wrap_socket(target_socket, server_hostname=host) as server_tls_socket:
                logger.debug("Forwarding data between client and server")
                # Forward data between the client and server
                client_to_server = threading.Thread(target=forward_data, args=(client_tls_socket, server_tls_socket))
                server_to_client = threading.Thread(target=forward_data, args=(server_tls_socket, client_tls_socket))
                client_to_server.start()
                server_to_client.start()
                client_to_server.join()
                server_to_client.join()

    except Exception as e:
        logger.error(f"Error handling HTTPS for {host}:{port} - {e}")
        try:
            client_socket.sendall(b"HTTP/1.1 500 Internal Server Error\r\n\r\n")
        except Exception:
            logger.error("Failed to send error response to client.")
    finally:
        client_socket.close()
