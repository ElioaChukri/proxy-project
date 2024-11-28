import socket
import threading

BUFFER_SIZE = 4096
HOST = '127.0.0.1'
PORT = 12345
SOCKET_TIMEOUT = 10  # Timeout in seconds for all sockets

def handle_client(client_socket):
    """
    This function handles incoming client requests. It processes both HTTP and HTTPS traffic 
    by parsing the client's request, determining the target server, and establishing a connection to it. 
    For HTTPS requests, it sets up a secure tunnel to forward encrypted traffic without decrypting it. 
    For HTTP requests, it forwards the client's request to the target server, retrieves the response, 
    and sends it back to the client.
    """
    try:
        client_socket.settimeout(SOCKET_TIMEOUT)
        
        # Receive request from client
        request = client_socket.recv(BUFFER_SIZE)
        if not request:
            raise ValueError("Empty request received.")

        # Parse the request to extract target host and port
        try:
            lines = request.split(b'\r\n')
            first_line = lines[0].decode('utf-8')
            method, url, _ = first_line.split()
        except Exception:
            client_socket.sendall(b"HTTP/1.1 400 Bad Request\r\n\r\nInvalid request format.")
            return

        # Extract hostname and port from the URL
        if '://' in url:
            url = url.split('://')[1]
        host_port_path = url.split('/', 1)
        host_port = host_port_path[0]
        path = '/' + host_port_path[1] if len(host_port_path) > 1 else '/'

        if ':' in host_port:
            host, port = host_port.split(':')
            port = int(port)
        else:
            host = host_port
            port = 443 if method == 'CONNECT' else 80

        # Handle HTTPS (CONNECT method)
        if method == 'CONNECT':
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as target_socket:
                target_socket.settimeout(SOCKET_TIMEOUT)
                target_socket.connect((host, port))
                client_socket.sendall(b'HTTP/1.1 200 Connection Established\r\n\r\n')

                # Securely tunnel traffic without decrypting
                client_to_target = threading.Thread(target=forward_data, args=(client_socket, target_socket))
                target_to_client = threading.Thread(target=forward_data, args=(target_socket, client_socket))
                client_to_target.start()
                target_to_client.start()
                client_to_target.join()
                target_to_client.join()
        else:
            # Handle HTTP requests
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as target_socket:
                target_socket.settimeout(SOCKET_TIMEOUT)
                target_socket.connect((host, port))
                # Modify the request to update the path
                updated_request = request.replace(url.encode('utf-8'), path.encode('utf-8'), 1)
                target_socket.sendall(updated_request)

                # Receive response from target server and send to client
                while True:
                    data = target_socket.recv(BUFFER_SIZE)
                    if not data:
                        break
                    client_socket.sendall(data)
    except socket.timeout:
        client_socket.sendall(b"HTTP/1.1 504 Gateway Timeout\r\n\r\nThe connection timed out.")
    except ValueError as ve:
        client_socket.sendall(b"HTTP/1.1 400 Bad Request\r\n\r\n" + str(ve).encode('utf-8'))
    except Exception as e:
        client_socket.sendall(b"HTTP/1.1 500 Internal Server Error\r\n\r\nAn error occurred.")
    finally:
        client_socket.close()

def forward_data(source, destination):
    """
    This function facilitates bidirectional data transfer between two sockets. It is used 
    primarily for HTTPS tunneling, where encrypted traffic is forwarded between the client 
    and the target server without decryption. The function reads data from the source socket 
    and writes it to the destination socket until the connection is closed.
    """
    try:
        while True:
            data = source.recv(BUFFER_SIZE)
            if not data:
                break
            destination.sendall(data)
    except Exception:
        pass  # Ignore errors during forwarding
    finally:
        source.close()
        destination.close()

def start_proxy():
    """
    This function initializes and starts the proxy server. It binds to the specified host 
    and port, listens for incoming client connections, and spawns a new thread for each 
    client to handle their requests concurrently. The server runs indefinitely until 
    interrupted by the user.
    """
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind((HOST, PORT))
        server_socket.listen(5)
        print(f"[*] Proxy server listening on {HOST}:{PORT}")

        while True:
            try:
                client_socket, addr = server_socket.accept()
                print(f"[+] Connection established from {addr}")
                client_thread = threading.Thread(target=handle_client, args=(client_socket,))
                client_thread.start()
            except KeyboardInterrupt:
                print("[*] Shutting down server.")
                break

if __name__ == "__main__":
    start_proxy()
