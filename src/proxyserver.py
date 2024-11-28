import socket
import threading

BUFFER_SIZE = 4096
HOST = '127.0.0.1'  # Proxy server will listen on localhost
PORT = 12345          # Designated port for the proxy server

def handle_client(client_socket):
    try:
        # Receive request from client
        request = client_socket.recv(BUFFER_SIZE)
        
        # Parse the request to extract target host and port
        lines = request.split(b'\r\n')
        first_line = lines[0].decode('utf-8')
        method, url, _ = first_line.split()
        
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
    finally:
        client_socket.close()


def forward_data(source, destination):
    while True:
        data = source.recv(BUFFER_SIZE)
        if not data:
            break
        destination.sendall(data)


def start_proxy():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind((HOST, PORT))
        server_socket.listen(5)
        print(f"[*] Proxy server listening on {HOST}:{PORT}")

        while True:
            client_socket, addr = server_socket.accept()
            print(f"[+] Connection established from {addr}")
            client_thread = threading.Thread(target=handle_client, args=(client_socket,))
            client_thread.start()

if __name__ == "__main__":
    start_proxy()
