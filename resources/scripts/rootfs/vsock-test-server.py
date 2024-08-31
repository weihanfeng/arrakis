import socket
import sys

# VSOCK constants
VSOCK_SOCKET = 40  # AF_VSOCK
VMADDR_CID_ANY = 0xFFFFFFFF  # Allow any CID to connect

def vsock_echo_server(port):
    # Create a VSOCK socket
    sock = socket.socket(VSOCK_SOCKET, socket.SOCK_STREAM)
    
    server_address = (VMADDR_CID_ANY, port)
    sock.bind(server_address)
    
    # Listen for incoming connections
    sock.listen(1)
    print(f"VSOCK Echo Server listening on port {port}")

    while True:
        print("Waiting for a connection...")
        connection, client_address = sock.accept()
        try:
            print(f"Connection from {client_address}")
            
            while True:
                data = connection.recv(1024)
                if data:
                    print(f"Received: {data.decode('utf-8').strip()}")
                    connection.sendall(data)
                else:
                    break
                
        finally:
            connection.close()

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <port>")
        sys.exit(1)
    
    port = int(sys.argv[1])
    vsock_echo_server(port)