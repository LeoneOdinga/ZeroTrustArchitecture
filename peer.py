import socket
import threading

class Peer:
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.connections = []
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    def create_connection(self, target_host, target_port):
        # Create a connection to another peer
        try:
            target_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            target_sock.connect((target_host, target_port))
            self.connections.append(target_sock)
            print(f"Connected to {target_host}:{target_port}")
        except Exception as e:
            print(f"Failed to connect to {target_host}:{target_port}: {str(e)}")

    def listen(self):
        # Bind and listen for incoming connections
        self.sock.bind((self.host, self.port))
        self.sock.listen(5)

        while True:
            client, addr = self.sock.accept()
            self.connections.append(client)
            print(f"Connected to {addr[0]}:{addr[1]}")
            receive_thread = threading.Thread(target=self.receive_data, args=(client,))
            receive_thread.daemon = True
            receive_thread.start()

    def receive_data(self, connection):
        while True:
            try:
                data = connection.recv(1024)
                if not data:
                    break
                print(f"Received: {data.decode()}")
            except ConnectionResetError:
                break

    def exchange_data(self, target_peer, data):
        # Send data to a specific peer
        target_peer.send(data)

    def start_listening_thread(self):
        listen_thread = threading.Thread(target=self.listen)
        listen_thread.daemon = True
        listen_thread.start()

    def close(self):
        for connection in self.connections:
            connection.close()
        self.sock.close()
