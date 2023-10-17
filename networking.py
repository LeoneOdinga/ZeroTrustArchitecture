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

if __name__ == '__main__':
    node1 = Peer('127.0.0.1', 8080)
    node2 = Peer('127.0.0.1', 8081)

    node1.start_listening_thread()
    node2.start_listening_thread()

    # Connect node1 to node2
    node1.create_connection('127.0.0.1', 8081)

    while True:
        try:
            message = input("Enter a message to send: ")
            if message:
                node1.exchange_data(node2.connections[0], message.encode())
        except KeyboardInterrupt:
            print("Keyboard interrupt detected. Closing connections.")
            node1.close()
            node2.close()
            break
