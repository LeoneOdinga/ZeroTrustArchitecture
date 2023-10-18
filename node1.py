from peer import Peer

if __name__ == '__main__':
    node1 = Peer('127.0.0.1', 8080)
    node1.start_listen_and_send_thread()
    
    # Predefined target peer's address (Node 2)
    target_host, target_port = '127.0.0.1', 8081
    node1.create_connection(target_host, target_port)
    
    while True:
        try:
            message = input("Enter a message to send (or press Enter to receive messages): ")
            if message:
                node1.exchange_data(node1.connections[0], message.encode())
            else:
                # Code for handling received messages can be added here
                pass
        except KeyboardInterrupt:
            print("Keyboard interrupt detected. Closing connections.")
            node1.close()
            break
