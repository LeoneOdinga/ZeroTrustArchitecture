from peer import Peer

if __name__ == '__main__':
    # Predefined target peer's address
    target_host, target_port = '127.0.0.1', 8080

    node2 = Peer('127.0.0.1', 8081)
    node2.start_listening_thread()

    while True:
        try:
            message = input("Enter a message to send (or press Enter to receive messages): ")
            if message:
                node2.create_connection(target_host, target_port)
                node2.exchange_data(node2.connections[0], message.encode())
            else:
                # Code for handling received messages can be added here
                pass
        except KeyboardInterrupt:
            print("Keyboard interrupt detected. Closing connections.")
            node2.close()
            break
