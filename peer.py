class Node:
    def __init__(self, name):
        self.name = name
        self.port = {}
        self.connections = set()

    def establish_connection(self, other_node):
        if other_node == self:
            print(f"{self.name} cannot connect to itself.")
            return
        if other_node not in self.connections:
            self.connections.add(other_node)
            other_node.connections.add(self)
            self.port[other_node] = []
            other_node.port[self] = []
            print(f"{self.name} has established a connection with {other_node.name}")

    def send_message(self, other_node, message):
        if other_node in self.port:
            self.port[other_node].append(message)
            print(f"{self.name} sent a message to {other_node.name}: {message}")
        else:
            print(f"{self.name} is not connected to {other_node.name}.")

    def receive_messages(self):
        for other_node, messages in self.port.items():
            for message in messages:
                print(f"{self.name} received a message from {other_node.name}: {message}")
            self.port[other_node] = []

    def terminate_connection(self, other_node):
        if other_node in self.connections:
            self.connections.remove(other_node)
            other_node.connections.remove(self)
            del self.port[other_node]
            del other_node.port[self]
            print(f"{self.name} has terminated the connection with {other_node.name}")
        else:
            print(f"{self.name} is not connected to {other_node.name}.")

    def close_port(self, other_node):
        if other_node in self.port:
            del self.port[other_node]
            if self in other_node.port:
                del other_node.port[self]
            print(f"{self.name} has closed the port to {other_node.name}")

# Create three nodes
node1 = Node("Node1")
node2 = Node("Node2")
node3 = Node("Node3")

# Establish connections between nodes
node1.establish_connection(node2)
node1.establish_connection(node3)
node2.establish_connection(node3)

# Send and receive messages
node1.send_message(node2, "Hello from Node1")
node2.send_message(node1, "Hi there from Node2")
node3.send_message(node1, "Greetings from Node3")

node1.receive_messages()
node2.receive_messages()
node3.receive_messages()

# Terminate connections
node1.terminate_connection(node2)
node2.terminate_connection(node3)

# Close ports
node1.close_port(node3)

# Try sending a message after terminating a connection
node1.send_message(node2, "This message won't be sent")

# Try establishing a connection to itself
node1.establish_connection(node1)
