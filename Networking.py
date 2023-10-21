'''

Class that extends the p2pnetwork class to add application specific implementation Details 
Handles how communication happens between the access proxy, trust engine, and policy engine.
Uses peer to peer communication without involvement of a centralized server for establishing connections

'''

from p2pnetwork.node import Node

class Networking(Node):
    #Define a dictionary of the node roles based on their node.id attributes
    NODE_ROLE = {
        '1': 'Access Proxy Node',
        '2':'Trust Engine Node',
        '3':'Policy Engine Node'
    }

    # Python class constructor to initialize the class Networking
    def __init__(self, host, port, id=None, callback=None, max_connections=10):
        super(Networking, self).__init__(host, port, id, callback, max_connections)
        print(f"\n{self.get_node_role(self.id)} STARTED on {self.host}:{self.port}")
    
    #Define a function to extract the name of a node based on it's node.id attribute
    def get_node_role(self,node_id):
        return self.NODE_ROLE.get(node_id,'UNKNOWN ROLE')
    

    def send_message_to_node(self, node_id, message):
        # Find the specific node by its ID
        target_node = None

        for node in self.all_nodes:
            if node.id == node_id:
                target_node = node
                # Send the message to the specific node
                self.send_to_node(target_node, message)
                print("Message sent to node:", node_id)
                break
        if target_node is None:
            print(f"Node {node_id} not found in inbound or outbound connections.")

    

    def print_all_nodes(self):
        print("Outbound Nodes:")
        for node in self.nodes_outbound:
            print(f"Outbound Node ID: {node.id}, Host: {node.host}, Port: {node.port}")

        print("\nInbound Nodes:")
        for node in self.nodes_inbound:
            print(f"Inbound Node ID: {node.id}, Host: {node.host}, Port: {node.port}")


    # The methods below are called when events happen in the network

    def outbound_node_connected(self, node):
        node_role = self.get_node_role(node.id)
        print(f"\n{self.get_node_role(self.id)} Connected to {node_role}")
        
    def inbound_node_connected(self, node):
        print(f"\n{self.get_node_role(node.id)} Connected to {self.get_node_role(self.id)}")

    def inbound_node_disconnected(self, node):
        print(f"\n{self.get_node_role(node.id)} DISCONNECTED from {self.get_node_role(self.id)}")

    def outbound_node_disconnected(self, node):
        print(f"\n{self.get_node_role(self.id)} DISCONNECTED from {self.get_node_role(node.id)}")

    def node_message(self, node, data):
        print(f"\nReceived Data From {self.get_node_role(node.id)}: {str(data)}")
        
    def node_disconnect_with_outbound_node(self, node):
        print(f"\n{self.get_node_role(self.id)} wants to disconnect with {node.id}")   
            
    def node_request_to_stop(self):
        print(f"\nStopping the {self.get_node_role(self.id)} node")
        
