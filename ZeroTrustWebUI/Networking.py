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
        '3':'Policy Engine Node',
        '4':'Web UI'
    }

    # Python class constructor to initialize the class Networking
    def __init__(self, host, port, id=None, callback=None, max_connections=0):
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
                #convert the message to a json object
                json_message = {
                    "senderID": self.id,
                    "messageContent":message
                }
                # Send the message to the specific node
                self.send_to_node(target_node, json_message)
                print("Message sent to node:", node_id)
                break
        if target_node is None:
            print(f"Node {node_id} not found in inbound or outbound connections.")
    
    def message_is_from_access_proxy(self, sender_id):
        return sender_id == '1'

    def message_is_from_trust_engine(self, sender_id):
        return sender_id == '2'

    def message_is_from_policy_engine(self, sender_id):
        return sender_id == '3'
    
    def message_is_from_web_ui(self, sender_id):
        return sender_id == '4'
    
    def process_message_from_access_proxy(self, sender, message):
        print(f"Received a message from Access Proxy Node [{sender}]: {message}")
        # Your code to process messages from the Access Proxy Node goes here

    def process_message_from_trust_engine(self, sender, message):
        print(f"Received a message from Trust Engine Node [{sender}]: {message}")
        # Your code to process messages from the Trust Engine Node goes here

    def process_message_from_policy_engine(self, sender, message):
        print(f"Received a message from Policy Engine Node [{sender}]: {message}")
        # Your code to process messages from the Policy Engine Node goes here

    def process_message_from_web_ui(self, sender, message):
        print(f"Received an Access Request from Web UI [{sender}]: {message}")
        self.send_message_to_node('2',message)
        # Your code to process messages from the Policy Engine Node goes here

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
        sender_id = node.id  # Get the sender's ID
        message_content = data  # Get the message content

        if "senderID" in message_content:
            message_content = message_content["messageContent"]
            #extract other future message atributes like unique hash, and message intent

        # Process the message based on the sender's ID
        if self.message_is_from_access_proxy(sender_id):
            self.process_message_from_access_proxy(sender_id, message_content)
        elif self.message_is_from_trust_engine(sender_id):
            self.process_message_from_trust_engine(sender_id, message_content)
        elif self.message_is_from_policy_engine(sender_id):
            self.process_message_from_policy_engine(sender_id, message_content)
        elif self.message_is_from_web_ui(sender_id):
            self.process_message_from_web_ui(sender_id, message_content)
        else:
            print(f"Received a message from an unknown sender ({sender_id}): {message_content}")
        
    def node_disconnect_with_outbound_node(self, node):
        print(f"\n{self.get_node_role(self.id)} wants to disconnect with {node.id}")   
            
    def node_request_to_stop(self):
        print(f"\nStopping the {self.get_node_role(self.id)} node")
        
