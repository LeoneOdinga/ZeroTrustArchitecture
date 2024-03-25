'''

Class that extends the p2pnetwork class to add application specific implementation Details 
Handles how communication happens between the access proxy, trust engine, and policy engine.
Uses peer to peer communication without involvement of a centralized server for establishing connections

'''
import datetime
from p2pnetwork.node import Node
import yaml
import ZeroTrustWebUI.TrustAlgorithm as ta
from ZeroTrustWebUI.trust_signal_collection import *

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
                print(f"Message sent to: {self.get_node_role(node_id)}")
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
        #if this node is trust engine, check if the intent is 'request_trust_score'
        if message.get('intent') == 'request_trust_score':
            user_id = message.get('user_id')
            print(f"Received a Trust Score Request From: {user_id}")
            #get the trust score for this user_id using the trust algorithm
            user_trust_score = ta.calculate_overall_trust_score(user_id)
            print(f"Performing Trust Evaluation for the Subject({user_id})...")
            print(f"Subject({user_id}) Trust Score: {user_trust_score}")
            print(f"Sending the subject's trust score to Policy Engine for policy validation...")
            data = {
                'user_id': user_id,
                'intent': 'request_access_decision',
                'user_trust_score': user_trust_score
            }
            self.send_message_to_node('3',data)
    def make_access_decision(self,user_role, user_trust_score, sign_in_risk):
    # Load policy configuration data from YAML file
        with open('policyConfiguration.yml', 'r') as file:
            policy_configuration = yaml.safe_load(file)

        # Access specific values from the policy configuration
        admin_threshold = float(policy_configuration['adminThreshold'])
        approver_threshold = float(policy_configuration['approverThreshold'])
        security_viewer_threshold = float(policy_configuration['securityViewerThreshold'])
        sign_in_risk_threshold = float(policy_configuration['signInRiskThreshold'])

        # Initialize verdict
        verdict = 1

        # Determine access decision based on user trust score and role-specific thresholds
        if user_role == 'Approver' and user_trust_score < approver_threshold:
            verdict = 0
        elif user_role == 'Security Viewer' and user_trust_score < security_viewer_threshold:
            verdict = 0
        elif user_role == 'Policy Administrator' and user_trust_score < admin_threshold:
            verdict = 0

        # Determine access decision based on sign-in risk threshold
        if sign_in_risk < sign_in_risk_threshold:
            verdict = 0

        return verdict


    def process_message_from_trust_engine(self, sender, message):
        print(f"Received a message from Trust Engine Node [{sender}]: {message}")
        #if this node is a policy engine then check if the message intent is 'request_access_decision'
        if message.get('intent') == 'request_access_decision':
            user_id = message.get('user_id')
            user_trust_score = message.get('user_trust_score')
            print(f"Received a Request for Access Decision from Trust Engine for User {user_id}")
            print(f"Current Subject's Trust Score: {user_trust_score}")
            print(f"Checking against security policies...")
            print(f"Latest Access Request for the user: {get_latest_access_request(user_id,'access_requests.json')}")
            print(f"Latest Authentication Data for the user: {get_latest_auth_data(user_id,'auth_data.json')}")
            print(f"User Identity Data: {get_user_identity_data_by_id(user_id,'user_data.json')}")

            user_identity_data = get_user_identity_data_by_id(user_id,'user_data.json')
            user_auth_data = get_latest_auth_data(user_id, 'auth_data.json')
            user_access_request = get_latest_access_request(user_id, 'access_requests.json')

            access_request_time_str = user_access_request.get('access_request_time', '')

            # Convert the string time to a datetime object
            access_request_time_str = user_access_request.get('access_request_time', '')

            # Extract time components (hours, minutes, seconds)
            time_components = access_request_time_str.split(' ')[1]

            time_without_year = ':'.join(time_components.split(':')[:-1])  # Extracting HH:MM:SS

             # Retrieving user_role from user_identity_data
            user_role = user_identity_data.get('user_role')

            print(f"User Role: {user_role}")

            # Retrieving sign_in_risk from user_auth_data
            sign_in_risk = user_auth_data.get('sign_in_risk')
            print(f"Sign In Risk: {sign_in_risk}")

            # Retrieving country from location in user_access_request
            location = user_access_request.get('location', '')

            country = location.split('/')[-1]

            print(f"Country: {country}")

            file_path = 'access_decision.json'

            # Check if the file exists to determine the initial ID
            if os.path.exists(file_path):
                with open(file_path, 'r') as file:
                    access_decisions = json.load(file)
                    if access_decisions:
                        last_entry = access_decisions[-1]
                        new_id = last_entry['ID'] + 1
                    else:
                        new_id = 1
            else:
                access_decisions = []
                new_id = 1

            # Call the access decision script /function here to return the verdict
            verdict = self.make_access_decision(user_role,user_trust_score,sign_in_risk)

            print(f"Policy Engine Verdict: {verdict}")
             # Prepare the access decision data
            access_decision_data = {
                'ID': new_id,
                'user_id': user_id,
                'intent': 'request_access_decision',
                'user_trust_score': user_trust_score,
                'access_decision': verdict
            }

            self.send_message_to_node('4',access_decision_data)

            # Append the new access decision data to the existing list
            access_decisions.append(access_decision_data)

            # Write the updated data to the JSON file
            with open(file_path, 'w') as file:
                json.dump(access_decisions, file, indent=4)

    def process_message_from_policy_engine(self, sender, message):
        print(f"Received a message from Policy Engine Node [{sender}]: {message}")

    def process_message_from_web_ui(self, sender, message):
        print(f"Received an Access Request from Web UI [{sender}]: {message}")
        # Check if the 'intent' key has the value 'Access Request'
        if message.get('intent', '').lower() == 'access request':
            #access request received, prepare data to send to Trust Engine(node 2)
            user_id = message.get('user_id')
            intent = 'request_trust_score'

            data = {
                'user_id': user_id,
                'intent': intent
            }
            self.send_message_to_node('2',data)
        else:
            print("The intent is not 'Access Request'")

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
        
