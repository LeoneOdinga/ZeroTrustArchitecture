import sys

sys.path.insert(0, '..') # Import the files where the modules are located

from Networking import Networking

#Create an instance of this node
node_2 = Networking("127.0.0.1", 8002, 2)

#Start the node2
node_2.start()

debug = False

node_2.debug = debug

#Connect with node 1
node_2.connect_with_node('127.0.0.1', 8003)
node_2.connect_with_node('127.0.0.1',8001)

#Start a loop to keep sending messages between node 1 and node 2
while(True):

    userInput = input("\nSend a Message to  Node 1 and node 3: ")

    if(userInput == 'exit'):
        break
    
    else:
        node_2.send_message_to_node('1',userInput)
        node_2.send_message_to_node('3',userInput)

node_2.stop()
