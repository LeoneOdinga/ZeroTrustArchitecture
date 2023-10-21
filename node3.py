import sys

sys.path.insert(0, '..') # Import the files where the modules are located

from Networking import Networking

#Create an instance of this node
node_3 = Networking("127.0.0.1", 8003, 3)

#Start the node
node_3.start()
node_3.connect_with_node('127.0.0.1',8002)
node_3.connect_with_node('127.0.0.1', 8001)
debug = False

node_3.debug = debug

#Start a loop to keep sending messages between node 1 and node 2
while(True):

    userInput = input("\nSend a Message to  Node 1: ")

    if(userInput == 'exit'):
        break
    
    else:
        node_3.send_message_to_node('1',userInput)
        node_3.send_message_to_node('2',userInput)

node_3.stop()
