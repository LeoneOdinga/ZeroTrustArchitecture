import sys

sys.path.insert(0, '..') # Import the files where the modules are located

from Networking import Networking

#Create an instance of this node
node_2 = Networking("127.0.0.2", 8002, 2)

#Start the node
node_2.start()

debug = False

#Connect with node 2
node_2.connect_with_node('127.0.0.2', 8002)

#Start a loop to keep sending messages between node 1 and node 2
while(True):

    userInput = input("Send a Message to  Node 2: ")
    node_2.send_message_to_node('2',userInput)

    if(userInput == 'exit'):
        break

node_2.stop()
