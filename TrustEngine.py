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

while(True):

    userInput = input("\nType 'exit' to end the Trust engine...")

    if(userInput == 'exit'):
        break

node_2.stop()
