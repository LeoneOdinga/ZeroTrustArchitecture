import sys

sys.path.insert(0, '..') # Import the files where the modules are located

from Networking import Networking

#Create an instance of this node
node_1 = Networking("127.0.0.1", 8001, 1)

#Start the node
node_1.start()

debug = False

node_1.debug =debug

#Connect with node 4
node_1.connect_with_node('127.0.0.1',8004)