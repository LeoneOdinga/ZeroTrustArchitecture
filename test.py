#######################################################################################################################
# Author: Maurice Snoeren                                                                                             #
# Version: 0.1 beta (use at your own risk)                                                                            #
#                                                                                                                     #
# This example show how to derive a own Node class (MyOwnPeer2PeerNode) from p2pnet.Node to implement your own Node   #
# implementation. See the MyOwnPeer2PeerNode.py for all the details. In that class all your own application specific  #
# details are coded.                                                                                                  #
#######################################################################################################################

import sys
import time
sys.path.insert(0, '..') # Import the files where the modules are located

from Networking import Networking

node_1 = Networking("127.0.0.1", 8001,1)
node_2 = Networking("127.0.0.1", 8002,2)
node_3 = Networking("127.0.0.1", 8003,3)

time.sleep(1)

node_1.start()
node_2.start()
node_3.start()

time.sleep(1)

node_1.connect_with_node('127.0.0.1', 8002)
node_2.connect_with_node('127.0.0.1', 8003)
node_3.connect_with_node('127.0.0.1', 8001)

time.sleep(2)

node_1.send_to_nodes({ "name" : "Maurice", "number" : 11 })
node_2.send_message_to_node('3',"Hello from node 2")

time.sleep(5)

node_1.stop()
node_2.stop()
node_3.stop()
print('end test')