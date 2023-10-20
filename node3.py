import sys
import time
sys.path.insert(0, '..') # Import the files where the modules are located

from Networking import Networking

node_3 = Networking("127.0.0.1", 8003, 3)

time.sleep(1)

node_3.start()

time.sleep(15)

debug = False

node_3.connect_with_node('127.0.0.2', 8002)
node_3.connect_with_node('127.0.0.1',8001)
node_3.print_connections()

time.sleep(2)

node_3.send_to_nodes("Hi there from node 3 to node 1")
node_3.print_all_nodes()

time.sleep(1)
node_3.send_message_to_node(1,"hweeeeeeeeeeeeeey")
time.sleep(20)
node_3.stop()

print('end test')
