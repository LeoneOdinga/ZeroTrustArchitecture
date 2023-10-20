import sys
import time
sys.path.insert(0, '..') # Import the files where the modules are located

from Networking import Networking

node_1 = Networking("127.0.0.1", 8001, 1)

time.sleep(1)

node_1.start()

time.sleep(5)

debug = True

node_1.connect_with_node('127.0.0.2', 8002)
node_1.debug =debug

time.sleep(1)
node_1.print_all_nodes()

time.sleep(1)
node_1.send_message_to_node('2',{'Name':'leone'})

time.sleep(10)
node_1.stop()

print('end test')
