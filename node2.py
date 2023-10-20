import sys
import time
sys.path.insert(0, '..') # Import the files where the modules are located

from Networking import Networking

node_2 = Networking("127.0.0.2", 8002, 2)

node_2.start()
time.sleep(10)
debug = False

node_2.connect_with_node('127.0.0.1', 8001)

node_2.debug = debug

while(True):
    userInput = input("Send a Message to  Node 1")
    node_2.send_message_to_node('1',userInput)

    if(userInput == 'exit'):
        break
time.sleep(10)

node_2.stop()

print('end test')
