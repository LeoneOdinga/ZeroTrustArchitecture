import sys
import time
sys.path.insert(0, '..') # Import the files where the modules are located

from Networking import Networking

node_1 = Networking("127.0.0.1", 8001, 1)

node_1.start()

<<<<<<< HEAD
time.sleep(5)
=======
time.sleep(10)
>>>>>>> 211b6fde86928bd5315d16ed783858aafd53f9b8

debug = False

node_1.connect_with_node('127.0.0.2', 8002)
<<<<<<< HEAD
node_1.print_connections()

time.sleep(1)

while(True):
    userInput = input("Send a Message to  Node 2")
    node_1.send_message_to_node('2',userInput)

time.sleep(1)
node_1.send_message_to_node('2',"hweeeeeeeeeeeeeey")  

node_1.stop()
=======
node_1.debug =debug

node_1.send_message_to_node('2',{'Name':'leone'})
>>>>>>> 211b6fde86928bd5315d16ed783858aafd53f9b8
