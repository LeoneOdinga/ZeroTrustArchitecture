import sys
import time
sys.path.insert(0, '..') # Import the files where the modules are located

from Networking import Networking

node_2 = Networking("127.0.0.2", 8002, 2)

node_2.start()
<<<<<<< HEAD

time.sleep(15)

=======
time.sleep(10)
>>>>>>> 211b6fde86928bd5315d16ed783858aafd53f9b8
debug = False

node_2.connect_with_node('127.0.0.1', 8001)

node_2.debug = debug

while(True):
    userInput = input("Send a Message to  Node 1")
    node_2.send_message_to_node('1',userInput)

<<<<<<< HEAD
time.sleep(20)
=======
    if(userInput == 'exit'):
        break
time.sleep(10)
>>>>>>> 211b6fde86928bd5315d16ed783858aafd53f9b8

node_2.stop()

print('end test')
