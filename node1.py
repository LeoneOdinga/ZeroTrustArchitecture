import sys

sys.path.insert(0, '..') # Import the files where the modules are located

from Networking import Networking

#Create an instance of this node
node_1 = Networking("127.0.0.1", 8001, 1)

#Start the node
node_1.start()

debug = False

node_1.debug =debug

#Connect with node 2
node_1.connect_with_node('127.0.0.1', 8002)
node_1.connect_with_node('127.0.0.1',8003)

try:
    #Start a loop to keep sending messages between node 1 and node 2
    while(True):

        userInput = input("\nSend a Message to  Node 2 and node 3: ")

        if(userInput == 'exit'):
            break

        else:
            node_1.send_message_to_node('2',userInput)
            node_1.send_message_to_node('3',userInput)

except KeyboardInterrupt:
    print("\nKeyboard interrupt received. Exiting...")

finally:
    node_1.stop()
