import sys
from flask import Flask,render_template, request, jsonify

from Networking import Networking

sys.path.insert(0,'..')

app = Flask(__name__)

@app.route('/')
def index():
    return render_template('index.html', message = "ZT Home Page!")

@app.route('/home')
def home():
    return render_template('home.html')

#route to receive an access request and forward it to the AP | Testing...

@app.route('/receive-request', methods = ['POST'])
def receive_and_process_access_request():
    #receive the data from the front end when the option1 is clicked. 
    data = request.json
    print("Received data:", data)

    #try to send the data to the AP in the peer to peer network of nodes ... Testing

    #first create an instance of the Networking class
    node4 = Networking("127.0.0.1",8004,4)
    node4.start()
    node4.connect_with_node('127.0.0.1',8001)
    node4.send_message_to_node('1',data)

    #Then disconnect from the AP gracefully

    node4.stop()

    return jsonify({'message': 'Data receivved successfully'})

@app.route('/resource-selection')
def resource_selection():
    return render_template('resourceSelection.html')

if __name__ == "__main__":
    app.run(debug=True)




