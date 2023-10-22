from flask import Flask,render_template, request, jsonify

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
    return jsonify({'message': 'Data receivved successfully'})

if __name__ == "__main__":
    app.run(debug=True)




