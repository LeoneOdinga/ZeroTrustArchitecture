import sys
from flask import Flask,render_template, request, jsonify, session, url_for,redirect

import json
import logging

from flask import Flask, g
from flask_oidc import OpenIDConnect

from Networking import Networking

sys.path.insert(0,'..')


logging.basicConfig(level=logging.DEBUG)

app = Flask(__name__)

app.config.update({
    'SECRET_KEY': 'ii768hDPrWVKPpQpw6uIl69y9Xfz6WSG',
    'TESTING': True,
    'DEBUG': True,
    'OIDC_CLIENT_SECRETS': 'client_secrets.json',
    'OIDC_ID_TOKEN_COOKIE_SECURE': False,
    'OIDC_USER_INFO_ENABLED': True,
    'OIDC_OPENID_REALM': 'myrealm',
    'OIDC_SCOPES': ['openid', 'email', 'profile'],
    'OIDC_INTROSPECTION_AUTH_METHOD': 'client_secret_post'
})

oidc = OpenIDConnect(app)

@app.route('/')
def index():
    if oidc.user_loggedin:
        return redirect(url_for('home'))
    return render_template('index.html')

# Logout route
@app.route('/logout')
def logout():
    # Revoke the access token with Keycloak
    if oidc.user_loggedin:
        user_info = oidc.user_getinfo(['sub'])
        user_id = user_info.get('sub')
        access_token = oidc.get_access_token()
        if access_token:
            # Revoke the access token using Keycloak's logout endpoint
            revoke_endpoint = f'http://localhost:8080/auth/realms/myrealm/protocol/openid-connect/logout'
            request.get(revoke_endpoint, params={'client_id': 'myclient', 'refresh_token': access_token})
        
        # Logout the user from the Flask session
        session.pop('username', None)
        session.pop('access_token', None)
        oidc.logout()

    # Redirect to the home route after logout
    return redirect(url_for('home'))

@app.route('/home')
@oidc.require_login
def home():
    if 'oidc_auth_profile' in session:
        auth_profile = session['oidc_auth_profile']
        username = auth_profile.get('preferred_username')
        email = auth_profile.get('email')
        user_id = auth_profile.get('sub')

        # Extract user profile details
        given_name = auth_profile.get('given_name')
        family_name = auth_profile.get('family_name')

        access_token = oidc.get_access_token()  # Get the access token directly

        # Print out the extracted details
        print(f"Username: {username}")
        print(f"Email: {email}")
        print(f"Subject ID: {user_id}")
        print(f"First Name: {given_name}")
        print(f"Second Name: {family_name}")
        print(f"Access Token: {access_token}")

        if access_token:
            return render_template('home.html', username=username, email=email, user_id=user_id)
        else:
            return "<h1>NOT AUTHORIZED!</h1>"

    return "<h1>NOT AUTHORIZED!</h1>"

#route to receive an access request and forward it to the AP | Testing...

@app.route('/receive-access-request', methods = ['POST'])
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

    # Communicate to the frontend that the access request has been received
    response_data = {'message': 'Data received successfully', 'status': 'received'}
    return jsonify(response_data)

@app.route('/resource-selection')
@oidc.require_login
def resource_selection():
    if 'oidc_auth_profile' in session:
        auth_profile = session['oidc_auth_profile']
        username = auth_profile.get('preferred_username')
        email = auth_profile.get('email')
        user_id = auth_profile.get('sub')

        # Extract user profile details
        given_name = auth_profile.get('given_name')
        family_name = auth_profile.get('family_name')

    return render_template('resourceSelection.html',user_id=user_id,username=username,given_name=given_name)

if __name__ == "__main__":
    app.run(debug=True)




