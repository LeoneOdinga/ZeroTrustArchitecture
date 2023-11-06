import sys
from flask import Flask,render_template, request, jsonify, session, url_for,redirect, make_response
import logging

from flask import Flask, g
from flask_oidc import OpenIDConnect
from keycloak import KeycloakOpenID
import time

import requests
from Networking import Networking

sys.path.insert(0,'..')

logging.basicConfig(level=logging.DEBUG)

app = Flask(__name__)

'''
This section below contains the configuration of the flask OIDC and the keycloak OIDC
as well as constants

'''

app.config['OIDC_SESSION_TYPE'] = 'null'

app.config.update({
    'SECRET_KEY': 'KEViiP0yTFDgjfxKee2Xg1hgaCDHAEqU',
    'TESTING': True,
    'DEBUG': True,
    'OIDC_CLIENT_SECRETS': 'client_secrets.json',
    'OIDC_ID_TOKEN_COOKIE_SECURE': False,
    'OIDC_USER_INFO_ENABLED': True,
    'OIDC_OPENID_REALM': 'myrealm',
    'OIDC_SCOPES': ['openid', 'email', 'profile'],
    'OIDC_TOKEN_TYPE_HINT': 'access_token',
    'OIDC_INTROSPECTION_AUTH_METHOD': 'client_secret_post'
})

KEYCLOAK_SERVER_URL = "http://localhost:8080/auth"
KEYCLOAK_REALM = "myrealm"
KEYCLOAK_CLIENT_ID = "ZeroTrustPlatform"
KEYCLOAK_CLIENT_SECRET = "KEViiP0yTFDgjfxKee2Xg1hgaCDHAEqU"

SERVER_URL = f"{KEYCLOAK_SERVER_URL}/realms/{KEYCLOAK_REALM}/.well-known/openid-configuration"
API_BASE_URL = f"{KEYCLOAK_SERVER_URL}/realms/{KEYCLOAK_REALM}/protocol/openid-connect"
AUTHORIZATION_URL = f"{API_BASE_URL}/auth"
REGISTRATION_URL = f"{API_BASE_URL}/registrations"
TOKEN_URL = f"{API_BASE_URL}/token"
REVOCATION_URL = f"{API_BASE_URL}/logout"

oidc = OpenIDConnect(app)

# Configure client using the python-kyecloak library
keycloak_openid = KeycloakOpenID(server_url="http://localhost:8080/auth/",
                                 client_id="ZeroTrustPlatform",
                                 realm_name="myrealm",
                                 client_secret_key="KEViiP0yTFDgjfxKee2Xg1hgaCDHAEqU")

'''

The section below contains the system views. They contain the various routes in the web UI and the functionalities
that can be performed at each view

'''
#Main route
@app.route('/')
@oidc.require_login
def index():
    if oidc.user_loggedin and token_is_valid():
        return redirect(url_for('home'))
    else:
        return render_template('index.html')
    

#create a route to revoke an access token and redirect to index.html page for the user to authenticate
@app.route('/revokeToken')
@oidc.require_login
def revokeToken():
    refresh_token = oidc.get_refresh_token()
    if revoke_token(KEYCLOAK_CLIENT_ID,KEYCLOAK_CLIENT_SECRET,refresh_token, REVOCATION_URL):
        print("Revoked the access token")
        #redirect the user to the index.html page
        return render_template('index.html')
    else:
        return "<h1>Failed to revoke the access token!<h1>"
    
#Login Route
@app.route('/login')
@oidc.require_login
def login():
    token = oidc.get_access_token()
    response = make_response(redirect(url_for('home')))
    if token_is_valid:
        response.set_cookie('access_token', token['access_token'])
        session['access_token'] = token['access_token']  
        return response
    else:
        return render_template('index.html')

#function check if the token in valid
def token_is_valid():
    #get the current access token from the oidc
    access_token = oidc.get_access_token()
    #introspect the token to make sure that it is valid
    introspection_result = keycloak_openid.introspect(access_token)

    if introspection_result.get("active"):
        return True
    else:
        return False

# create a function to revoke an access token
def revoke_token(client_id, client_secret, refresh_token, revocation_url):
    data = {
        "client_id": client_id,
        "client_secret": client_secret,
        "refresh_token": refresh_token
    }

    response = requests.post(revocation_url, data=data)

    if response.status_code == 204:
        return True  # Token revocation was successful
    else:
        return False  # Token revocation failed

#Extract the list of role mappings for the specified user's access token 
def extract_user_role():
    #get the user's current access token
    access_token = oidc.get_access_token()

    # Introspect the access token to ensure it's valid
    introspection_result = keycloak_openid.introspect(access_token)

    #From the access token, return the list of user's roles 
    resource_access = introspection_result.get('resource_access', {}).get('ZeroTrustPlatform', {})
    user_roles = resource_access.get('roles', [])
    return user_roles

# The home route where all the available services are located
@app.route('/home')
@oidc.require_login
def home():
    if oidc.user_loggedin:
        access_token = oidc.get_access_token()

        # Introspect the access token to ensure it's valid
        introspection_result = keycloak_openid.introspect(access_token)

        print(f"\nINTROSPECTION RESULTS: {introspection_result}")

        userinfo = keycloak_openid.userinfo(access_token)

        print(f"\n{userinfo}")

        # Decode Token
        KEYCLOAK_PUBLIC_KEY = "-----BEGIN PUBLIC KEY-----\n" + keycloak_openid.public_key() + "\n-----END PUBLIC KEY-----"
        options = {"verify_signature": True, "verify_aud": False, "verify_exp": True}
        token_info = keycloak_openid.decode_token(access_token, key=KEYCLOAK_PUBLIC_KEY, options=options)

        print(f"\nDECODED TOKEN{token_info}")

        if token_is_valid():
            # The token is valid, and you can proceed to access protected resources
            if 'oidc_auth_profile' in session:
                auth_profile = session['oidc_auth_profile']
                username = auth_profile.get('name')
                email = auth_profile.get('email')
                user_id = auth_profile.get('sub')
                return render_template('home.html', username=username, email=email, user_id=user_id)
            else:
                return "<h1>NOT AUTHORIZED!</h1>"
            #the token is invalid
        else:
            return "<h1>UNAUTHORIZED[INVALID ACCESS TOKEN]!!!</h1>"
    else:
        return redirect(url_for('login'))

#route to receive an access request and forward it to the AP
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




