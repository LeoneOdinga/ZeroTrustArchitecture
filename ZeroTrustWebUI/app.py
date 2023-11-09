import json
import sys
from flask import Flask,render_template, request, jsonify, session, url_for,redirect, make_response
import logging
import tss,base64
import math

from flask import Flask, g
from flask_oidc import OpenIDConnect
from keycloak import KeycloakAuthenticationError, KeycloakOpenID
import time
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
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

from keycloak import KeycloakAdmin
from keycloak import KeycloakOpenIDConnection

keycloak_connection = KeycloakOpenIDConnection(
                        server_url="http://localhost:8080/auth/",
                        username='admin',
                        password='admin',
                        realm_name="myrealm",
                        user_realm_name="master",
                        client_id="admin-cli",
                        client_secret_key="Gd0BL0xq5BS4Tqd8Mu9qpYpc3fRvl9eY",
                        verify=False)

keycloak_admin = KeycloakAdmin(connection=keycloak_connection)

oidc = OpenIDConnect(app)

# Configure client using the python-kyecloak library
keycloak_openid = KeycloakOpenID(server_url="http://localhost:8080/auth/",
                                 client_id="ZeroTrustPlatform",
                                 realm_name="myrealm",
                                 client_secret_key="KEViiP0yTFDgjfxKee2Xg1hgaCDHAEqU")

# Configuration for SQLAlchemy
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///privileged_access.db' 
db = SQLAlchemy(app)

# Define the database model for access requests
class AccessRequest(db.Model):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    resource_name = db.Column(db.String(100), nullable=False)
    reason_for_access = db.Column(db.String(250), nullable=False)
    access_duration = db.Column(db.Integer, nullable=False)
    requestor_id = db.Column(db.String(100), nullable=False)
    requestor_username = db.Column(db.String(100), nullable=False)
    time_of_request = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    requestStatus = db.Column(db.String(20), default="pending")


# Create a new database model for approvers
class Approver(db.Model):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    approverID = db.Column(db.String(100), nullable=False)
    approverEmail = db.Column(db.String(100), nullable=False)
    request_id = db.Column(db.Integer, db.ForeignKey('access_request.id'), nullable=False)
    approver_secret_share = db.Column(db.String(750))

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

#function chech if the token is valid
def token_is_valid():
    #get the current access token from the oidc
    access_token = oidc.get_access_token()
    #introspect the token to make sure that it is valid
    introspection_result = keycloak_openid.introspect(access_token)

    if introspection_result.get("active"):
        return True
    else:
        return False

# create a function to revoke an access token and check if the revocation was a success
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

#function to generate shares from a secret key and return a list of shares
def generate_secret_shares(threshold,num_shares,secret_key,identifier):
    shares = tss.share_secret(threshold, num_shares, secret_key, identifier, tss.Hash.SHA256)
    # Encode shares in Base64
    base64_shares = [base64.b64encode(share).decode() for share in shares]

    return base64_shares

#function to construct shares from a secret key
def generate_and_reconstruct_secret(threshold, num_shares, secret, identifier):
    # Generate shares
    shares = tss.share_secret(threshold, num_shares, secret, identifier, tss.Hash.SHA256)

    # Encode shares in Base64
    base64_shares = [base64.b64encode(share).decode() for share in shares]


    print(base64_shares)

    # Reconstruct the secret from Base64-encoded shares
    binary_shares = [base64.b64decode(share.encode()) for share in base64_shares]

    try:
        # Recover the secret value
        reconstructed_secret = tss.reconstruct_secret(binary_shares)
        return reconstructed_secret
    except tss.TSSError:
        return None  # Handling error
    
def get_user_id_by_email(email_address):
    # Call Keycloak Admin API to get user details
    users = keycloak_admin.get_users({"email": email_address})

    # Check if users list is not empty
    if users:
        user_id = users[0]['id']
        return user_id
    else:
        return None  # Return None if no user found

def get_client_role_members_emails(client_id, role_name):
    # Get client role members
    role_members = keycloak_admin.get_client_role_members(client_id, role_name=role_name)

    # Initialize a list to store email addresses
    email_list = []

    # Iterate through the role members and extract email addresses
    for member in role_members:
        email = member.get('email', 'N/A')
        email_list.append(email)

    return email_list

# The home route where all the available services are located
@app.route('/home')
def home():
    try:
        if oidc.user_loggedin:
            access_token = oidc.get_access_token()

            # Introspect the access token to ensure it's valid
            introspection_result = keycloak_openid.introspect(access_token)

            print(f"\nINTROSPECTION RESULTS: {introspection_result}")

            userinfo = keycloak_openid.userinfo(access_token)

            #testing extraction of userID from email address using keycloak admin

            emailAddress = "userDemo1@leotech.cns"

            print(f"User ID: {get_user_id_by_email(emailAddress)}")

            encoded_base64_data = [
    "c2stYXBwcgAAAAAAAAAAAAICAFEBf9xEr7H0a1VDoA0AvlJbeVb4EwIt9YO/gOY/nGEKEhbNqePl20yUMUlBsh8wC6iMnf7sqdxnoKmi1EyZDcL4sfaZ2PMM2Zs9rpCMd5HHoQk=",
    "c2stYXBwcgAAAAAAAAAAAAICAFECYgwd2cJBf18p/oyv+3kZeTBEs5jhQ7TwtHLojF6pi6cd5khNFiqa9z0n6ZH8q+SI0ZryYKIofSxvx5m+uNnsCWFGnaocs+l5yepkwa+seq0=",
    "c2stYXBwcgAAAAAAAAAAAAICAFEDabUqAhrbc1kPPfPKMWAneRLZ0+6l2FA8UfeldUvI/MikKtjcpAhptREFKeu4yyl9HE/4J4jkNqbdPyOjItDgYeX6V53llcdFHTU8Wkx8Mzg="
]           
            print(encoded_base64_data)
                    # Reconstruct the secret from Base64-encoded shares
            binary_shares = [base64.b64decode(share.encode()) for share in encoded_base64_data]

            try:
                # Recover the secret value
                reconstructed_secret = tss.reconstruct_secret(binary_shares)
                return reconstructed_secret
            except tss.TSSError:
                return None  # Handling error


            print(generate_secret_shares(3,4,"testing","sk2"))

            #dynamically query the keycloak API for the list of approvers to diaplay for the requestor
            client_id = keycloak_admin.get_client_id("ZeroTrustPlatform")
            role_name = "Policy Administrator"
            email_addresses = get_client_role_members_emails(client_id, role_name)

            print(f"Email Addresses for policy administrators{email_addresses}")

            print(keycloak_admin.get_client_id("ZeroTrustPlatform"))

            #testing how to get the client role members 

            role = "Policy Administrator"
            client_id = keycloak_admin.get_client_id("ZeroTrustPlatform")

            print("PRINT OUT THE MEMBERS BELONGING TO THE SAME ROLE...")

            print(get_client_role_members_emails(client_id,role))

            print(f"\n{userinfo}")

            # Decode Token
            KEYCLOAK_PUBLIC_KEY = "-----BEGIN PUBLIC KEY-----\n" + keycloak_openid.public_key() + "\n-----END PUBLIC KEY-----"
            options = {"verify_signature": True, "verify_aud": False, "verify_exp": True}
            token_info = keycloak_openid.decode_token(access_token, key=KEYCLOAK_PUBLIC_KEY, options=options)

            print(f"\nDECODED TOKEN{token_info}")

            if token_is_valid():
                if 'oidc_auth_profile' in session:
                    auth_profile = session['oidc_auth_profile']
                    username = auth_profile.get('name')
                    email = auth_profile.get('email')
                    user_id = auth_profile.get('sub')
                    #get the user role
                    user_roles = extract_user_role()
                    user_role = user_roles[0]
                    return render_template('home.html', username=username, email=email, user_id=user_id, user_role=user_role)
                else:
                    return "<h1>NOT AUTHORIZED!</h1>"
            else:
                return "<h1>UNAUTHORIZED [INVALID ACCESS TOKEN]!!!</h1>"
        else:
            return redirect(url_for('login'))
    except KeycloakAuthenticationError as e:
        print(f"KeycloakAuthenticationError: {e}")
        return redirect(url_for('index'))

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

from datetime import datetime  # Import the datetime module

@app.route('/privilegedAccess', methods=['GET', 'POST'])
def privilegedAccess():
    #dynamically query the keycloak API for the list of approvers to diaplay for the requestor
    client_id = keycloak_admin.get_client_id("ZeroTrustPlatform")
    role_name = "Policy Administrator"
    email_addresses = get_client_role_members_emails(client_id, role_name)

    #Outline the sharing of secret shares and the threshold percentage to be met

    num_shares = len(email_addresses) #equal to the number of approvers 

    threshold = math.floor(num_shares * 0.8) #define at least 80 % of threshold to be met before secret key reconstruction occurs

    secret_key_identifier = "sk-appr"

    testing_secret = "testingSecretKeytestingsecretkeytestingsecretkey" # for testing purposes. Ideally, the secret key would be generated by the resource requested for

    secret_shares_list = generate_secret_shares(2,num_shares,testing_secret,secret_key_identifier)

    print(f"LIST OF GENERATED SECRET SHARES: {secret_shares_list}")

    if email_addresses is None:
        # Handle the case where email_addresses could not be retrieved
        email_addresses = []

    if request.method == 'POST':
        # Get form data
        resource_name = request.form['resource_name']
        reason_for_access = request.form['reason_for_access']
        access_duration = int(request.form['access_duration'])
        # Get the current user's ID and username from the session
        requestor_id = session['oidc_auth_profile'].get('sub')
        requestor_username = session['oidc_auth_profile'].get('preferred_username')
        # Capture the time of the request
        time_of_request = datetime.now()

        # Extract selected approvers in a list
        selected_approvers = request.form.getlist('approvers')

        # Validate the access duration (between 1 and 100 minutes)
        if 1 <= access_duration <= 100:
            # Create a new access request and add it to the database

            print("Selected Approvers:", selected_approvers)

            new_request = AccessRequest(
                resource_name=resource_name,
                reason_for_access=reason_for_access,
                access_duration=access_duration,
                requestor_id=requestor_id,
                requestor_username=requestor_username,
                time_of_request=time_of_request,
                requestStatus='pending',  # Set the requestStatus to 'pending'
            )

            db.session.add(new_request)
            db.session.commit()

             # Insert approver details
            for index, approver_email in enumerate(selected_approvers):
                approver_secret_share = secret_shares_list[index]  # Get the corresponding secret share
                approver = Approver(
                    approverID=get_user_id_by_email(approver_email),
                    approverEmail=approver_email,
                    request_id=new_request.id,
                    approver_secret_share=approver_secret_share  # Assign the secret share to each approverID
                )
                db.session.add(approver)
                db.session.commit()

            return render_template('success.html', message="Successfully received your request! Processing...")
        else:
            return "Invalid access duration. Please enter a value between 1 and 100 minutes."

    return render_template('privilegedAccessManagement.html',email_addresses=email_addresses)

# Define a variable to store the generated secret
generated_secret = "TEST"

@app.route('/processSecretKey', methods=['GET', 'POST'])
def process_secret_key():
    global generated_secret

    if request.method == 'POST':
        # Get the secret key entered by the user
        entered_secret_key = request.form.get('secret_key')

        if generated_secret is not None and entered_secret_key == generated_secret:
            # Redirect to the hidden page if the secret key matches
            return redirect(url_for('hidden_page'))
        else:
            # If the secret key doesn't match, display an error message
            return "Error: Invalid secret key"

    return render_template('enterKey.html')

@app.route('/viewAccessRequests')
def view_access_requests():
    access_requests = AccessRequest.query.all()
    approvers = Approver.query.all()
    requestor_id = session['oidc_auth_profile'].get('sub')
    print(requestor_id)

    return render_template('viewAccessRequests.html', access_requests=access_requests, approvers = approvers)
if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True)




