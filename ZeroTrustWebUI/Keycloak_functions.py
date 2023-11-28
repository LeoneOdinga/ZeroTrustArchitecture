'''
This module will contain a higher level implementation of keycloak functions that meets application-specific requirements

'''

from keycloak import KeycloakAdmin
import requests

#function chech if the token is valid
def token_is_valid(oidc,keycloak_openid):
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


def get_user_id_by_email(keycloak_admin,email_address):
    # Call Keycloak Admin API to get user details
    users = keycloak_admin.get_users({"email": email_address})

    # Check if users list is not empty
    if users:
        user_id = users[0]['id']
        return user_id
    else:
        return None  # Return None if no user found
    
#Extract the list of role mappings for the specified user's access token 
def extract_user_role(oidc,keycloak_openid):
    #get the user's current access token
    access_token = oidc.get_access_token()

    # Introspect the access token to ensure it's valid
    introspection_result = keycloak_openid.introspect(access_token)

    #From the access token, return the list of user's roles 
    resource_access = introspection_result.get('resource_access', {}).get('ZeroTrustPlatform', {})
    user_roles = resource_access.get('roles', [])
    return user_roles

def get_client_role_members_emails(keycloak_admin,client_id, role_name):
    # Get client role members
    role_members = keycloak_admin.get_client_role_members(client_id, role_name=role_name)

    # Initialize a list to store email addresses
    email_list = []

    # Iterate through the role members and extract email addresses
    for member in role_members:
        email = member.get('email', 'N/A')
        email_list.append(email)

    return email_list

def get_mac_details(mac_address):
     
    # We will use an API to get the vendor details
    url = "https://api.macvendors.com/"
     
    # Use get method to fetch details
    response = requests.get(url+mac_address)
    if response.status_code != 200:
        raise Exception("[!] Invalid MAC Address!")
    return response.content.decode()

def get_public_ip():
    try:
        # Make an HTTP GET request to retrieve the public IP address
        response = requests.get('https://api.ipify.org')
        
        # Check if the request was successful (status code 200)
        if response.status_code == 200:
            # Extract and return the public IP address from the response
            return response.text
        else:
            print(f"Failed to retrieve public IP. Status code: {response.status_code}")
    except requests.RequestException as e:
        print(f"Request Exception: {e}")
    
    return None  # Return None if unable to retrieve the public IP

def get_location(ip_address):
    response = requests.get(f'https://ipinfo.io/{ip_address}/json/').json()
    location_data = {
        "ip": ip_address,
        "city": response.get("city"),
        "region": response.get("region"),
        "country": response.get("country")
    }
    return location_data



