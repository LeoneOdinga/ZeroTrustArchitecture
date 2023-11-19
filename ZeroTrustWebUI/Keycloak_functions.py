'''
This module will contain a higher level implementation of keycloak functions that meets application-specific requirements

'''

from keycloak import KeycloakAdmin
import requests


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


def get_user_id_by_email(email_address):
    # Call Keycloak Admin API to get user details
    users = KeycloakAdmin.get_users({"email": email_address})

    # Check if users list is not empty
    if users:
        user_id = users[0]['id']
        return user_id
    else:
        return None  # Return None if no user found


