#THis file contains the constants for the keycloak configurations

# keycloak_config.py

KEYCLOAK_SERVER_URL = "http://localhost:8080/auth"
KEYCLOAK_REALM = "myrealm"
KEYCLOAK_CLIENT_ID = "ZeroTrustPlatform"
KEYCLOAK_CLIENT_SECRET = "bzf9bctfGor9tB2rOfLdQnK3VNDxt6rx"
KEYCLOAK_ADMIN_CLIENT_SECRET = "e6y3FaNFjz8gj8ZDXpA6X9AtZXBejggZ"

SERVER_URL = f"{KEYCLOAK_SERVER_URL}/realms/{KEYCLOAK_REALM}/.well-known/openid-configuration"
API_BASE_URL = f"{KEYCLOAK_SERVER_URL}/realms/{KEYCLOAK_REALM}/protocol/openid-connect"
AUTHORIZATION_URL = f"{API_BASE_URL}/auth"
REGISTRATION_URL = f"{API_BASE_URL}/registrations"
TOKEN_URL = f"{API_BASE_URL}/token"
REVOCATION_URL = f"{API_BASE_URL}/logout"