from datetime import datetime
import os
from .trust_signal_collection import get_latest_access_request, get_latest_auth_data, get_user_identity_data_by_id
# Function to calculate User Identity Score
def calculate_user_identity_score(identity_data):
    email_verified_score = 0.0
    totp_enabled_score = 0.0
    user_role_score = 0.0
    
    # Calculate scores based on email_verified, totp_enabled, and user_role
    if identity_data['email_verified']:
        email_verified_score = 0.8  # Higher score for verified email
    if identity_data['totp_enabled']:
        totp_enabled_score = 1.0  # Higher score for TOTP enabled

    if identity_data['user_role'] == 'Policy Administrator':
        user_role_score = 0.9
    elif identity_data['user_role'] == 'Approver':
        user_role_score = 0.7
    else:
        user_role_score = 0.5

    # Assign weights to attributes
    weight_email_verified = 0.4
    weight_totp_enabled = 0.4
    weight_user_role = 0.2

    # Calculate weighted score for user identity
    user_identity_score = (email_verified_score * weight_email_verified) + \
                         (totp_enabled_score * weight_totp_enabled) + \
                         (user_role_score * weight_user_role)
    return user_identity_score

# Function to calculate Authentication Data Score
def calculate_authentication_data_score(authentication_data):
    sign_in_risk = authentication_data['sign_in_risk']
    auth_type_score = 0.0
    
    # Consider sign_in_risk and auth_type
    if sign_in_risk >= 0.9:
        sign_in_risk_score = 0.9  # Higher risk increases the score
    elif sign_in_risk >=0.7 and sign_in_risk < 0.9:
        sign_in_risk_score = 0.75
    elif sign_in_risk >=0.5 and sign_in_risk < 0.7:
        sign_in_risk_score = 0.5
    else:
        sign_in_risk_score = 0.3

    # Evaluate auth_type and assign scores
    if authentication_data['auth_type'] == 'code':
        auth_type_score = 0.7
    else:
        auth_type_score = 0.5

    # Assign weights to attributes
    weight_sign_in_risk = 0.6
    weight_auth_type = 0.4

    # Calculate weighted score for authentication data
    authentication_data_score = (sign_in_risk_score * weight_sign_in_risk) + \
                                (auth_type_score * weight_auth_type)
    return authentication_data_score

# Function to calculate Experience Score
def calculate_experience_score(created_timestamp):
    # Get the current timestamp in milliseconds (assuming it's in milliseconds)
    current_timestamp = datetime.now().timestamp() * 1000

    # Calculate tenure in milliseconds by finding the difference between current time and user's creation time
    tenure_ms = current_timestamp - created_timestamp

    # Convert tenure from milliseconds to months
    tenure_months = tenure_ms / (1000 * 60 * 60 * 24 * 30)  # Assuming 30 days in a month

    # Define thresholds for experience (in months)
    threshold_1 = 1 
    threshold_2 = 0.15  

    # Assign scores based on tenure
    if tenure_months >= threshold_2:
        experience_score = 0.8  # Higher experience score
    elif tenure_months >= threshold_1:
        experience_score = 0.6  # Moderate experience score
    else:
        experience_score = 0.4  # Lower experience score

    return experience_score

#print(calculate_experience_score(created_timestamp=user_info['created_timestamp']))

#function to calculate the subject's score based on the access request and contextual information  such as location 
# Function to assign trust scores based on access request data for the user_id
def calculate_access_request_score(access_request_data, night_start='00:00:00', night_end='06:00:00',high_risk_locations=None, medium_risk_locations=None, low_risk_locations=None):
    location_score = 0.0
    access_time_score = 0.0
    device_os_score = 0.0
    device_type_score = 0.0
    
   # Evaluate location, access request time, device_os, and device_type
    location_risk = access_request_data['location'] 
    if high_risk_locations and location_risk in high_risk_locations:
        location_score = 0.15
    elif medium_risk_locations and location_risk in medium_risk_locations:
        location_score = 0.4
    elif low_risk_locations and location_risk in low_risk_locations:
        location_score = 0.7
    else:
        location_score = 0.5  # Assign a default score for locations not specified

    # Assess access request time
    access_time = datetime.strptime(access_request_data['access_request_time'], '%Y-%m-%d %H:%M:%S')
    
    # Check if the access time falls within the specified night time boundaries
    night_start_time = datetime.strptime(night_start, '%H:%M:%S').time()
    night_end_time = datetime.strptime(night_end, '%H:%M:%S').time()
    
    if night_start_time <= access_time.time() <= night_end_time:
        access_time_score = 0.6  
    else:
        access_time_score = 0.8

    # Evaluate device_os and device_type
    device_os = access_request_data['device_OS']
    if 'Linux' in device_os:
        device_os_score = 0.5
    else:
        device_os_score = 0.8
    
    device_type = access_request_data['device_type']
    if device_type == 'Mobile':
        device_type_score = 0.5
    else:
        device_type_score = 0.8

    # Assign weights to attributes
    weight_location = 0.3
    weight_access_time = 0.2
    weight_device_os = 0.25
    weight_device_type = 0.25

    # Calculate weighted score for access request
    access_request_score = (location_score * weight_location) + \
                           (access_time_score * weight_access_time) + \
                           (device_os_score * weight_device_os) + \
                           (device_type_score * weight_device_type)
    return access_request_score

# Function to calculate Overall Trust Score
def calculate_overall_trust_score(user_id):
    #user_data_file_path = os.path.join(os.path.abspath(os.path.join(os.getcwd(), os.pardir)), 'user_data.json')
    #access_request_data_file_path = os.path.join(os.path.abspath(os.path.join(os.getcwd(), os.pardir)), 'access_requests.json')
    #auth_data_file_path = os.path.join(os.path.abspath(os.path.join(os.getcwd(), os.pardir)), 'auth_data.json')
    
    # Get user data using provided functions
    identity_data = get_user_identity_data_by_id(user_id,'user_data.json')
    access_request_data = get_latest_access_request(user_id, 'access_requests.json')
    authentication_data = get_latest_auth_data(user_id, 'auth_data.json')

    # Calculate scores for each segment
    user_identity_score = calculate_user_identity_score(identity_data)
    access_request_score = calculate_access_request_score(access_request_data)
    authentication_data_score = calculate_authentication_data_score(authentication_data)
    experience_score = calculate_experience_score(identity_data['created_timestamp'])

    # Apply different weights to each segment
    weight_user_identity = 0.3
    weight_access_request = 0.2
    weight_authentication_data = 0.25
    weight_experience = 0.25

    # Calculate overall trust score based on weighted segments
    overall_trust_score = (user_identity_score * weight_user_identity) + \
                          (access_request_score * weight_access_request) + \
                          (authentication_data_score * weight_authentication_data) + \
                          (experience_score * weight_experience)

    return overall_trust_score