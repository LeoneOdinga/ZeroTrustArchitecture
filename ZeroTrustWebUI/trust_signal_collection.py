'''
This file will have the functions related to collecting trust signals, processing them and storing them in json files 

'''

'''
HANDLING PROCESSING OF AUTH_DATA
'''

import json
import os

def calculate_sign_in_risk(auth_data):
    user_dict = {}
    sign_in_risk = {}
    user_chain = {}

    # Initialize user_chain for each user_id
    for entry in auth_data:
        user_id = entry['user_id']
        user_chain[user_id] = [0]  # Assuming starting sign-in risk

    # Iterate through auth_data to compute sign-in risk for each user_id
    for entry in auth_data:
        user_id = entry['user_id']
        auth_status = entry['auth_status']

        if user_id not in user_dict:
            user_dict[user_id] = {'success_count': 0, 'failure_count': 0}
        
        # Update success or failure count for each user
        if auth_status == 1:
            user_dict[user_id]['success_count'] += 1
        else:
            user_dict[user_id]['failure_count'] += 1

        # Calculate the sign-in risk based on the success and failure counts
        success_count = user_dict[user_id]['success_count']
        failure_count = user_dict[user_id]['failure_count']
        total_count = success_count + failure_count

        if total_count > 0:
            sign_in_risk[user_id] = success_count / total_count

        # Update Markov Chain for each user
        user_chain[user_id].append(sign_in_risk[user_id])

    return user_chain

def predict_sign_in_risk(user_chain, current_sign_in_risk):
    # Predict the next sign-in risk based on the transition probabilities
    predicted_sign_in_risk = {}
    
    for user_id, chain in user_chain.items():
        if len(chain) > 1:
            transition_prob = chain[-1] - chain[-2]  # Difference between last two values
            if user_id in current_sign_in_risk:
                predicted_sign_in_risk[user_id] = current_sign_in_risk[user_id] + transition_prob
            else:
                predicted_sign_in_risk[user_id] = transition_prob  # Assign transition_prob if user_id not found

    return predicted_sign_in_risk

def process_events(events_data):
    cleaned_data = []

    for event in events_data:
        if event['user_id'] is not None:  # Skip entries with null user_id
            cleaned_event = {
                'time': event.get('time', None),
                'type': event.get('type', None),
                'user_id': event.get('user_id', None),
                'ip_address': event.get('ip_address', None),
                'auth_type': event.get('auth_type', None),
                'auth_status': 1 if event.get('type') == 'LOGIN' else 0
            }

            # Skip records not matching criteria
            if cleaned_event['auth_status'] == 0 and event.get('type') != 'LOGIN_ERROR':
                continue

            cleaned_data.append(cleaned_event)

    # Update auth_data with calculated sign-in risk
    auth_data = cleaned_data[:]
    user_chain = calculate_sign_in_risk(auth_data)

    for entry in auth_data:
        user_id = entry['user_id']
        entry['sign_in_risk'] = user_chain[user_id][-1]

    # Predict the next sign-in risk
    current_sign_in_risk = {entry['user_id']: entry['sign_in_risk'] for entry in auth_data if entry['user_id'] is not None}
    predicted_sign_in_risk = predict_sign_in_risk(user_chain, current_sign_in_risk)

    # Blend the predicted and current sign-in risk
    for entry in auth_data:
        user_id = entry['user_id']
        if user_id in predicted_sign_in_risk:
            entry['sign_in_risk'] = (entry['sign_in_risk'] + predicted_sign_in_risk[user_id]) / 2

    # File handling to store events in a JSON file
    file_path = os.path.join(os.path.abspath(os.path.join(os.getcwd(), os.pardir)), 'auth_data.json')

    try:
        existing_data = []
        new_id = 1

        if os.path.exists(file_path):
            with open(file_path, 'r') as file:
                existing_data = json.load(file)
                if existing_data:
                    last_entry = existing_data[-1]
                    new_id = last_entry.get('ID', 0) + 1  # Check if 'ID' exists, otherwise set new_id to 1

        # Filter out events that already exist in the JSON file
        auth_data_to_add = [event for event in auth_data if not any(event['user_id'] == entry.get('user_id') for entry in existing_data)]

        for i, event in enumerate(auth_data_to_add, start=new_id):
            event['ID'] = i
            existing_data.append(event)

        # Write the updated data to the JSON file
        with open(file_path, 'w') as file:
            json.dump(existing_data, file, indent=4)

    except (json.JSONDecodeError, FileNotFoundError) as e:
        print(f"Error occurred while handling the JSON file: {e}")

    except IOError as e:
        print(f"Error occurred while writing JSON data: {e}")


def load_events_data(file_path):
    try:
        with open(file_path, 'r') as file:
            events_data = json.load(file)
        return events_data
    except FileNotFoundError:
        print(f"File '{file_path}' not found.")
        return None
    except json.JSONDecodeError as e:
        print(f"Error decoding JSON file: {e}")
        return None

'''

HANDLING PROCESSING AND STORAGE OF EVENTS DATA

'''

def store_keycloak_events(keycloak_admin):
    query_params = {
        "dateFrom": "2023-01-01",
        "dateTo": "2023-12-31",
        "max": 10000,
    }

    events_data = keycloak_admin.get_events(query=query_params)
    cleaned_data = []

    for event in events_data:
        cleaned_event = {
            'time': event.get('time', None),
            'type': event.get('type', None),
            'user_id': event.get('userId', None),
            'ip_address': event.get('ipAddress', None)
        }

        if 'details' in event:
            details = event['details']
            cleaned_event['auth_type'] = details.get('auth_type', None)
            cleaned_event['token_id'] = details.get('token_id', None)

        cleaned_event['session_id'] = event.get('sessionId', None)

        cleaned_data.append(cleaned_event)

    file_path = os.path.join(os.path.abspath(os.path.join(os.getcwd(), os.pardir)), 'events.json')

    try:
        existing_data = []
        new_id = 1

        if os.path.exists(file_path):
            with open(file_path, 'r') as file:
                existing_data = json.load(file)
                if existing_data:
                    last_entry = existing_data[-1]
                    new_id = last_entry['ID'] + 1

        for i, event in enumerate(cleaned_data, start=new_id):
            event_exists = False
            for existing_event in existing_data:
                if event['time'] == existing_event['time'] and event['user_id'] == existing_event['user_id']:
                    event_exists = True
                    break

            if not event_exists:
                event['ID'] = i
                existing_data.append(event)

        with open(file_path, 'w') as file:
            json.dump(existing_data, file, indent=4)

    except (json.JSONDecodeError, FileNotFoundError) as e:
        print(f"Error occurred while handling the JSON file: {e}")

    except IOError as e:
        print(f"Error occurred while writing JSON data: {e}")

#get the latest access request data for a particular user_id

def get_latest_access_request(user_id, access_requests):
    with open(access_requests, 'r') as file:
        data = json.load(file)

    latest_request = None
    for request in data:
        if request['user_id'] == user_id:
            if latest_request is None or request['access_request_time'] > latest_request['access_request_time']:
                latest_request = request

    return latest_request

#get the latest auth data for the particular user_id
def get_latest_auth_data(user_id, auth_data):
    with open(auth_data, 'r') as file:
        data = json.load(file)

    latest_data = None
    for entry in data:
        if entry['user_id'] == user_id:
            if latest_data is None or entry['time'] > latest_data['time']:
                latest_data = entry

    return latest_data

#get user identity information
def get_user_identity_data_by_id(user_id, user_data_file):
    with open(user_data_file, 'r') as file:
        user_data = json.load(file)

    for user in user_data:
        if user['user_id'] == user_id:
            return user

    return None  # Return None if user_id not found