import random

class User:
    def __init__(self, user_id):
        self.user_id = user_id
        self.trust_score = 0
        self.history = []

    def update_trust_score(self, new_score):
        self.trust_score = new_score

    def add_history(self, data):
        self.history.append(data)

    def get_latest_history(self):
        return self.history[-1] if self.history else None

class ZeroTrustAlgorithm:
    def __init__(self):
        self.weights = {
            "authentication_rate": 0.3,
            "access_frequency": 0.2,
            "policy_violation_count": -0.1,
        }
        self.transition_matrices = {
            "Low": {"Low": 0.5, "Medium": 0.4, "High": 0.1},
            "Medium": {"Low": 0.2, "Medium": 0.6, "High": 0.2},
            "High": {"Low": 0.1, "Medium": 0.3, "High": 0.6}
        }

    def calculate_trust_score(self, data):
        trust_score = sum(data.get(key, 0) * self.weights.get(key, 0) for key in data)
        return trust_score

    def adjust_score_based_on_geolocation(self, data):
        location = data.get("location")
        if location in ["New York", "London", "Tokyo"]:  # Example high-risk locations
            return -0.5  # Reduce trust score for high-risk locations
        elif location in ["San Francisco", "Sydney", "Berlin"]:  # Example low-risk locations
            return 0.2  # Increase trust score for low-risk locations
        else:
            return 0  # No adjustment for other locations

    def generate_transition_matrix(self, trust_score, auth_rate):
        transition_matrix = self.transition_matrices.copy()

        if trust_score < 0.3:
            for state in transition_matrix:
                for next_state in transition_matrix[state]:
                    transition_matrix[state][next_state] += 0.1

        if auth_rate < 0.5:
            for state in transition_matrix:
                for next_state in transition_matrix[state]:
                    transition_matrix[state][next_state] += 0.2

        return transition_matrix

    def transition_trust_score(self, current_state, transition_matrix):
        return random.choices(
            list(transition_matrix[current_state].keys()),
            weights=transition_matrix[current_state].values()
        )[0]

    def run_simulation(self, access_data):
        user = User(access_data['user_id'])

        trust_score = self.calculate_trust_score(access_data)
        geo_adjustment = self.adjust_score_based_on_geolocation(access_data)
        trust_score += geo_adjustment
        
        user.update_trust_score(trust_score)
        user.add_history(access_data)

        transition_matrix = self.generate_transition_matrix(trust_score, access_data["authentication_rate"])
        next_state = self.transition_trust_score("Low", transition_matrix)

        return user, next_state

# Sample data (can be dynamically updated in a real-time scenario)
access_data = {
    "user_id": "john_doe",
    "resource_requested": "sensitive_data",
    "time": "2023-11-21 10:30:00",
    "user_agent": "Chrome",
    "os": "Windows",
    "device_type": "Laptop",
    "ip_address": "192.168.1.1",
    "location": "New York",
    "device_mac": "00:1A:2B:3C:4D:5E",
    "device_vendor": "VendorX",
    "authentication_rate": 0.9,
    "access_frequency": 5,
    "policy_violation_count": 0,
    "user_role": "employee"
}

# Run the simulation
algorithm = ZeroTrustAlgorithm()
user, next_state = algorithm.run_simulation(access_data)

print(f"User ID: {user.user_id}")
print(f"Initial Trust Score: {user.trust_score}")
print(f"Next Trust Score State: {next_state}")
print(f"Latest History: {user.get_latest_history()}")
