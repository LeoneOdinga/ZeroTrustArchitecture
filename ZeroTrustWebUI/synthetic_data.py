import json
import random
import string
from datetime import datetime, timedelta

# Sample user IDs
user_ids = ['user123', 'user456', 'user789', 'user101', 'user202']

# Generate sample transaction types
transaction_types = ['Top-Up', 'Transfer', 'Bill Payment', 'Withdrawal']

# Generate sample transactions
transactions = []
for i in range(45):  # Generate 45 transactions
    transaction = {
        "transaction_id": f"txn_{i + 1}",
        "user_id": random.choice(user_ids),
        "amount": round(random.uniform(10, 500), 2),
        "transaction_type": random.choice(transaction_types),
        "timestamp": (datetime.now() - timedelta(days=random.randint(1, 365))).strftime("%Y-%m-%d %H:%M:%S")
    }
    transactions.append(transaction)

# Save transactions to a JSON file
with open('mobile_money_transactions.json', 'w') as file:
    json.dump(transactions, file, indent=4)
