import ZeroTrustWebUI.TrustAlgorithm as ta
from ZeroTrustWebUI.trust_signal_collection import *
# Calculate overall trust score for a specific user_id
user_id = '768df141-8bd3-454a-b85c-761c2ed072f3'
trust_score = ta.calculate_overall_trust_score(user_id)
print(f"Overall Trust Score for user ID {user_id}: {trust_score}")