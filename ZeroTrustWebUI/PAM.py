import secrets
import string
import tss
import base64

class PAM:
    @staticmethod
    def generate_secret_shares(threshold, num_shares, secret_key, identifier):
        shares = tss.share_secret(threshold, num_shares, secret_key, identifier, tss.Hash.SHA256)
        # Encode shares in Base64
        base64_shares = [base64.b64encode(share).decode() for share in shares]
        return base64_shares

    @staticmethod
    def generate_and_reconstruct_secret(threshold, num_shares, secret, identifier):
        shares = tss.share_secret(threshold, num_shares, secret, identifier, tss.Hash.SHA256)
        # Encode shares in Base64
        base64_shares = [base64.b64encode(share).decode() for share in shares]

        # Reconstruct the secret from Base64-encoded shares
        binary_shares = [base64.b64decode(share.encode()) for share in base64_shares]

        try:
            # Recover the secret value
            reconstructed_secret = tss.reconstruct_secret(binary_shares)
            return reconstructed_secret
        except tss.TSSError:
            return None  # Handling error

    @staticmethod
    def reconstruct_secret_from_base64_shares(base64_shares):
        # Reconstruct the secret from Base64-encoded shares
        binary_shares = [base64.b64decode(share.encode()) for share in base64_shares]

        try:
            # Recover the secret value
            reconstructed_secret = tss.reconstruct_secret(binary_shares)
            return reconstructed_secret
        except tss.TSSError:
            return None  # Handling error
        
    @staticmethod
    def generate_secret_message(length=20):
        alphabet = string.ascii_letters + string.digits  # Only letters and digits
        secret_message = ''.join(secrets.choice(alphabet) for _ in range(length))
        return secret_message
    

