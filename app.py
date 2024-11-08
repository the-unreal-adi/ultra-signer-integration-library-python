from hashlib import sha256
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
import requests
import secrets
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
import binascii

# Base URL of your Flask API
BASE_URL = "http://127.0.0.1:8080"

def list_tokens():
    """
    Call the /list-tokens endpoint to retrieve available tokens.
    """
    try:
        response = requests.get(f"{BASE_URL}/list-tokens")
        response.raise_for_status()
        tokens = response.json()
        return tokens
    except requests.RequestException as e:
        print(f"Error listing tokens: {e}")
        return None

def register_token(tokens, nonce):
    """
    Call the /register_token endpoint with the provided certificate and nonce,
    and verify the returned signature.
    """
    # Step 1: Prepare the payload and send the request
    try:
        payload = {
            "certificate": tokens.get("certficate"),
            "nonce": nonce
        }
        response = requests.post(f"{BASE_URL}/register_token", json=payload)
        response.raise_for_status()
        
        # Extract the response JSON containing the signature and timestamp
        result = response.json()
        signature_hex = result.get("signature")
        timestamp = result.get("timestamp")

        if not signature_hex or not timestamp:
            print("Invalid response: Missing signature or timestamp.")
            return False
    except requests.RequestException as e:
        print(f"Error registering token: {e}")
        return False

    # Step 2: Verify the returned signature
    public_key_hex = tokens.get("public_key")
    if not public_key_hex:
        print("Public key not found in tokens.")
        return False

    try:
        # Convert hex-encoded DER public key to bytes and load it
        public_key_bytes = bytes.fromhex(public_key_hex)
        public_key = serialization.load_der_public_key(public_key_bytes, backend=default_backend())
    except ValueError as e:
        print(f"Error loading public key: {e}")
        return False

    # Recreate the combined data that was signed (nonce + owner name + timestamp)
    owner_name = tokens.get("owner_name")
    combined_data = nonce + owner_name + timestamp
    hash_value = sha256(combined_data.encode()).digest()
    
    # Decode the received signature from hex
    signature = bytes.fromhex(signature_hex)
    
    try:
        # Verify the signature using RSA-PKCS1 v1.5 padding with SHA-256
        public_key.verify(
            signature,
            hash_value,
            None,
            hashes.SHA256()
        )
        print("Signature verified successfully.")
        return True
    except Exception as e:
        print(f"Signature verification failed: {e}")
        return False

def main():
    # Step 1: List tokens and get available certificates
    print("Fetching available tokens from /list-tokens...")
    tokens = list_tokens()
    if not tokens:
        print("Failed to retrieve tokens.")
        return

    # Display tokens and let the user select one
    print("\nAvailable Tokens:")
    print(tokens)
    certificate_hex = tokens.get("certficate")
    if not certificate_hex:
        print("No certificates found.")
        return

    print(f"Selected Certificate: {certificate_hex}")

    # Step 2: Generate a random nonce for registration
    nonce = secrets.token_hex(16)  # 16-byte hex nonce
    print(f"Generated Nonce: {nonce}")

    # Step 3: Register the token using the selected certificate and nonce
    print("Registering token with /register_token...")
    result = register_token(tokens, nonce)

    # Display the response from /register_token
    if result:
        print("\nRegistration Result:")
    else:
        print("Registration failed.")

if __name__ == "__main__":
    main()
