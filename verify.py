import hashlib
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
import binascii

# Public key in DER format (hexadecimal)
PUBLIC_KEY_DER_HEX = (
    "30820122300d06092a864886f70d01010105000382010f003082010a02820101009a5f273b913292f10381be4d2a1e3a88cb24575b5d9c7792b7ff07d7e92e720c3ef139c4a830e3114799a3b1959838bd9a13b673df04e9f98699d5d4628662256209ac734f6d4870ef8473e2089fd3a4633f999c72397b060fd031d682f698ba4c6f4bf8393621422a2ce91aad21375d0b2fcd03ed9b4ddb5731011c50bb5a9fea2c3755bf07f1d6e53e76b337ddeb51228fa443bc6f09ffddca4cb0db8a751699e93688449c98d57ddaf2c5742dd8a2b085c8ed93f8cf1b7d45342168e028876a2e3be580b7af7840283250289f0e728b24bbc1cbd4f64ee6dcfac4dbff48c084df13aaa9fdc775b77c73734d63249010928160a296364539b94e7fe86470bf0203010001"
)

# Data to verify
DATA = "Sweet! This is a test message to verify the signature."

# Signature in hexadecimal format
SIGNATURE_HEX = (
    "7799115A68FA8E11FC346CF60227E2BF391532F5BA380AA26ADF5D1E26E3C67A65D75F09117D3A2ED90BBDB0E0AF944D8A50D88E4478FFDCA3E98136ACC38CF55A1E25D827220621C39EE7219C69170635B9D90BFF20ADF704FE2FBAD165520C54A80B846287429461D4AD69B0F3A9537F94F68A5F47AEDEA67CDAE921788E1DBD2C2E6440CE61C0E9ABB1AE6099EA176B19BEBB109342F8547854EB2773B677E2F42658F1D5A2CB3FD873C0AA2BC021DBDE327B7ACAFA33EA3AAFFCB5079F011788595CAC5EAF8C2614A64CAECAD0171B9EE85C5B36C34A35B3DCCA1ACD1328F073DB86B60E4C55A9FE37319AC09F3FE5F9956ECCE345212494E85314377E68"
)

TS = "2025-06-29T11:25:05.0960217Z"


def load_public_key_from_der_hex(der_hex):
    """
    Load a public key from DER format (hexadecimal string).
    """
    public_key_der = binascii.unhexlify(der_hex)
    return serialization.load_der_public_key(public_key_der, backend=default_backend())


def verify_signature(public_key, signature, digest_hex, timestamp):
    """
    Verify a digital signature using RSA-PKCS#1 v1.5 and SHA-256.
    """
    try:
        if not all([public_key, signature, digest_hex, timestamp]):
            raise ValueError("Insufficient verification data")
    
        try:
            # Convert hex-encoded DER public key to bytes and load it
            public_key_der = binascii.unhexlify(public_key)
            public_key_final = serialization.load_der_public_key(public_key_der, backend=default_backend())
        except ValueError as e:
            raise

        # Recreate the combined data that was signed
        combined_data = '|'.join([digest_hex, timestamp]).encode('utf-8')

        # Decode the received signature from hex
        signature_final = binascii.unhexlify(signature)

        try:
            # Verify the signature using RSA-PKCS1 v1.5 padding with SHA-256
            public_key_final.verify(
                signature_final,
                combined_data,  # Hash of the data
                padding=padding.PKCS1v15(),  # PKCS#1 v1.5 padding
                algorithm=hashes.SHA256()  # Explicitly specify the hash algorithm
            )  
            return True
        except Exception as e:
            raise Exception("Signature verification failed.") 
    except Exception as e:
        print(f"Error: {e}")
        return False

def create_sha512_digest(components):
    """
    Create a SHA-256 digest from a list of components.
    """
    try:
        if not components:
            raise ValueError("Empty digest component")
        
        if not isinstance(components, list):
            raise TypeError("Components must be a list.")
        
        combined_data = '|'.join(components).encode('utf-8')
        
        hash_object = hashlib.sha512(combined_data)
        digest = hash_object.hexdigest()
        return digest
    except Exception as e:
        print(f"Error: {e}")
        return None

# Main execution
if __name__ == "__main__":
    digest = create_sha512_digest([DATA])
    print(f"Digest: {digest}")
    status=verify_signature(
        PUBLIC_KEY_DER_HEX,
        SIGNATURE_HEX,
        digest,
        TS
    )
    if status:
        print("Signature is valid.")
    else:
        print("Signature is invalid.")
