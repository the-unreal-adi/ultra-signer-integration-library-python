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
DATA = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

# Signature in hexadecimal format
SIGNATURE_HEX = (
    "5E3497ED575550967A570EAAE1E31B421A0D94907FEC9187E88672E5B4F32E2DCCF065448F90D73844BB8C5545DA65A6FDDD41D44A182C5A02F62CE74391C502BAC96A6D1E2C94B27BB0FF89FDECF767E6CCDE61534D2BFF65703595B156AAC27A68330BCE3E129BC16B6D9D9024735D69B13BF91A251CC7BB231F942F6A2F584DDC8FEA861916956406F55F6B89E738B5BC8168391787C0D8040283A34EE59D9430BECA04BCCF95D25C6F65C316E7061277579FF14BB04EE32B4C1317D06B946F23DEAF4695B70ACD631485857AC876CA4A73D0F8DECB0BDD1D73862BF3D06E176E8BB0C2CC8C34FE4B1E494ACFD28AC497B3AFC032BAF55AA92887E22B18D8"
)

TS = "2025-06-29T09:54:09.5882460Z"


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


# Main execution
if __name__ == "__main__":
    status=verify_signature(
        PUBLIC_KEY_DER_HEX,
        SIGNATURE_HEX,
        DATA,
        TS
    )
    if status:
        print("Signature is valid.")
    else:
        print("Signature is invalid.")
