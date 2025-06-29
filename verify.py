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
    "1D0A09DB6A9FAC480A3B8464FD9F813435E59C392601A38C379B335ABC5D87447E5835ED0B67818052C2E9FCEE0EA477E51C95FC8205AC6E3AC8D1FC5CB66B832BAB8FF7786AB98C2D00CCCFAC2E2C6DE7675AD197B78DB69C1F354B83CFC10EF0D8EA85CA5724672C747D4E3B24A254F9ACD5976C785A0E4524F798A3B6E8DBB24301D165EC1E909FBBE7120B22361216E691D19211250ECC4CD3C4040FB2F8C3FA92A5F6CA7B9CAFB5E8CE7A4007A16C3AA78E4EEB9295E659765CD655A065F894D599132FA9C9B591340FC29C4EF34D85BF6F4375AFE2928A480640D902704B729BF770976294670763AFC8CA609F2668CDE696B034759652F7A7626E05A7"
)

TS = "2025-06-29T11:15:43.9496537Z"


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
                algorithm=hashes.SHA512()  # Explicitly specify the hash algorithm
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
