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
data = b"ilovepython"

# Signature in hexadecimal format
SIGNATURE_HEX = (
    "6d9f3e29c4e7ed9925dfd614dd66c717322945d9355d9631b1594d41f15cb31c645aa5fd8f667258fdca015873a983c1311b2e07c4fcab1cd3c8774b2883b71506cf76bf07e8bd3a7765661b46313a58eaf3d73ea1b40270337d0652bd1327a0d93541621924f117804143c8a93d5bc07b66ec9d134cbdbb9cc1f4b310f8b4bfc9ba0eb9356c0d2fbbb8872358eeed90338c2d72db94e9b2b4419beb51c74aa6cd5bffa607c30616df8a4ab096cf5015fb7bf72fa5d59b00b587e848ed38bcaee2c5183aa68a6f1cd60eaa276cb221c7746fa17fd5ee74f022555a3a2347dbccbd75d463c340d6144b2c2894e6d79f5da6df2c99a8ad0b18a27db32b16067c0d"
)


def load_public_key_from_der_hex(der_hex):
    """
    Load a public key from DER format (hexadecimal string).
    """
    public_key_der = binascii.unhexlify(der_hex)
    return serialization.load_der_public_key(public_key_der, backend=default_backend())


def verify_raw_rsa_signature(public_key, data, signature):
    """
    Verify an RSA signature with no padding (raw RSA operation).
    """
    try:
        # Compute the hash of the original data
        hash_obj = hashes.Hash(hashes.SHA256(), backend=default_backend())
        hash_obj.update(data)
        digest = hash_obj.finalize()

        # Log the hash (digest) and signature
        print("Hash (digest):", digest.hex())
        print("Signature (decoded):", signature.hex())

        # Perform raw RSA verification
        public_key.verify(
            signature,
            data,  # Hash of the data
            padding=padding.PKCS1v15(),  # PKCS#1 v1.5 padding
            algorithm=hashes.SHA256()  # Explicitly specify the hash algorithm
        )
        print("Signature is valid.")
    except Exception as e:
        print(f"Signature verification failed: {e}")


# Main execution
if __name__ == "__main__":
    # Load the public key from DER hexadecimal
    public_key = load_public_key_from_der_hex(PUBLIC_KEY_DER_HEX)

    # Decode the signature from hex
    signature = binascii.unhexlify(SIGNATURE_HEX)

    # Verify the signature
    verify_raw_rsa_signature(public_key, data, signature)
