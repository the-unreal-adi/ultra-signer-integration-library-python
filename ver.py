from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
import binascii

# Public key in DER format (hexadecimal)
PUBLIC_KEY_DER_HEX = (
    "30820122300d06092a864886f70d01010105000382010f003082010a0282010100e3e22a2bb61397445dfebfa718c50a3ca1098e0e76d7a7bda97eed799df7cf5e59b9f693c614efae4d5ba7406c926ada743d368c81c79237466c49d30a44827d642061af8efddecc62187d66371e3ceb458cc9b04d43d5c040994e3085b93e8640c9241b6e740804afb3bf36f4790c58571ecd10e77408751124723fc63e9a133a04229c457d2e663fbcd6bc18780332820dea78373dcfd769af6edaf0e5dcca1bdb256104c555b82386f3104028636b3fa269be5811e2b56c95e2bac0a1b5b6858cef711846ea0ddd7a24c716eaf8c5e370149522f839abd4d09fcfe8f227b565dce920f5416da4916258d309f15a553444188da2a0af802e308daa9b8785930203010001"
)

# Data to verify
data = b"ilovepython"

# Signature in hexadecimal format
SIGNATURE_HEX = (
    "ae726f61a595d8ce08e127b2e2f2da44a3130c30dcf61fc8cb1bbac01c821cc544e688cb5dbb61b82c0f64271e2a5ca39b16d6b62c8bc9f99d1dd8ca86668bb973a9aea1eb005fd42f7329abde65a6e63a67253599980ada38099481eb4d6ccece6a1ae3095be5c93962ef876a68c3347bfd58c8353ea247b41916e1db78f6d22e76f2847b541777dcc52f3181aeec4ae9aabe639555fca638727339e5742bfc7d72fbbd35a9321ef2fb3ad861eb4ddad2f1eb4a337040429036ce43c09600fb67e2021020586e0764a000e2ad8282f31c6042b11c7415ec6797a9e02d6ba5c39f0df67d64b1037853ff3e4bf27fc760ed84ad5b8d2531bbc377a91da2d0613c"
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
            digest,  # Hash of the data
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
