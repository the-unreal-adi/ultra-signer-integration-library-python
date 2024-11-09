from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
import binascii

# Public key in DER format (hexadecimal)
PUBLIC_KEY_DER_HEX = (
    "30820122300d06092a864886f70d01010105000382010f003082010a0282010100e3e22a2bb61397445dfebfa718c50a3ca1098e0e76d7a7bda97eed799df7cf5e59b9f693c614efae4d5ba7406c926ada743d368c81c79237466c49d30a44827d642061af8efddecc62187d66371e3ceb458cc9b04d43d5c040994e3085b93e8640c9241b6e740804afb3bf36f4790c58571ecd10e77408751124723fc63e9a133a04229c457d2e663fbcd6bc18780332820dea78373dcfd769af6edaf0e5dcca1bdb256104c555b82386f3104028636b3fa269be5811e2b56c95e2bac0a1b5b6858cef711846ea0ddd7a24c716eaf8c5e370149522f839abd4d09fcfe8f227b565dce920f5416da4916258d309f15a553444188da2a0af802e308daa9b8785930203010001"
)

# Decode the DER-encoded public key
try:
    public_key_der = binascii.unhexlify(PUBLIC_KEY_DER_HEX)
    public_key = serialization.load_der_public_key(public_key_der, backend=default_backend())
    print("Public Key is valid.")
except ValueError as e:
    print(f"Failed to load public key: {e}")

# Get public key numbers
public_numbers = public_key.public_numbers()
modulus = public_numbers.n
exponent = public_numbers.e

print("Modulus (n):", modulus)
print("Exponent (e):", exponent)
