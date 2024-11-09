import os
from cryptography.hazmat.primitives import hashes
from PyKCS11 import *

# Path to your PKCS#11 library
PKCS11_LIB_PATH = "eps2003csp11v264.dll"  # Replace with your PKCS#11 library path

# Data to be signed
data = b"ilovepython"
data2 = b"iloveupython"
# Step 1: Compute the hash of the data
def compute_hash(data, algorithm=hashes.SHA256):
    hash_obj = hashes.Hash(algorithm(), backend=None)
    hash_obj.update(data)
    return hash_obj.finalize()

digest = compute_hash(data)
digest2 = compute_hash(data2)

pkcs11 = PyKCS11Lib()
pkcs11.load(PKCS11_LIB_PATH)

# Open session and login
slot = pkcs11.getSlotList(tokenPresent=True)[0]
session = pkcs11.openSession(slot)
session.login("12345678")  # Replace with your token PIN

certs = session.findObjects([(PyKCS11.LowLevel.CKA_CLASS, PyKCS11.LowLevel.CKO_CERTIFICATE)])
if not certs:
    raise ValueError("No certificate found on the DSC token")
    
cert_der = bytes(session.getAttributeValue(certs[0], [PyKCS11.LowLevel.CKA_VALUE], True)[0])

# Find the private key
priv_keys = session.findObjects([(PyKCS11.LowLevel.CKA_CLASS, PyKCS11.LowLevel.CKO_PRIVATE_KEY)])
if not priv_keys:
    raise ValueError("No private key found on the DSC token")
priv_key = priv_keys[0]

# Perform raw RSA signing
signature = bytes(session.sign(priv_key, digest, PyKCS11.MechanismRSAPKCS1))

pub_keys = session.findObjects([(PyKCS11.LowLevel.CKA_CLASS, PyKCS11.LowLevel.CKO_PUBLIC_KEY)])
if not pub_keys:
    raise ValueError("No public found on the DSC token")
pub_key = pub_keys[0]

result=session.verify(pub_key,digest,signature,PyKCS11.MechanismRSAPKCS1)

print("Digest",digest.hex())
print("Certificate: ", cert_der.hex())
print("Signature (hex): ", signature.hex())
print("Verified",result)

# Logout and close session
session.logout()
session.closeSession()
