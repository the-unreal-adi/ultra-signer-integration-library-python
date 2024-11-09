import binascii
from PyKCS11 import PyKCS11, Mechanism

# Initialize PKCS#11 library
pkcs11 = PyKCS11.PyKCS11Lib()
pkcs11.load("eps2003csp11v264.dll")

# Open a session on the first available slot
slots = pkcs11.getSlotList()
session = pkcs11.openSession(slots[0])

# Login if necessary
session.login('12345678')

# Find the public key object
public_key = session.findObjects([(PyKCS11.CKA_CLASS, PyKCS11.CKO_PUBLIC_KEY)])[0]

# Extract the public key attributes
pub_key_attributes = session.getAttributeValue(public_key, [
    PyKCS11.CKA_MODULUS,      # For RSA keys
    PyKCS11.CKA_PUBLIC_EXPONENT
])

# Convert attributes to bytes
modulus = bytes(pub_key_attributes[0])
exponent = bytes(pub_key_attributes[1])

# Construct the public key in DER format
from Crypto.PublicKey import RSA
rsa_key = RSA.construct((int.from_bytes(modulus, 'big'), int.from_bytes(exponent, 'big')))
der_pub_key = rsa_key.exportKey(format='DER')

# Convert DER to PEM
from base64 import b64encode
pem_pub_key = b"-----BEGIN PUBLIC KEY-----\n" + \
    b64encode(der_pub_key) + b"\n-----END PUBLIC KEY-----\n"

# Save the public key to a file
with open('pubkey.pem', 'wb') as f:
    f.write(pem_pub_key)

# Logout and close the session
session.logout()
session.closeSession()
