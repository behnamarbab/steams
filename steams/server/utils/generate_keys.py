import os
import rsa

from Crypto.PublicKey import RSA

def generate_rsa_key_pair():
    key = RSA.generate(2048)
    private_key = key.export_key().decode('utf-8')
    public_key = key.publickey().export_key().decode('utf-8')
    return private_key, public_key

# Define file paths for the keys
private_key_path = "private_key.pem"
public_key_path = "public_key.pem"

# Check if keys already exist
if not os.path.exists(private_key_path) or not os.path.exists(public_key_path):
    # Generate RSA keys
    (public_key, private_key) = rsa.newkeys(2048)

    # Save the public key
    with open(public_key_path, "wb") as f:
        f.write(public_key.save_pkcs1())

    # Save the private key
    with open(private_key_path, "wb") as f:
        f.write(private_key.save_pkcs1())

    print("RSA key pair generated and saved.")
else:
    print("RSA key pair already exists.")
