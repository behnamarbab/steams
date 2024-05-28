from Crypto.Cipher import DES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
import os


# RSA key generation for the server (only done once)
def generate_rsa_keys():
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return public_key, private_key

# Load or generate server RSA keys
public_key, private_key = generate_rsa_keys()

# Encrypt DES key with RSA public key
def encrypt_des_key(des_key):
    rsa_key = RSA.import_key(public_key)
    cipher_rsa = PKCS1_OAEP.new(rsa_key)
    encrypted_des_key = cipher_rsa.encrypt(des_key)
    return encrypted_des_key

# Decrypt DES key with RSA private key
def decrypt_des_key(encrypted_des_key):
    rsa_key = RSA.import_key(private_key)
    cipher_rsa = PKCS1_OAEP.new(rsa_key)
    des_key = cipher_rsa.decrypt(encrypted_des_key)
    return des_key

# DES encryption/decryption
def encrypt_message(message, key):
    des = DES.new(key, DES.MODE_ECB)
    padded_message = pad_message(message.encode('utf-8'))
    encrypted_message = des.encrypt(padded_message)
    return encrypted_message

def decrypt_message(encrypted_message, key):
    des = DES.new(key, DES.MODE_ECB)
    decrypted_message = des.decrypt(encrypted_message)
    return unpad_message(decrypted_message).decode('utf-8')

def pad_message(message):
    while len(message) % 8 != 0:
        message += b' '
    return message

def unpad_message(message):
    return message.rstrip(b' ')

# RSA signing
def sign_message(message):
    h = SHA256.new(message)
    signature = pkcs1_15.new(private_key).sign(h)
    return signature

def verify_signature(message, signature):
    h = SHA256.new(message)
    try:
        pkcs1_15.new(public_key).verify(h, signature)
        return True
    except (ValueError, TypeError):
        return False
    
# Generate a new DES key
def generate_des_key():
    return os.urandom(8)
