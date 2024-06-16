# chat.py
from Crypto.Cipher import DES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA1
from Crypto.Signature import pkcs1_15
from server.models import Chat, ChatUser
import base64
import os

def get_or_create_chat(users):
    print("------- Creating a chat?!")
    if len(users) == 2:
        user1, user2 = users
        print("I have both users", user1, user2)
        chats = Chat.objects.filter(is_group_chat=False).filter(chatuser__user=user1).filter(chatuser__user=user2)
        if chats.exists():
            return chats.first()
    chat = Chat.objects.create(is_group_chat=False)
    for user in users:
        ChatUser.objects.create(user=user, chat=chat)
    return chat

def generate_des_key():
    return os.urandom(8)  # Generates a random 8-byte key for DES

def encrypt_message(des_key, plaintext):
    des = DES.new(des_key, DES.MODE_ECB)
    padded_text = plaintext.ljust(8 * ((len(plaintext) + 7) // 8))  # Padding to ensure it's a multiple of 8
    return des.encrypt(padded_text)

def decrypt_message(des_key, ciphertext):
    des = DES.new(des_key, DES.MODE_ECB)
    return des.decrypt(ciphertext).strip()

def sign_message(private_key_str, message):
    private_key = RSA.import_key(private_key_str)
    hash = SHA1.new(message)
    return pkcs1_15.new(private_key).sign(hash)

def verify_signature(public_key_str, message, signature):
    public_key = RSA.import_key(public_key_str)
    hash = SHA1.new(message)
    try:
        pkcs1_15.new(public_key).verify(hash, signature)
        return True
    except (ValueError, TypeError):
        return False

def rsa_encrypt(public_key_str, des_key):
    public_key = RSA.import_key(public_key_str)
    cipher_rsa = PKCS1_OAEP.new(public_key)
    encrypted_des_key = cipher_rsa.encrypt(des_key)
    return encrypted_des_key

def rsa_decrypt(private_key_str, encrypted_des_key):
    private_key = RSA.import_key(private_key_str)
    cipher_rsa = PKCS1_OAEP.new(private_key)
    decrypted_des_key = cipher_rsa.decrypt(encrypted_des_key)
    return decrypted_des_key
