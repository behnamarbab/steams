# consumers.py
import json
import rsa
import base64
import logging

from channels.generic.websocket import AsyncWebsocketConsumer
from channels.db import database_sync_to_async
from .models import Chat, Message
from .utils.chat import generate_des_key, encrypt_message, sign_message, rsa_encrypt
from .utils.generate_keys import generate_rsa_key_pair
from django.contrib.auth import get_user_model
from Crypto.Cipher import DES
from Crypto.Hash import SHA1

logger = logging.getLogger(__name__)
User = get_user_model()

class ChatConsumer(AsyncWebsocketConsumer):
    async def connect(self):
        logger.info('---------- Connect ws')
        self.chat_id = self.scope['url_route']['kwargs']['chat_id']
        self.room_group_name = f'chat_{self.chat_id}'

        await self.channel_layer.group_add(
            self.room_group_name,
            self.channel_name
        )

        await self.accept()
        print(f"WebSocket connection established: {self.chat_id}")

    async def disconnect(self, close_code):
        logger.info("--------- DC ws")
        await self.channel_layer.group_discard(
            self.room_group_name,
            self.channel_name
        )
        print(f"WebSocket connection closed: {self.chat_id}")

    async def receive(self, text_data):
        """ 
            The text_data includes:
                [encrypted_message, signature_on_message, encrypted_DesKey_A]
            An encrypted message is received (from A to S):
                encrypted_message = E_pubS(DES_A(msg))
                As it is encrypted using the server's public key, it can be stored into the database right away.
                
                TODO: In case of RSA Key Versions, store the key VERSION as well.
                NOTE: SERVER HAS the USER's PUBLIC KEYS
        """
        logger.info("RECEIVED a message!")
        text_data_json = json.loads(text_data)
        encrypted_message = text_data_json['message']
        encrypted_deskey = text_data_json['encrypted_des_key']
        
        sender = self.scope['user']
        timestamp = text_data_json["timestamp"]
        
        # TODO: Retrieve Sender's Public Key
        # TODO: Check the digital signature of the sender
            # ! Message Digest is the 48bit hash of XOR of plaintext blocks of the message.

        recipient_username = text_data_json['recipient']
        recipient = await self.get_user_by_username(recipient_username)
        if not recipient:
            await self.send(text_data=json.dumps({'error': 'Recipient not found'}))
            return

        # ! These info must be acquired/updated by the user. Private key shouldn't be there
        # NOTE: Public keys are gathered when user registers
        if not sender.rsa_private_key or not sender.rsa_public_key:
            logger.info("Public/Private keys were not found!!!!!!!!!!!")
            private_key, public_key = generate_rsa_key_pair()
            await self.update_user_keys(sender, private_key, public_key)
        else:
            logger.info(f"Public/Private keys: {sender.rsa_private_key} - {sender.rsa_public_key}")

        if not recipient.rsa_private_key or not recipient.rsa_public_key:
            private_key, public_key = generate_rsa_key_pair()
            await self.update_user_keys(recipient, private_key, public_key)

        # des_key = generate_des_key()
        # encrypted_message = encrypt_message(des_key, message.encode())
        # encrypted_des_key = rsa_encrypt(recipient.rsa_public_key, des_key)
        # message_hash = SHA1.new(message.encode()).digest()
        signature = sign_message(sender.rsa_private_key, message_hash)

        # TODO: Store the DES_ENCRYPTED message into DB
        await self.save_message(sender.id, recipient.id, encrypted_message, encrypted_des_key)
        
        # TODO: Send the message to the receiver
        await self.channel_layer.group_send(
            self.room_group_name,
            {
                'type': 'chat_message',
                'message': message,
                'sender': sender.username,
                'timestamp': timestamp
            }
        )

    @database_sync_to_async
    def get_user_by_username(self, username):
        try:
            return User.objects.get(username=username)
        except User.DoesNotExist:
            return None

    @database_sync_to_async
    def update_user_keys(self, user, private_key, public_key):
        user.rsa_private_key = private_key
        user.rsa_public_key = public_key
        user.save()

    @database_sync_to_async
    def save_message(self, sender_id, recipient_id, message, encrypted_des_key):
        logger.info(f"Trying to save message for {sender_id} and {recipient_id}")
        sender = User.objects.get(id=sender_id)
        recipient = User.objects.get(id=recipient_id)
        chat = Chat.objects.get(id=self.chat_id)
        Message.objects.create(
            chat=chat,
            sender=sender,
            recipient=recipient,
            encrypted_message=message,
            encrypted_des_key=encrypted_des_key
        )

    def decrypt_des_key(self, encrypted_des_key):
        logger.info("Trying to DES_DECRYPT the KEY")
        with open("private_key.pem", "rb") as key_file:
            private_key = rsa.PrivateKey.load_pkcs1(key_file.read())
        decrypted_des_key = rsa.decrypt(base64.b64decode(encrypted_des_key), private_key)
        return decrypted_des_key

    def decrypt_message(self, encrypted_message, des_key):
        logger.info("Trying to DES_DECRYPT the MESSAGE")
        des = DES.new(des_key, DES.MODE_ECB)
        decrypted_message = des.decrypt(base64.b64decode(encrypted_message)).decode().rstrip()
        return decrypted_message

    async def chat_message(self, event):
        logger.info("CHAT MESSAGE is called!")
        message = event['message']
        sender = event['sender']
        timestamp = event['timestamp']

        await self.send(text_data=json.dumps({
            'message': message,
            'sender': sender,
            'timestamp': timestamp,
        }))
