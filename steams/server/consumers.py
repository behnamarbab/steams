import json
import logging
import base64
from datetime import datetime, UTC

import pytz

from channels.generic.websocket import AsyncWebsocketConsumer
from asgiref.sync import sync_to_async
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from Crypto.Cipher import DES
from .models import CustomUser, Message
from django.utils.dateparse import parse_datetime

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.DEBUG)

class ChatConsumer(AsyncWebsocketConsumer):
    async def connect(self):
        logger.info(f"Scope: {self.scope['url_route']['kwargs']}")
        self.chat_id = self.scope['url_route']['kwargs']['chat_id']

        # Join room group
        await self.channel_layer.group_add(
            self.chat_id,
            self.channel_name
        )

        await self.accept()

    async def disconnect(self, close_code):
        # Leave room group
        await self.channel_layer.group_discard(
            self.chat_id,
            self.channel_name
        )

    async def receive(self, text_data):
        data = json.loads(text_data)
        timestamp = data['timestamp']
        encrypted_message = data['message']
        encrypted_des_key = data['encrypted_des_key']
        signature = data['signature']
        sender_id = data['sender_id']
        recipient_id = data['recipient']
        chat_id = data['chat_id']

        # Asynchronous database operations
        try:
            user = await sync_to_async(CustomUser.objects.get)(id=sender_id)
            recipient = await sync_to_async(CustomUser.objects.get)(id=recipient_id)
            if user.rsa_public_key is None:
                await self.send(text_data=json.dumps({'status': 'error', 'message': 'Public key not found for user'}))
                return
            public_key = RSA.import_key(user.rsa_public_key)
        except CustomUser.DoesNotExist:
            await self.send(text_data=json.dumps({'status': 'error', 'message': 'User not found'}))
            return

        # Custom verification
        hash_to_verify = self.xor_hash(encrypted_message)
        hash_str = hash_to_verify['high'].to_bytes(3, 'big') + hash_to_verify['low'].to_bytes(3, 'big')
        h = SHA256.new(hash_str)

        decoded_signature = base64.b64decode(signature)
                
        try:
            pkcs1_15.new(public_key).verify(h, decoded_signature)
        except (ValueError, TypeError):
            if signature is None:
                await self.send(text_data=json.dumps({'status': 'error', 'message': 'Invalid signature'}))
                return

        # Asynchronous database operation
        await sync_to_async(Message.objects.create)(
            sender=user,
            recipient=recipient,
            encrypted_message=encrypted_message,
            encrypted_des_key=encrypted_des_key,
            chat_id=chat_id,
            timestamp=datetime.fromtimestamp(float(timestamp)/1000, tz=UTC)
        )
        
        # Send message to room group
        await self.channel_layer.group_send(
            self.chat_id,
            {
                'type': 'chat_message',
                'message': encrypted_message,
                'sender': user.username,
                'timestamp': timestamp,
            }
        )

    async def chat_message(self, event):
        message = event['message']
        sender = event['sender']
        timestamp = event['timestamp']

        # Send message to WebSocket
        await self.send(text_data=json.dumps({
            'message': message,
            'sender': sender,
            'timestamp': timestamp,
        }))

    def xor_hash(self, message):
        blockSize = 48 // 8  # 48 bits = 6 bytes
        high = 0  # higher 24 bits
        low = 0   # lower 24 bits

        for i in range(len(message)):
            char_code = ord(message[i])
            shift_amount = (i % blockSize) * 8

            if shift_amount < 24:
                low ^= char_code << shift_amount
            else:
                high ^= char_code << (shift_amount - 24)

        return {'high': high & 0xFFFFFF, 'low': low & 0xFFFFFF}

    def decrypt_message(self, encrypted_message, des_key):
        des_key_bytes = bytes.fromhex(des_key)
        encrypted_message_bytes = bytes.fromhex(encrypted_message)
        cipher = DES.new(des_key_bytes, DES.MODE_ECB)
        decrypted_message = cipher.decrypt(encrypted_message_bytes)
        # Unpad the decrypted message (remove padding bytes)
        pad_length = decrypted_message[-1]
        decrypted_message = decrypted_message[:-pad_length]
        return decrypted_message.decode('utf-8')
