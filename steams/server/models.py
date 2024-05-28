from django.contrib.auth.models import AbstractUser
from django.db import models

class CustomUser(AbstractUser):
    # des_key = models.CharField(max_length=32, null=True, blank=True)  # Example field for DES key
    last_online = models.DateTimeField(auto_now_add=True, null=True)

class Chat(models.Model):
    name = models.CharField(max_length=255, blank=True)  # Optional name for group chats
    is_group_chat = models.BooleanField(default=False)

    def __str__(self):
        if self.is_group_chat and self.name:
            return f"Group Chat: {self.name}"
        return f"Chat {self.id}"

class ChatUser(models.Model):
    user = models.ForeignKey(CustomUser, on_delete=models.CASCADE)
    chat = models.ForeignKey(Chat, on_delete=models.CASCADE)
    joined_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.user.username} in {self.chat}"

class Message(models.Model):
    chat = models.ForeignKey(Chat, on_delete=models.CASCADE, related_name='messages')
    sender = models.ForeignKey(CustomUser, on_delete=models.CASCADE, related_name='sent_messages')
    content = models.TextField()  # Plain text content
    timestamp = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        ordering = ['timestamp']

    def __str__(self):
        return f"Message from {self.sender.username} at {self.timestamp}"
