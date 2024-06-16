# views.py
import logging.config
import os
import logging

from django.http import JsonResponse
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import user_passes_test, login_required
from django.contrib.auth import authenticate, login
from django.contrib.auth.views import LoginView
from asgiref.sync import sync_to_async, async_to_sync
from .forms import CustomUserCreationForm, UserLoginForm, MessageForm
from .models import CustomUser, Chat, ChatUser, Message
from .utils.security import encrypt_message, decrypt_message, verify_signature, encrypt_des_key, generate_des_key, decrypt_des_key
from .utils.chat import get_or_create_chat
from .utils.generate_keys import generate_rsa_key_pair
from django.views.decorators.csrf import csrf_exempt

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.DEBUG)

@login_required
def home(request):
    # Retrieve list of other users
    other_users = CustomUser.objects.exclude(pk=request.user.pk)
    return render(request, 'server/home.html', {'other_users': other_users})

@user_passes_test(lambda u: u.is_sysadmin)
def register_user(request):
    if request.method == 'POST':
        form = CustomUserCreationForm(request.POST)
        if form.is_valid():
            user = form.save(commit=False)
            des_key = generate_des_key()
            encrypted_des_key = encrypt_des_key(des_key)
            user.encrypted_des_key = encrypted_des_key
            user.save()
            return redirect('user_list')
    else:
        form = CustomUserCreationForm()
    return render(request, 'server/register_user.html', {'form': form})

@login_required
def chat_with_user(request, user_id):
    logger.info("This is called!")
    user_to_chat_with = get_object_or_404(CustomUser, pk=user_id)
    current_user = request.user

    # Retrieve or create the chat
    chat = async_to_sync(get_or_create_chat)(current_user, user_to_chat_with)
    chat_users = ChatUser.objects.filter(chat=chat).order_by('joined_at')

    # Retrieve all messages for this chat
    messages = chat.messages.order_by('timestamp')

    # Message form
    message_form = MessageForm()

    return render(request, 'server/chat_with_user.html', {
        'user_to_chat_with': user_to_chat_with,
        'messages': messages,
        'chat': chat,
        'message_form': message_form,
        'chat_users': chat_users,
    })

@sync_to_async
def get_or_create_chat(user1, user2):
    chat, created = Chat.objects.get_or_create(is_group_chat=False)
    if created:
        ChatUser.objects.create(user=user1, chat=chat)
        ChatUser.objects.create(user=user2, chat=chat)
    else:
        if not ChatUser.objects.filter(user=user1, chat=chat).exists():
            ChatUser.objects.create(user=user1, chat=chat)
        if not ChatUser.objects.filter(user=user2, chat=chat).exists():
            ChatUser.objects.create(user=user2, chat=chat)
    return chat

@login_required
def send_message(request, chat_id):
    logger.info("Sending a message?!!!!!")
    chat = get_object_or_404(Chat, id=chat_id)  # Assuming you have a Chat model
    if request.method == 'POST':
        form = MessageForm(request.POST)
        if form.is_valid():
            message = form.save(commit=False)
            message.encrypted_message = form.cleaned_data['encrypted_content']
            message.sender = request.user
            message.chat = chat
            message.save()
            logger.info("Message sent and encrypted: %s", message.encrypted_message)
            return redirect('chat_with_user', chat_id=chat.id)
    else:
        form = MessageForm()
    return render(request, 'chat_with_user.html', {'form': form, 'chat': chat})

@login_required
def group_chat(request, chat_id):
    chat = get_object_or_404(Chat, pk=chat_id)
    messages = chat.messages.order_by('timestamp')

    return render(request, 'server/group_chat.html', {
        'chat': chat,
        'messages': messages
    })

@login_required
def message_list(request):
    messages = Message.objects.filter(recipient=request.user)
    des_key = decrypt_des_key(request.user.encrypted_des_key)  # Decrypt the user's DES key
    decrypted_messages = [
        (msg, decrypt_message(msg.content, des_key))
        for msg in messages
    ]
    return render(request, 'server/message_list.html', {'messages': decrypted_messages})

@login_required
def update_des_key(request):
    des_key = generate_des_key()
    encrypted_des_key = encrypt_des_key(des_key)
    request.user.encrypted_des_key = encrypted_des_key
    request.user.save()
    return redirect('profile')  # Redirect to a user profile page or another relevant page

class CustomLoginView(LoginView):
    template_name = 'server/login.html'
    authentication_form = UserLoginForm

    def form_valid(self, form):
        # Get the authenticated user
        user = form.get_user()
        public_key = form.cleaned_data.get('public_key')

        if public_key:
            user.rsa_public_key = public_key
            user.save()

        # Log in the user
        login(self.request, user)

        # Redirect to the next page
        return JsonResponse({'status': 'success'})
    
    def form_invalid(self, form):
        return JsonResponse({'status': 'error', 'message': 'Invalid credentials'}, status=400)
