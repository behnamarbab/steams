import logging.config
import os
import logging

from django.http import JsonResponse
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import user_passes_test, login_required
from django.contrib.auth.views import LoginView
from .forms import CustomUserCreationForm, UserLoginForm, MessageForm
from .models import CustomUser, Chat, ChatUser, Message
from .utils.security import encrypt_message, decrypt_message, verify_signature, encrypt_des_key, generate_des_key, decrypt_des_key
from .utils.chat import get_or_create_chat

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
def send_message(request):
    if request.method == 'POST':
        message_content = request.POST.get('message')
        chat_id = request.POST.get('chat_id')
        chat = get_object_or_404(Chat, pk=chat_id)
        sender = request.user

        # Save the message to the database
        message = Message(chat=chat, sender=sender, content=message_content)
        message.save()

        return JsonResponse({'success': True})
    return JsonResponse({'success': False})

@login_required
def chat_with_user(request, user_id):
    logger.info("This is called!")
    user_to_chat_with = get_object_or_404(CustomUser, pk=user_id)
    current_user = request.user

    # Retrieve or create the chat
    chat = get_or_create_chat([current_user, user_to_chat_with])

    # Retrieve all messages for this chat
    messages = chat.messages.order_by('timestamp')

    # Message form
    message_form = MessageForm()

    return render(request, 'server/chat_with_user.html', {
        'user_to_chat_with': user_to_chat_with,
        'messages': messages,
        'chat_id': chat.id,
        'message_form': message_form,
    })
    
def group_chat(request, chat_id):
    chat = get_object_or_404(Chat, pk=chat_id)
    messages = chat.messages.order_by('timestamp')

    return render(request, 'server/group_chat.html', {
        'chat': chat,
        'messages': messages
    })

@login_required
def message_list(request):
    messages = Message.objects.filter(receiver=request.user)
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
