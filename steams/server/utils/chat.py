from server.models import Chat, ChatUser

def get_or_create_chat(users):
    if len(users) == 2:
        user1, user2 = users
        chats = Chat.objects.filter(is_group_chat=False).filter(chatuser__user=user1).filter(chatuser__user=user2)
        if chats.exists():
            return chats.first()
    chat = Chat.objects.create(is_group_chat=False)
    for user in users:
        ChatUser.objects.create(user=user, chat=chat)
    return chat