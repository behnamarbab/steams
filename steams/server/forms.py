from django import forms
from django.contrib.auth.forms import UserCreationForm, AuthenticationForm
from .models import CustomUser, Message

class CustomUserCreationForm(UserCreationForm):
    class Meta:
        model = CustomUser
        fields = ('username',)
        
class UserLoginForm(AuthenticationForm):
    class Meta:
        fields = ['username', 'password']

class MessageForm(forms.ModelForm):
    class Meta:
        model = Message
        fields = ['content']
        labels = {
            'content': 'Message',
        }
        widgets = {
            'content': forms.Textarea(attrs={'rows': 2, 'cols': 50, 'id': 'id_content'}),
        }