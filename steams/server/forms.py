from django import forms
from django.contrib.auth.forms import UserCreationForm, AuthenticationForm
from .models import CustomUser, Message

class CustomUserCreationForm(UserCreationForm):
    class Meta:
        model = CustomUser
        fields = ('username',)
        
class UserLoginForm(AuthenticationForm):
    public_key = forms.CharField(required=False, widget=forms.HiddenInput())
    class Meta:
        fields = ['username', 'password']

class MessageForm(forms.ModelForm):
    encrypted_content = forms.CharField(widget=forms.HiddenInput())

    class Meta:
        model = Message
        fields = ['encrypted_content']
