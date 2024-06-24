"""
URL configuration for app project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/5.0/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import path
from .views import register_user, send_message, message_list, CustomLoginView, home, chat_with_user, logout_view

urlpatterns = [
    path('home/', home, name='home'),
    path('register/', register_user, name='register_user'),
    path('send/', send_message, name='send_message'),
    path('messages/', message_list, name='message_list'),
    path('login/', CustomLoginView.as_view(), name='login'),
    path('logout/', logout_view, name='logout'),
    path('chatting/<int:user_id>/', chat_with_user, name='chat_with_user'),
]
