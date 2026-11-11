from django.contrib import admin
from .models import Message

@admin.register(Message)
class MessageAdmin(admin.ModelAdmin):
    list_display = ['sender', 'receiver', 'content', 'timestamp']
    list_filter = ['sender', 'receiver', 'timestamp']
    search_fields = ['content', 'sender__username', 'receiver__username']