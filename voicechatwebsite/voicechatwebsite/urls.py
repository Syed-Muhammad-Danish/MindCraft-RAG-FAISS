from django.contrib import admin
from django.urls import path, include
from django.shortcuts import redirect
from django.views.generic import View
from chat import views
from django.views.generic import RedirectView

class HomeView(View):
    def get(self, request):
        if request.user.is_authenticated:
            return redirect('study_home')
        return redirect('login')

urlpatterns = [
    path('admin/', admin.site.urls),
    path('accounts/', include('accounts.urls')),
    path('study/', include('study_assistant.urls')),
    path('chat/', include('chat.urls')),
    path('home/', HomeView.as_view(), name='home'),
    path('', RedirectView.as_view(url='/study/', permanent=True)),
    path('chat-index/', views.index, name='chat_index'),
    path('room/<str:username>/', views.chat_room, name='chat_room'),
    path('search/', views.search_users, name='search_users'),
    path('send-request/<str:username>/', views.send_connection_request, name='send_connection_request'),
    path('handle-request/<int:connection_id>/', views.handle_connection_request, name='handle_connection_request'),
    path('encrypt-file/', views.encrypt_file, name='encrypt_file'),
    path('decrypt-file/', views.decrypt_file, name='decrypt_file'),
]