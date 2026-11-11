from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required
from django.db import models
from accounts.models import CustomUser, UserKey, AES, pad, unpad
import base64
from .models import Message, Connection
from .fileEncryption import FileEncryption
from django.conf import settings
import logging
from openai import OpenAI
import os
import uuid
import tempfile

logger = logging.getLogger(__name__)

client = OpenAI(api_key=settings.OPENAI_API_KEY)

def generate_ai_response(user, question):
    try:
        history = Message.objects.filter(
            models.Q(sender=user, receiver__username='ai') |
            models.Q(sender__username='ai', receiver=user)
        ).order_by('timestamp')[:10]
        messages = [{"role": "system", "content": "You are a helpful assistant."}]
        for msg in history:
            role = "user" if msg.sender == user else "assistant"
            messages.append({"role": role, "content": msg.content})
        messages.append({"role": "user", "content": question})
        response = client.chat.completions.create(
            model="gpt-3.5-turbo",
            messages=messages,
            max_tokens=150,
            temperature=0.7
        )
        ai_response = response.choices[0].message.content.strip()
        logger.info(f"OpenAI API response: {ai_response}")
        return ai_response
    except Exception as e:
        logger.error(f"OpenAI API error: {e}")
        return "Sorry, I'm having trouble responding right now. Please try again later."

@login_required
def index(request):
    return redirect('/room/ai/')

@login_required
def search_users(request):
    query = request.GET.get('q', '').strip()
    current_chat_user = request.GET.get('current_user', 'ai')
    try:
        receiver = CustomUser.objects.get(username=current_chat_user)
    except CustomUser.DoesNotExist:
        logger.error(f"User {current_chat_user} not found")
        receiver = CustomUser.objects.get(username='ai')

    user_key = get_object_or_404(UserKey, user=request.user)
    recipient_key = get_object_or_404(UserKey, user=receiver)

    if receiver.username != 'ai':
        connection_to = Connection.objects.filter(from_user=request.user, to_user=receiver, status='accepted').exists()
        connection_from = Connection.objects.filter(from_user=receiver, to_user=request.user, status='accepted').exists()
        if not (connection_to or connection_from):
            receiver = CustomUser.objects.get(username='ai')
            recipient_key = get_object_or_404(UserKey, user=receiver)

    users = [c.to_user for c in Connection.objects.filter(from_user=request.user, status='accepted')] + \
            [c.from_user for c in Connection.objects.filter(to_user=request.user, status='accepted')]

    messages = Message.objects.filter(
        models.Q(sender=request.user, receiver=receiver) |
        models.Q(sender=receiver, receiver=request.user)
    ).order_by('timestamp')

    for message in messages:
        try:
            if message.sender == request.user:
                aes_key = recipient_key.private_key_d[:16].encode('utf-8')
            else:
                aes_key = user_key.private_key_d[:16].encode('utf-8')
            aes = AES(aes_key)
            encrypted_data = base64.b64decode(message.encrypted_content.encode('utf-8'))
            decrypted_content = b""
            for i in range(0, len(encrypted_data), 16):
                block = encrypted_data[i:i + 16]
                decrypted_content += aes.decrypt_block(block)
            message.encrypted_content = unpad(decrypted_content).decode('utf-8')
        except Exception as e:
            logger.error(f"Error decrypting message id={message.id}: {e}")
            message.encrypted_content = "[Error decrypting message]"

    connected_users = [u.id for u in users]
    search_results = []
    if query:
        search_results = CustomUser.objects.filter(username__icontains=query).exclude(id=request.user.id).exclude(username='ai').exclude(id__in=connected_users)

    pending_requests = Connection.objects.filter(to_user=request.user, status='pending')
    return render(request, 'chat/chat_room.html', {
        'receiver': receiver,
        'messages': messages,
        'users': users,
        'search_results': search_results,
        'query': query,
        'pending_requests': pending_requests,
        'recipient_public_key': [recipient_key.public_key_e, recipient_key.public_key_n],
        'user_private_key': [user_key.private_key_d, user_key.private_key_n],
    })

@login_required
def send_connection_request(request, username):
    to_user = get_object_or_404(CustomUser, username=username)
    if to_user != request.user and Connection.objects.filter(from_user=request.user, to_user=to_user).count() == 0:
        Connection.objects.create(from_user=request.user, to_user=to_user)
    return redirect('/room/ai/')

@login_required
def handle_connection_request(request, connection_id):
    connection = get_object_or_404(Connection, id=connection_id, to_user=request.user)
    if request.method == 'POST':
        action = request.POST.get('action')
        if action == 'accept':
            connection.status = 'accepted'
        elif action == 'reject':
            connection.status = 'rejected'
        connection.save()
    return redirect('/room/ai/')

@login_required
def encrypt_file(request):
    if request.method == 'POST':
        file = request.FILES.get('file')
        password = request.POST.get('password')
        allowed_user_id = request.POST.get('allowed_user')
        current_chat_user = request.POST.get('current_chat_user', 'ai')

        if file and password:
            temp_file = tempfile.NamedTemporaryFile(delete=False, dir=settings.MEDIA_ROOT, suffix=f"_{uuid.uuid4()}_{file.name}")
            temp_path = temp_file.name
            try:
                for chunk in file.chunks():
                    temp_file.write(chunk)
                temp_file.close()
                output_path = os.path.join(settings.MEDIA_ROOT, f"encrypted_{file.name}")
                enc = FileEncryption(password)
                enc.encrypt(temp_path, output_path, allowed_user_id)
            finally:
                for _ in range(3):
                    try:
                        os.remove(temp_path)
                        break
                    except PermissionError:
                        logger.warning(f"File {temp_path} is locked, retrying...")
                        import time
                        time.sleep(1)
                else:
                    logger.error(f"Failed to remove temporary file {temp_path} after retries")

            logger.info(f"Redirecting to /room/{current_chat_user}/ after encryption")
            return redirect(f'/room/{current_chat_user}/')

    connected_users = [u for u in Connection.objects.filter(from_user=request.user, status='accepted').values_list('to_user', flat=True)] + \
                      [u for u in Connection.objects.filter(to_user=request.user, status='accepted').values_list('from_user', flat=True)]
    allowed_users = CustomUser.objects.filter(id__in=connected_users)
    return render(request, 'chat/chat_room.html', {'allowed_users': allowed_users, 'current_chat_user': request.GET.get('current_chat_user', 'ai')})

@login_required
def decrypt_file(request):
    if request.method == 'POST':
        file = request.FILES.get('file')
        password = request.POST.get('password')
        user_id = request.user.id
        current_chat_user = request.POST.get('current_chat_user', 'ai')

        if file and password:
            temp_file = tempfile.NamedTemporaryFile(delete=False, dir=settings.MEDIA_ROOT, suffix=f"_{uuid.uuid4()}_{file.name}")
            temp_path = temp_file.name
            try:
                for chunk in file.chunks():
                    temp_file.write(chunk)
                temp_file.close()
                output_path = os.path.join(settings.MEDIA_ROOT, f"decrypted_{file.name}")
                enc = FileEncryption(password)
                enc.decrypt(temp_path, output_path, user_id)
            except FileNotFoundError as e:
                try:
                    os.remove(temp_path)
                except PermissionError:
                    logger.warning(f"Failed to remove temporary file {temp_path} due to locking")
                error_message = f"File not found: {str(e)}"
                return render(request, 'chat/chat_room.html', {
                    'error': error_message,
                    'current_chat_user': current_chat_user,
                    'redirect_url': f'/room/{current_chat_user}/'
                })
            except Exception as e:
                try:
                    os.remove(temp_path)
                except PermissionError:
                    logger.warning(f"Failed to remove temporary file {temp_path} due to locking")
                error_message = f"Error during decryption: {str(e)}"
                return render(request, 'chat/chat_room.html', {
                    'error': error_message,
                    'current_chat_user': current_chat_user,
                    'redirect_url': f'/room/{current_chat_user}/'
                })
            finally:
                for _ in range(3):
                    try:
                        os.remove(temp_path)
                        break
                    except PermissionError:
                        logger.warning(f"File {temp_path} is locked, retrying...")
                        import time
                        time.sleep(1)
                else:
                    logger.error(f"Failed to remove temporary file {temp_path} after retries")

            logger.info(f"Redirecting to /room/{current_chat_user}/ after decryption")
            return redirect(f'/room/{current_chat_user}/')

    current_chat_user = request.GET.get('current_chat_user', 'ai')
    return render(request, 'chat/chat_room.html', {'current_chat_user': current_chat_user})

@login_required
def chat_room(request, username):
    try:
        receiver = CustomUser.objects.get(username=username)
    except CustomUser.DoesNotExist:
        logger.error(f"User {username} not found")
        return redirect('/room/ai/')

    user_key = get_object_or_404(UserKey, user=request.user)
    recipient_key = get_object_or_404(UserKey, user=receiver)

    ai_user = CustomUser.objects.get(username='ai')
    users = [ai_user]
    users.extend([c.to_user for c in Connection.objects.filter(from_user=request.user, status='accepted')])
    users.extend([c.from_user for c in Connection.objects.filter(to_user=request.user, status='accepted')])
    users = list(dict.fromkeys(users))

    if receiver.username != 'ai':
        connection_to = Connection.objects.filter(from_user=request.user, to_user=receiver, status='accepted').exists()
        connection_from = Connection.objects.filter(from_user=receiver, to_user=request.user, status='accepted').exists()
        if not (connection_to or connection_from):
            return redirect('/room/ai/')

    messages = Message.objects.filter(
        models.Q(sender=request.user, receiver=receiver) |
        models.Q(sender=receiver, receiver=request.user)
    ).order_by('timestamp')
    logger.debug(f"Chat room: fetched {messages.count()} messages for {request.user.username} and {receiver.username}")

    for message in messages:
        try:
            if message.sender == request.user:
                aes_key = recipient_key.private_key_d[:16].encode('utf-8')
            else:
                aes_key = user_key.private_key_d[:16].encode('utf-8')
            aes = AES(aes_key)
            encrypted_data = base64.b64decode(message.encrypted_content.encode('utf-8'))
            decrypted_content = b""
            for i in range(0, len(encrypted_data), 16):
                block = encrypted_data[i:i + 16]
                decrypted_content += aes.decrypt_block(block)
            message.encrypted_content = unpad(decrypted_content).decode('utf-8')
        except Exception as e:
            logger.error(f"Error decrypting message id={message.id}: {e}")
            message.encrypted_content = "[Error decrypting message]"

    pending_requests = Connection.objects.filter(to_user=request.user, status='pending')
    connected_users = [u.id for u in users if u != request.user and u != ai_user]
    allowed_users = CustomUser.objects.filter(id__in=connected_users)
    return render(request, 'chat/chat_room.html', {
        'receiver': receiver,
        'messages': messages,
        'users': users,
        'search_results': [],
        'query': '',
        'pending_requests': pending_requests,
        'recipient_public_key': [recipient_key.public_key_e, recipient_key.public_key_n],
        'user_private_key': [user_key.private_key_d, user_key.private_key_n],
        'allowed_users': allowed_users,
        'current_chat_user': username,
    })