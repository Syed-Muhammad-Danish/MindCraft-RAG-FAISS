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
        connection_from = Connection.objects.filter(from_user=receiver, to_user=request.user,
                                                    status='accepted').exists()
        if not (connection_to or connection_from):
            return redirect('room/ai/')

    users = [c.to_user for c in Connection.objects.filter(from_user=request.user, status='accepted')] + \
            [c.from_user for c in Connection.objects.filter(to_user=request.user, status='accepted')]
    error = None
    if request.method == 'POST':
        content = request.POST.get('content', '').strip()
        logger.debug(f"Chat room POST: username={username}, content='{content}', form_data={request.POST}")
        if content:
            try:
                aes_key = recipient_key.private_key_d[:16].encode('utf-8')
                aes = AES(aes_key)
                padded_content = pad(content.encode('utf-8'))
                encrypted_for_storage = b""
                for i in range(0, len(padded_content), 16):
                    block = padded_content[i:i + 16]
                    encrypted_for_storage += aes.encrypt_block(block)
                encrypted_for_storage = base64.b64encode(encrypted_for_storage).decode('utf-8')

                message = Message.objects.create(
                    sender=request.user,
                    receiver=receiver,
                    content=content,
                    encrypted_content=encrypted_for_storage
                )
                logger.info(f"Message saved: id={message.id}, from={request.user.username}, to={receiver.username}")

                if receiver.username == 'ai':
                    ai_response = generate_ai_response(request.user, content)
                    user_aes_key = user_key.private_key_d[:16].encode('utf-8')
                    aes = AES(user_aes_key)
                    padded_response = pad(ai_response.encode('utf-8'))
                    encrypted_response = b""
                    for i in range(0, len(padded_response), 16):
                        block = padded_response[i:i + 16]
                        encrypted_response += aes.encrypt_block(block)
                    encrypted_response = base64.b64encode(encrypted_response).decode('utf-8')

                    ai_message = Message.objects.create(
                        sender=receiver,
                        receiver=request.user,
                        content=ai_response,
                        encrypted_content=encrypted_response
                    )
                    logger.info(f"AI message saved: id={ai_message.id}, from=ai, to={request.user.username}")

                return redirect(f'/room/{username}/')
            except Exception as e:
                logger.error(f"Error saving message: {e}, sender={request.user.username}, receiver={username}")
                error = f"Failed to send message: {str(e)}"
        else:
            logger.warning("Empty message content in POST")
            error = "Message cannot be empty."

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
    connected_users = [u for u in
                       Connection.objects.filter(from_user=request.user, status='accepted').values_list('to_user',
                                                                                                        flat=True)] + \
                      [u for u in
                       Connection.objects.filter(to_user=request.user, status='accepted').values_list('from_user',
                                                                                                      flat=True)]
    allowed_users = CustomUser.objects.filter(id__in=connected_users)
    return render(request, 'chat/chat_room.html', {
        'receiver': receiver,
        'messages': messages,
        'users': users,
        'error': error,
        'pending_requests': pending_requests,
        'recipient_public_key': [recipient_key.public_key_e, recipient_key.public_key_n],
        'user_private_key': [user_key.private_key_d, user_key.private_key_n],
        'search_results': [],
        'query': '',
        'allowed_users': allowed_users,
    })