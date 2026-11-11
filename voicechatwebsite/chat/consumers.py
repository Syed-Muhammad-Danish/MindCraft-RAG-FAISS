import json
from channels.generic.websocket import AsyncWebsocketConsumer
from channels.db import database_sync_to_async
from accounts.models import CustomUser
from chat.models import Message


class ChatConsumer(AsyncWebsocketConsumer):
    async def connect(self):
        self.receiver_username = self.scope['url_route']['kwargs']['username']
        self.sender_username = self.scope['user'].username
        # Symmetric room group name
        usernames = sorted([self.sender_username, self.receiver_username])
        self.room_group_name = f'chat_{usernames[0]}_{usernames[1]}'

        print(
            f"WebSocket connecting: room={self.room_group_name}, user={self.sender_username}, receiver={self.receiver_username}")

        try:
            await self.channel_layer.group_add(
                self.room_group_name,
                self.channel_name
            )
            await self.accept()
            print(f"WebSocket connected: {self.room_group_name}")
        except Exception as e:
            print(f"WebSocket connection error: {e}")
            await self.close()

    async def disconnect(self, close_code):
        print(f"WebSocket disconnected: room={self.room_group_name}, code={close_code}")
        try:
            await self.channel_layer.group_discard(
                self.room_group_name,
                self.channel_name
            )
        except Exception as e:
            print(f"Error disconnecting: {e}")

    async def receive(self, text_data):
        print(f"Received data: {text_data}")
        try:
            text_data_json = json.loads(text_data)
            message = text_data_json.get('message', '').strip()
            if not message:
                print("Empty message received, ignoring")
                return

            saved_message = await self.save_message(self.sender_username, self.receiver_username, message)
            print(f"Message saved: {saved_message.content} from {self.sender_username} to {self.receiver_username}")

            await self.channel_layer.group_send(
                self.room_group_name,
                {
                    'type': 'chat_message',
                    'message': message,
                    'sender': self.sender_username,
                    'timestamp': saved_message.timestamp.isoformat()
                }
            )
        except json.JSONDecodeError as e:
            print(f"JSON decode error: {e}")
        except Exception as e:
            print(f"Error in receive: {e}")

    async def chat_message(self, event):
        try:
            print(f"Broadcasting: {event['message']} from {event['sender']}")
            await self.send(text_data=json.dumps({
                'message': event['message'],
                'sender': event['sender'],
                'timestamp': event['timestamp']
            }))
        except Exception as e:
            print(f"Error broadcasting: {e}")

    @database_sync_to_async
    def save_message(self, sender_username, receiver_username, message):
        print(f"Saving message: {message} from {sender_username} to {receiver_username}")
        try:
            sender = CustomUser.objects.get(username=sender_username)
            receiver = CustomUser.objects.get(username=receiver_username)
            message_obj = Message.objects.create(
                sender=sender,
                receiver=receiver,
                content=message
            )
            print(f"Saved successfully: {message_obj.content}")
            return message_obj
        except Exception as e:
            print(f"Save error: {e}")
            raise