from django.db import models
from accounts.models import CustomUser

class Message(models.Model):
    sender = models.ForeignKey(CustomUser, related_name='sent_messages', on_delete=models.CASCADE)
    receiver = models.ForeignKey(CustomUser, related_name='received_messages', on_delete=models.CASCADE)
    content = models.TextField()  # Plaintext for AI processing or internal use
    encrypted_content = models.TextField(blank=True)  # Encrypted message
    timestamp = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.sender.username} to {self.receiver.username}: {self.content}"

class Connection(models.Model):
    from_user = models.ForeignKey(CustomUser, related_name='sent_connections', on_delete=models.CASCADE)
    to_user = models.ForeignKey(CustomUser, related_name='received_connections', on_delete=models.CASCADE)
    status = models.CharField(max_length=10, choices=[('pending', 'Pending'), ('accepted', 'Accepted'), ('rejected', 'Rejected')], default='pending')
    timestamp = models.DateTimeField(auto_now_add=True)

    class Meta:
        unique_together = ('from_user', 'to_user')

    def __str__(self):
        return f"{self.from_user.username} -> {self.to_user.username} ({self.status})"