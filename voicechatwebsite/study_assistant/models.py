from __future__ import annotations

from django.conf import settings
from django.db import models


class DocumentUpload(models.Model):
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name='study_documents'
    )
    title = models.CharField(max_length=255)
    file = models.FileField(upload_to='study_documents/%Y/%m/%d/')
    extracted_text = models.TextField(blank=True, default='')
    uploaded_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    is_active = models.BooleanField(default=True)

    class Meta:
        ordering = ['-uploaded_at']

    def __str__(self):
        return f'{self.user.username} - {self.title}'


class DocumentChunk(models.Model):
    document = models.ForeignKey(
        DocumentUpload,
        related_name='chunks',
        on_delete=models.CASCADE,
    )
    chunk_index = models.PositiveIntegerField(default=0)
    text = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['chunk_index']

    def __str__(self):
        return f'{self.document.title} chunk {self.chunk_index}'
