# inicio2/models.py
from django.db import models
from django.contrib.auth.models import User
import uuid
from datetime import datetime, timedelta

class VerificationToken(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    token = models.UUIDField(default=uuid.uuid4, editable=False)
    created_at = models.DateTimeField(auto_now_add=True)
    is_verified = models.BooleanField(default=False)
    
    def is_valid(self):
        # El token es válido por 24 horas
        return datetime.now() - self.created_at.replace(tzinfo=None) < timedelta(hours=24)
    
    def __str__(self):
        return f"Token for {self.user.username}"
    
# Añadir al archivo models.py existente
class PasswordResetToken(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    token = models.UUIDField(default=uuid.uuid4, editable=False)
    created_at = models.DateTimeField(auto_now_add=True)
    
    def is_valid(self):
        # El token es válido por 1 hora
        from django.utils import timezone
        return timezone.now() - self.created_at < timedelta(hours=1)
    
    def __str__(self):
        return f"Password Reset Token for {self.user.username}"
    
