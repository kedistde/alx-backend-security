# ip_tracking/models.py
from django.db import models

class RequestLog(models.Model):
    ip_address = models.GenericIPAddressField()
    timestamp = models.DateTimeField(auto_now_add=True)
    path = models.CharField(max_length=255)
    
    class Meta:
        ordering = ['-timestamp']
        verbose_name = 'Request Log'
        verbose_name_plural = 'Request Logs'
    
    def __str__(self):
        return f"{self.ip_address} - {self.path} - {self.timestamp}"
