from django.db import models

class RequestLog(models.Model):
    ip_address = models.GenericIPAddressField()
    timestamp = models.DateTimeField(auto_now_add=True)
    path = models.CharField(max_length=255)
    country = models.CharField(max_length=100, blank=True, null=True)
    city = models.CharField(max_length=100, blank=True, null=True)
    
    class Meta:
        ordering = ['-timestamp']
        verbose_name = 'Request Log'
        verbose_name_plural = 'Request Logs'
        indexes = [
            models.Index(fields=['ip_address']),
            models.Index(fields=['country', 'city']),
            models.Index(fields=['timestamp']),
        ]
    
    def __str__(self):
        location = f"{self.city}, {self.country}" if self.city and self.country else "Unknown location"
        return f"{self.ip_address} - {self.path} - {location}"


class BlockedIP(models.Model):
    ip_address = models.GenericIPAddressField(unique=True)
    created_at = models.DateTimeField(auto_now_add=True)
    reason = models.CharField(max_length=255, blank=True, null=True)
    
    class Meta:
        verbose_name = 'Blocked IP'
        verbose_name_plural = 'Blocked IPs'
        ordering = ['-created_at']
    
    def __str__(self):
        return f"{self.ip_address} (blocked at {self.created_at})"


class GeolocationCache(models.Model):
    ip_address = models.GenericIPAddressField(unique=True)
    country = models.CharField(max_length=100)
    city = models.CharField(max_length=100)
    timestamp = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        verbose_name = 'Geolocation Cache'
        verbose_name_plural = 'Geolocation Cache'
        indexes = [
            models.Index(fields=['ip_address']),
            models.Index(fields=['timestamp']),
        ]
    
    def __str__(self):
        return f"{self.ip_address} - {self.city}, {self.country}"
    
    def is_expired(self):
        from django.utils import timezone
        from datetime import timedelta
        return timezone.now() > self.timestamp + timedelta(hours=24)
