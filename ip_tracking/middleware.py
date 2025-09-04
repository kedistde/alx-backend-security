# ip_tracking/middleware.py
from django.utils import timezone
from .models import RequestLog

class IPTrackingMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response
    
    def __call__(self, request):
        # Process the request
        response = self.get_response(request)
        
        # Log the request details
        self.log_request(request)
        
        return response
    
    def get_client_ip(self, request):
        """
        Get the client's IP address from the request
        """
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            # X-Forwarded-For header can contain multiple IPs, the first one is the client's
            ip = x_forwarded_for.split(',')[0].strip()
        else:
            ip = request.META.get('REMOTE_ADDR')
        return ip
    
    def log_request(self, request):
        """
        Log the request details to the database
        """
        try:
            ip_address = self.get_client_ip(request)
            path = request.path
            
            # Create and save the log entry
            RequestLog.objects.create(
                ip_address=ip_address,
                path=path
            )
        except Exception as e:
            # Log the error but don't break the application
            # You might want to add proper logging here
            pass
