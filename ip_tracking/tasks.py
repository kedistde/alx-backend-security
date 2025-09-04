from celery import shared_task
from django.utils import timezone
from datetime import timedelta
from django.db.models import Count, Q
from django.db import transaction
import logging

from .models import RequestLog, SuspiciousIP, BlockedIP

logger = logging.getLogger(__name__)

@shared_task
def detect_suspicious_ips():
    """
    Celery task to detect suspicious IP addresses based on request patterns
    Runs hourly to check for anomalies
    """
    try:
        logger.info("Starting suspicious IP detection task...")
        
        # Calculate time range for analysis (last hour)
        one_hour_ago = timezone.now() - timedelta(hours=1)
        
        # Detect IPs with excessive requests (>100 per hour)
        detect_high_frequency_ips(one_hour_ago)
        
        # Detect IPs accessing sensitive paths
        detect_sensitive_path_access(one_hour_ago)
        
        # Detect scanning behavior (multiple 404 errors)
        detect_scanning_behavior(one_hour_ago)
        
        # Clean up old suspicious IP records
        cleanup_old_suspicious_ips()
        
        logger.info("Suspicious IP detection task completed successfully")
        return {"status": "success", "message": "Anomaly detection completed"}
    
    except Exception as e:
        logger.error(f"Error in suspicious IP detection task: {str(e)}")
        return {"status": "error", "message": str(e)}

def detect_high_frequency_ips(one_hour_ago):
    """
    Detect IPs making more than 100 requests in the last hour
    """
    high_frequency_ips = RequestLog.objects.filter(
        timestamp__gte=one_hour_ago
    ).values('ip_address').annotate(
        request_count=Count('id')
    ).filter(
        request_count__gt=100
    )
    
    for ip_data in high_frequency_ips:
        ip_address = ip_data['ip_address']
        request_count = ip_data['request_count']
        
        reason = f"High request frequency: {request_count} requests in the last hour"
        
        # Get additional info for the IP
        latest_request = RequestLog.objects.filter(
            ip_address=ip_address
        ).order_by('-timestamp').first()
        
        country = latest_request.country if latest_request else None
        city = latest_request.city if latest_request else None
        
        with transaction.atomic():
            suspicious_ip, created = SuspiciousIP.objects.get_or_create(
                ip_address=ip_address,
                defaults={
                    'reason': reason,
                    'request_count': request_count,
                    'country': country,
                    'city': city,
                }
            )
            
            if not created:
                # Update existing record
                suspicious_ip.reason = reason
                suspicious_ip.request_count = request_count
                suspicious_ip.last
