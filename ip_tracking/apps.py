from django.apps import AppConfig
from django.utils.translation import gettext_lazy as _

class IpTrackingConfig(AppConfig):
    """
    Configuration class for the IP Tracking application.
    
    This class defines the configuration for the ip_tracking app,
    including the default auto field, app name, verbose name,
    and any app-specific initialization.
    """
    
    # Default primary key field type
    default_auto_field = 'django.db.models.BigAutoField'
    
    # App name (Python path)
    name = 'ip_tracking'
    
    # Human-readable name for the admin interface
    verbose_name = _('IP Tracking')
    
    def ready(self):
        """
        This method is called when the app is ready.
        Use it to perform initialization tasks, import signals,
        or schedule periodic tasks.
        """
        # Import and register signals
        try:
            from . import signals  # noqa: F401
        except ImportError:
            # Signals module doesn't exist or has errors
            pass
        
        # Import and register checks
        try:
            from . import checks  # noqa: F401
        except ImportError:
            # Checks module doesn't exist or has errors
            pass
        
        # Schedule Celery tasks if Celery is installed
        self.schedule_celery_tasks()
        
        # Register admin customizations
        self.register_admin_customizations()
    
    def schedule_celery_tasks(self):
        """
        Schedule periodic Celery tasks for the IP tracking app.
        This method checks if Celery is available and schedules
        the anomaly detection tasks.
        """
        try:
            from celery.schedules import crontab
            from django.conf import settings
            
            # Check if Celery is configured
            if hasattr(settings, 'CELERY_BEAT_SCHEDULE'):
                # Import tasks to ensure they're registered
                from . import tasks  # noqa: F401
                
                # Schedule hourly anomaly detection
                settings.CELERY_BEAT_SCHEDULE['ip_tracking_detect_suspicious_ips'] = {
                    'task': 'ip_tracking.tasks.detect_suspicious_ips',
                    'schedule': crontab(minute=0),  # Run every hour at :00
                    'options': {'expires': 3600},  # Expire after 1 hour
                }
                
                # Schedule daily cleanup of old suspicious IPs
                settings.CELERY_BEAT_SCHEDULE['ip_tracking_auto_block_suspicious_ips'] = {
                    'task': 'ip_tracking.tasks.auto_block_suspicious_ips',
                    'schedule': crontab(hour=2, minute=0),  # Run daily at 2:00 AM
                    'options': {'expires': 86400},  # Expire after 24 hours
                }
                
        except ImportError:
            # Celery is not installed, skip scheduling
            pass
        except Exception as e:
            # Log any errors during task scheduling
            import logging
            logger = logging.getLogger(__name__)
            logger.warning(f"Failed to schedule Celery tasks: {e}")
    
    def register_admin_customizations(self):
        """
        Register any admin customizations for the IP tracking app.
        This can include custom admin views, actions, or filters.
        """
        try:
            from django.contrib import admin
            from .models import RequestLog, BlockedIP, SuspiciousIP, GeolocationCache
            
            # You can add custom admin site configurations here
            # For example, register custom admin views or actions
            
        except Exception as e:
            # Log any errors during admin customization
            import logging
            logger = logging.getLogger(__name__)
            logger.warning(f"Failed to register admin customizations: {e}")
    
    def get_models(self, include_auto_created=False, include_swapped=False):
        """
        Return all models for this app.
        Override this method if you need to customize model discovery.
        """
        return super().get_models(include_auto_created, include_swapped)
    
    def get_model(self, model_name, require_ready=True):
        """
        Return the model with the given name.
        
        Args:
            model_name (str): Name of the model to retrieve
            require_ready (bool): Whether the app must be ready
            
        Returns:
            Model: The requested model class
        """
        return super().get_model(model_name, require_ready)
