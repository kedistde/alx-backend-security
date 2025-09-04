# Add to existing settings.py

# Rate limiting configuration
RATELIMIT_VIEW = 'ip_tracking.views.rate_limit_exceeded'
RATELIMIT_USE_CACHE = 'default'
RATELIMIT_ENABLE = True  # Enable rate limiting in production

# Cache configuration for rate limiting (if not already set)
CACHES = {
    'default': {
        'BACKEND': 'django.core.cache.backends.locmem.LocMemCache',
        'LOCATION': 'unique-snowflake',
        'TIMEOUT': 300,  # 5 minutes
    }
}

# Add to INSTALLED_APPS if not already there
INSTALLED_APPS = [
    # ... other apps
    'ip_tracking',
    'ratelimit',
    # ... other apps
]

# Add to MIDDLEWARE if not already there
MIDDLEWARE = [
    # ... other middleware
    'ratelimit.middleware.RatelimitMiddleware',
    # ... other middleware
]

# URL configuration for the app
ROOT_URLCONF = 'your_project.urls'  # This should already be set

# Login URL for redirects
LOGIN_URL = '/login/'
LOGIN_REDIRECT_URL = '/'
LOGOUT_REDIRECT_URL = '/login/'
