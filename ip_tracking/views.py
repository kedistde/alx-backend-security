# Add this to the existing views.py

from django.shortcuts import render
from django.http import HttpResponseForbidden
from ratelimit.exceptions import Ratelimited

def rate_limit_exceeded(request, exception):
    """Custom view for when rate limit is exceeded"""
    if isinstance(exception, Ratelimited):
        return render(request, 'ip_tracking/rate_limit_exceeded.html', status=429)
    return HttpResponseForbidden()

# Add error handler
def handler403(request, exception=None):
    if isinstance(exception, Ratelimited):
        return rate_limit_exceeded(request, exception)
    return HttpResponseForbidden()

def handler429(request, exception=None):
    return rate_limit_exceeded(request, exception)
