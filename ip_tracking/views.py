from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.utils.decorators import method_decorator
from django.views import View
from django.views.generic import ListView, TemplateView
from django.views.decorators.csrf import csrf_protect
from django.http import HttpResponseForbidden, JsonResponse
from django.db.models import Count, Q
from django.utils import timezone
from datetime import timedelta
from ratelimit.decorators import ratelimit
from ratelimit.exceptions import Ratelimited

from .models import RequestLog, BlockedIP

class LoginView(View):
    """
    Login view with rate limiting for both GET and POST requests
    """
    @method_decorator(csrf_protect)
    @method_decorator(ratelimit(key='user_or_ip', rate='10/m', method='POST', block=True))
    def post(self, request):
        """
        Handle login POST requests with rate limiting
        """
        # Rate limiting is applied to POST requests only
        username = request.POST.get('username')
        password = request.POST.get('password')
        
        user = authenticate(request, username=username, password=password)
        if user is not None:
            login(request, user)
            messages.success(request, f'Welcome back, {user.username}!')
            return redirect('home')
        else:
            messages.error(request, 'Invalid username or password.')
            return render(request, 'ip_tracking/login.html', {'username': username})
    
    @method_decorator(ratelimit(key='ip', rate='5/m', method='GET', block=True))
    def get(self, request):
        """
        Handle login GET requests with rate limiting for anonymous users
        """
        # Redirect authenticated users to home
        if request.user.is_authenticated:
            return redirect('home')
        return render(request, 'ip_tracking/login.html')

class LogoutView(View):
    """
    Logout view
    """
    def get(self, request):
        logout(request)
        messages.info(request, 'You have been logged out successfully.')
        return redirect('login')

class HomeView(TemplateView):
    """
    Home page view
    """
    template_name = 'ip_tracking/home.html'
    
    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        
        # Add some statistics to the context
        if self.request.user.is_authenticated:
            context['recent_requests'] = RequestLog.objects.all()[:10]
            context['total_requests'] = RequestLog.objects.count()
            context['blocked_ips_count'] = BlockedIP.objects.count()
            
            # Top countries in the last 24 hours
            twenty_four_hours_ago = timezone.now() - timedelta(hours=24)
            context['top_countries'] = RequestLog.objects.filter(
                timestamp__gte=twenty_four_hours_ago
            ).exclude(country__isnull=True).values('country').annotate(
                count=Count('country')
            ).order_by('-count')[:5]
        
        return context

class SensitiveActionView(View):
    """
    Example of a sensitive view that requires rate limiting
    """
    @method_decorator(login_required)
    @method_decorator(ratelimit(key='user', rate='10/m', method='POST', block=True))
    def post(self, request):
        """
        Handle sensitive action POST requests
        """
        # This would be for sensitive actions like password reset, etc.
        messages.success(request, 'Sensitive action completed successfully.')
        return redirect('home')
    
    @method_decorator(login_required)
    @method_decorator(ratelimit(key='user', rate='5/m', method='GET', block=True))
    def get(self, request):
        """
        Handle sensitive action GET requests
        """
        return render(request, 'ip_tracking/sensitive_action.html')

class RequestLogListView(ListView):
    """
    View to display request logs (admin and staff only)
    """
    model = RequestLog
    template_name = 'ip_tracking/request_logs.html'
    context_object_name = 'request_logs'
    paginate_by = 50
    ordering = ['-timestamp']
    
    @method_decorator(login_required)
    def dispatch(self, request, *args, **kwargs):
        """
        Only allow staff users to access this view
        """
        if not request.user.is_staff:
            messages.error(request, 'You do not have permission to view request logs.')
            return redirect('home')
        return super().dispatch(request, *args, **kwargs)
    
    def get_queryset(self):
        queryset = super().get_queryset()
        
        # Filter by IP address if provided
        ip_address = self.request.GET.get('ip')
        if ip_address:
            queryset = queryset.filter(ip_address__icontains=ip_address)
        
        # Filter by country if provided
        country = self.request.GET.get('country')
        if country:
            queryset = queryset.filter(country__icontains=country)
        
        # Filter by path if provided
        path = self.request.GET.get('path')
        if path:
            queryset = queryset.filter(path__icontains=path)
        
        # Filter by date range if provided
        date_from = self.request.GET.get('date_from')
        date_to = self.request.GET.get('date_to')
        if date_from:
            queryset = queryset.filter(timestamp__date__gte=date_from)
        if date_to:
            queryset = queryset.filter(timestamp__date__lte=date_to)
        
        return queryset
    
    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        
        # Add filter parameters to context
        context['ip_filter'] = self.request.GET.get('ip', '')
        context['country_filter'] = self.request.GET.get('country', '')
        context['path_filter'] = self.request.GET.get('path', '')
        context['date_from_filter'] = self.request.GET.get('date_from', '')
        context['date_to_filter'] = self.request.GET.get('date_to', '')
        
        # Add statistics
        context['total_logs'] = RequestLog.objects.count()
        context['unique_ips'] = RequestLog.objects.values('ip_address').distinct().count()
        context['unique_countries'] = RequestLog.objects.exclude(country__isnull=True).values('country').distinct().count()
        
        return context

class BlockedIPListView(ListView):
    """
    View to display blocked IPs (admin and staff only)
    """
    model = BlockedIP
    template_name = 'ip_tracking/blocked_ips.html'
    context_object_name = 'blocked_ips'
    paginate_by = 50
    ordering = ['-created_at']
    
    @method_decorator(login_required)
    def dispatch(self, request, *args, **kwargs):
        """
        Only allow staff users to access this view
        """
        if not request.user.is_staff:
            messages.error(request, 'You do not have permission to view blocked IPs.')
            return redirect('home')
        return super().dispatch(request, *args, **kwargs)

class DashboardView(TemplateView):
    """
    Dashboard with analytics and statistics
    """
    template_name = 'ip_tracking/dashboard.html'
    
    @method_decorator(login_required)
    def dispatch(self, request, *args, **kwargs):
        """
        Only allow staff users to access the dashboard
        """
        if not request.user.is_staff:
            messages.error(request, 'You do not have permission to access the dashboard.')
            return redirect('home')
        return super().dispatch(request, *args, **kwargs)
    
    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        
        # Time periods for analytics
        now = timezone.now()
        twenty_four_hours_ago = now - timedelta(hours=24)
        seven_days_ago = now - timedelta(days=7)
        thirty_days_ago = now - timedelta(days=30)
        
        # Basic statistics
        context['total_requests'] = RequestLog.objects.count()
        context['total_blocked_ips'] = BlockedIP.objects.count()
        
        # Recent activity
        context['recent_requests'] = RequestLog.objects.all()[:10]
        
        # Requests by time period
        context['requests_24h'] = RequestLog.objects.filter(
            timestamp__gte=twenty_four_hours_ago
        ).count()
        
        context['requests_7d'] = RequestLog.objects.filter(
            timestamp__gte=seven_days_ago
        ).count()
        
        context['requests_30d'] = RequestLog.objects.filter(
            timestamp__gte=thirty_days_ago
        ).count()
        
        # Top IP addresses
        context['top_ips'] = RequestLog.objects.values('ip_address').annotate(
            count=Count('ip_address')
        ).order_by('-count')[:10]
        
        # Top countries
        context['top_countries'] = RequestLog.objects.exclude(country__isnull=True).values(
            'country'
        ).annotate(
            count=Count('country')
        ).order_by('-count')[:10]
        
        # Top paths
        context['top_paths'] = RequestLog.objects.values('path').annotate(
            count=Count('path')
        ).order_by('-count')[:10]
        
        # Requests by hour (for chart)
        requests_by_hour = []
        for i in range(24):
            hour_start = twenty_four_hours_ago + timedelta(hours=i)
            hour_end = hour_start + timedelta(hours=1)
            count = RequestLog.objects.filter(
                timestamp__gte=hour_start,
                timestamp__lt=hour_end
            ).count()
            requests_by_hour.append({
                'hour': hour_start.strftime('%H:00'),
                'count': count
            })
        
        context['requests_by_hour'] = requests_by_hour
        
        return context

class APIStatsView(View):
    """
    API endpoint for statistics (JSON)
    """
    @method_decorator(login_required)
    def get(self, request):
        """
        Return JSON statistics
        """
        if not request.user.is_staff:
            return JsonResponse({'error': 'Permission denied'}, status=403)
        
        # Time periods
        now = timezone.now()
        twenty_four_hours_ago = now - timedelta(hours=24)
        
        stats = {
            'total_requests': RequestLog.objects.count(),
            'total_blocked_ips': BlockedIP.objects.count(),
            'requests_24h': RequestLog.objects.filter(timestamp__gte=twenty_four_hours_ago).count(),
            'unique_ips_24h': RequestLog.objects.filter(
                timestamp__gte=twenty_four_hours_ago
            ).values('ip_address').distinct().count(),
            'top_countries': list(
                RequestLog.objects.exclude(country__isnull=True).values('country').annotate(
                    count=Count('country')
                ).order_by('-count')[:5]
            ),
            'top_ips': list(
                RequestLog.objects.values('ip_address').annotate(
                    count=Count('ip_address')
                ).order_by('-count')[:5]
            )
        }
        
        return JsonResponse(stats)

def rate_limit_exceeded(request, exception):
    """
    Custom view for when rate limit is exceeded
    """
    if isinstance(exception, Ratelimited):
        return render(request, 'ip_tracking/rate_limit_exceeded.html', status=429)
    return HttpResponseForbidden()

def handler403(request, exception=None):
    """
    Custom 403 handler
    """
    if isinstance(exception, Ratelimited):
        return rate_limit_exceeded(request, exception)
    return render(request, 'ip_tracking/403.html', status=403)

def handler404(request, exception=None):
    """
    Custom 404 handler
    """
    return render(request, 'ip_tracking/404.html', status=404)

def handler500(request):
    """
    Custom 500 handler
    """
    return render(request, 'ip_tracking/500.html', status=500)

def handler429(request, exception=None):
    """
    Custom 429 handler
    """
    return rate_limit_exceeded(request, exception)

class AboutView(TemplateView):
    """
    About page
    """
    template_name = 'ip_tracking/about.html'

class DocumentationView(TemplateView):
    """
    Documentation page
    """
    template_name = 'ip_tracking/documentation.html'

class ContactView(View):
    """
    Contact form view
    """
    @method_decorator(ratelimit(key='ip', rate='3/m', method='POST', block=True))
    def post(self, request):
        """
        Handle contact form submission with rate limiting
        """
        # Process contact form here
        messages.success(request, 'Your message has been sent successfully!')
        return redirect('contact')
    
    @method_decorator(ratelimit(key='ip', rate='5/m', method='GET', block=True))
    def get(self, request):
        """
        Display contact form
        """
        return render(request, 'ip_tracking/contact.html')

class PrivacyPolicyView(TemplateView):
    """
    Privacy policy page
    """
    template_name = 'ip_tracking/privacy_policy.html'

class TermsOfServiceView(TemplateView):
    """
    Terms of service page
    """
    template_name = 'ip_tracking/terms_of_service.html'

# Utility views
class ClearOldLogsView(View):
    """
    View to clear old logs (admin only)
    """
    @method_decorator(login_required)
    def post(self, request):
        """
        Clear logs older than 30 days
        """
        if not request.user.is_superuser:
            messages.error(request, 'Only administrators can perform this action.')
            return redirect('dashboard')
        
        thirty_days_ago = timezone.now() - timedelta(days=30)
        deleted_count, _ = RequestLog.objects.filter(timestamp__lt=thirty_days_ago).delete()
        
        messages.success(request, f'Successfully deleted {deleted_count} old log entries.')
        return redirect('dashboard')

class ExportLogsView(View):
    """
    View to export logs as CSV (admin only)
    """
    @method_decorator(login_required)
    def get(self, request):
        """
        Export logs as CSV
        """
        if not request.user.is_staff:
            messages.error(request, 'You do not have permission to export logs.')
            return redirect('home')
        
        import csv
        from django.http import HttpResponse
        
        # Create HttpResponse object with CSV header
        response = HttpResponse(content_type='text/csv')
        response['Content-Disposition'] = 'attachment; filename="request_logs.csv"'
        
        writer = csv.writer(response)
        writer.writerow(['IP Address', 'Timestamp', 'Path', 'Country', 'City'])
        
        # Write log data
        logs = RequestLog.objects.all().order_by('-timestamp')
        for log in logs:
            writer.writerow([log.ip_address, log.timestamp, log.path, log.country or '', log.city or ''])
        
        return response        Handle contact form submission with rate limiting
        """
        # Process contact form here
        messages.success(request, 'Your message has been sent successfully!')
        return redirect('contact')
    
    @method_decorator(ratelimit(key='ip', rate='5/m', method='GET', block=True))
    def get(self, request):
        """
        Display contact form
        """
        return render(request, 'ip_tracking/contact.html')

class PrivacyPolicyView(TemplateView):
    """
    Privacy policy page
    """
    template_name = 'ip_tracking/privacy_policy.html'

class TermsOfServiceView(TemplateView):
    """
    Terms of service page
    """
    template_name = 'ip_tracking/terms_of_service.html'

# Utility views
class ClearOldLogsView(View):
    """
    View to clear old logs (admin only)
    """
    @method_decorator(login_required)
    def post(self, request):
        """
        Clear logs older than 30 days
        """
        if not request.user.is_superuser:
            messages.error(request, 'Only administrators can perform this action.')
            return redirect('dashboard')
        
        thirty_days_ago = timezone.now() - timedelta(days=30)
        deleted_count, _ = RequestLog.objects.filter(timestamp__lt=thirty_days_ago).delete()
        
        messages.success(request, f'Successfully deleted {deleted_count} old log entries.')
        return redirect('dashboard')

class ExportLogsView(View):
    """
    View to export logs as CSV (admin only)
    """
    @method_decorator(login_required)
    def get(self, request):
        """
        Export logs as CSV
        """
        if not request.user.is_staff:
            messages.error(request, 'You do not have permission to export logs.')
            return redirect('home')
        
        import csv
        from django.http import HttpResponse
        
        # Create HttpResponse object with CSV header
        response = HttpResponse(content_type='text/csv')
        response['Content-Disposition'] = 'attachment; filename="request_logs.csv"'
        
        writer = csv.writer(response)
        writer.writerow(['IP Address', 'Timestamp', 'Path', 'Country', 'City'])
        
        # Write log data
        logs = RequestLog.objects.all().order_by('-timestamp')
        for log in logs:
            writer.writerow([log.ip_address, log.timestamp, log.path, log.country or '', log.city or ''])
        
        return responseortcuts import render
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
