from django.contrib import admin
from django.utils.html import format_html
from django.utils import timezone
from datetime import timedelta
from .models import RequestLog, BlockedIP, SuspiciousIP, GeolocationCache

@admin.register(RequestLog)
class RequestLogAdmin(admin.ModelAdmin):
    list_display = ('ip_address', 'path', 'country', 'city', 'timestamp')
    list_filter = ('timestamp', 'country', 'city')
    search_fields = ('ip_address', 'path', 'country', 'city')
    readonly_fields = ('ip_address', 'path', 'country', 'city', 'timestamp')
    date_hierarchy = 'timestamp'
    list_per_page = 50
    
    fieldsets = (
        ('Request Information', {
            'fields': ('ip_address', 'path', 'timestamp')
        }),
        ('Geolocation Data', {
            'fields': ('country', 'city'),
            'classes': ('collapse',)
        }),
    )
    
    def get_queryset(self, request):
        return super().get_queryset(request).select_related(None)

@admin.register(BlockedIP)
class BlockedIPAdmin(admin.ModelAdmin):
    list_display = ('ip_address', 'created_at', 'reason', 'block_duration')
    list_filter = ('created_at',)
    search_fields = ('ip_address', 'reason')
    readonly_fields = ('created_at',)
    list_editable = ('reason',)
    date_hierarchy = 'created_at'
    
    fieldsets = (
        (None, {
            'fields': ('ip_address', 'reason')
        }),
        ('Timestamps', {
            'fields': ('created_at',),
            'classes': ('collapse',)
        }),
    )
    
    def block_duration(self, obj):
        duration = timezone.now() - obj.created_at
        days = duration.days
        hours = duration.seconds // 3600
        return f"{days}d {hours}h"
    block_duration.short_description = 'Block Duration'

@admin.register(SuspiciousIP)
class SuspiciousIPAdmin(admin.ModelAdmin):
    list_display = ('ip_address', 'reason', 'request_count', 'first_detected', 'last_detected', 'is_active', 'action_buttons')
    list_filter = ('is_active', 'first_detected', 'last_detected')
    search_fields = ('ip_address', 'reason')
    readonly_fields = ('first_detected', 'last_detected')
    list_editable = ('is_active',)
    date_hierarchy = 'first_detected'
    actions = ['block_selected_ips', 'mark_as_inactive']
    
    fieldsets = (
        (None, {
            'fields': ('ip_address', 'reason', 'request_count', 'is_active')
        }),
        ('Additional Information', {
            'fields': ('sensitive_paths', 'country', 'city'),
            'classes': ('collapse',)
        }),
        ('Timestamps', {
            'fields': ('first_detected', 'last_detected'),
            'classes': ('collapse',)
        }),
    )
    
    def action_buttons(self, obj):
        return format_html(
            '<a href="/admin/ip_tracking/blockedip/add/?ip_address={}" class="button">Block</a> '
            '<a href="/admin/ip_tracking/requestlog/?ip_address={}" class="button">View Logs</a>',
            obj.ip_address, obj.ip_address
        )
    action_buttons.short_description = 'Actions'
    action_buttons.allow_tags = True
    
    def block_selected_ips(self, request, queryset):
        for suspicious_ip in queryset:
            if not BlockedIP.objects.filter(ip_address=suspicious_ip.ip_address).exists():
                BlockedIP.objects.create(
                    ip_address=suspicious_ip.ip_address,
                    reason=f"Blocked from suspicious IP list: {suspicious_ip.reason}"
                )
        self.message_user(request, f"Blocked {queryset.count()} IP addresses")
    block_selected_ips.short_description = "Block selected IP addresses"
    
    def mark_as_inactive(self, request, queryset):
        updated = queryset.update(is_active=False)
        self.message_user(request, f"Marked {updated} suspicious IPs as inactive")
    mark_as_inactive.short_description = "Mark selected as inactive"

@admin.register(GeolocationCache)
class GeolocationCacheAdmin(admin.ModelAdmin):
    list_display = ('ip_address', 'country', 'city', 'timestamp', 'is_expired')
    list_filter = ('country', 'city', 'timestamp')
    search_fields = ('ip_address', 'country', 'city')
    readonly_fields = ('timestamp',)
    date_hierarchy = 'timestamp'
    
    fieldsets = (
        (None, {
            'fields': ('ip_address', 'country', 'city')
        }),
        ('Timestamps', {
            'fields': ('timestamp',),
            'classes': ('collapse',)
        }),
    )
    
    def is_expired(self, obj):
        return obj.is_expired()
    is_expired.boolean = True
    is_expired.short_description = 'Expired'

# Custom admin site header and title
admin.site.site_header = 'IP Tracking Administration'
admin.site.site_title = 'IP Tracking Admin'
admin.site.index_title = 'Welcome to IP Tracking Administration'

# Optional: Add a custom admin view for statistics
from django.urls import path
from django.http import HttpResponse
from django.db.models import Count, Q
from django.utils import timezone
from datetime import timedelta

class CustomAdminSite(admin.AdminSite):
    def get_urls(self):
        urls = super().get_urls()
        custom_urls = [
            path('ip_tracking_stats/', self.admin_view(self.ip_tracking_stats), name='ip_tracking_stats'),
        ]
        return custom_urls + urls
    
    def ip_tracking_stats(self, request):
        # Calculate statistics
        twenty_four_hours_ago = timezone.now() - timedelta(hours=24)
        
        stats = {
            'total_requests': RequestLog.objects.count(),
            'requests_24h': RequestLog.objects.filter(timestamp__gte=twenty_four_hours_ago).count(),
            'total_blocked_ips': BlockedIP.objects.count(),
            'active_suspicious_ips': SuspiciousIP.objects.filter(is_active=True).count(),
            'top_countries': list(RequestLog.objects.exclude(country__isnull=True).values('country')
                                .annotate(count=Count('country')).order_by('-count')[:5]),
            'top_ips': list(RequestLog.objects.values('ip_address')
                            .annotate(count=Count('ip_address')).order_by('-count')[:5]),
        }
        
        # Simple HTML response with statistics
        html = f"""
        <h1>IP Tracking Statistics</h1>
        <p>Total Requests: {stats['total_requests']}</p>
        <p>Requests (24h): {stats['requests_24h']}</p>
        <p>Blocked IPs: {stats['total_blocked_ips']}</p>
        <p>Active Suspicious IPs: {stats['active_suspicious_ips']}</p>
        <h2>Top Countries</h2>
        <ul>
        {"".join(f'<li>{item["country"]}: {item["count"]}</li>' for item in stats['top_countries'])}
        </ul>
        <h2>Top IP Addresses</h2>
        <ul>
        {"".join(f'<li>{item["ip_address"]}: {item["count"]}</li>' for item in stats['top_ips'])}
        </ul>
        """
        return HttpResponse(html)

# Optional: Replace the default admin site
# admin.site = CustomAdminSite()
