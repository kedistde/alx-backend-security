from django.contrib import admin
from django.urls import path, include
from django.conf import settings
from django.conf.urls import handler403, handler429

# Custom error handlers
handler403 = 'ip_tracking.views.handler403'
handler429 = 'ip_tracking.views.handler429'

urlpatterns = [
    path('admin/', admin.site.urls),
    path('', include('ip_tracking.urls')),
]
