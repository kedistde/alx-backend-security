from django.http import HttpResponseForbidden
from django.core.cache import cache
from django.utils import timezone
from datetime import timedelta
from ipgeolocation import IpGeolocationAPI, GeolocationParams
from .models import RequestLog, BlockedIP, GeolocationCache

class IPTrackingMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response
        # Initialize with a dummy key - you should set IPGEOLOCATION_API_KEY in settings
        self.geolocation_api = IpGeolocationAPI("dummy_key")
    
    def __call__(self, request):
        # Check if IP is blocked before processing the request
        client_ip = self.get_client_ip(request)
        
        if self.is_ip_blocked(client_ip):
            return HttpResponseForbidden(
                f"Access denied. Your IP address ({client_ip}) has been blocked."
            )
        
        # Process the request if not blocked
        response = self.get_response(request)
        
        # Log the request details with geolocation
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
    
    def is_ip_blocked(self, ip_address):
        """
        Check if the IP address is in the blocked list
        """
        return BlockedIP.objects.filter(ip_address=ip_address).exists()
    
    def get_geolocation_data(self, ip_address):
        """
        Get geolocation data for an IP address with caching
        """
        # Skip private IP addresses
        if self.is_private_ip(ip_address):
            return None, None
        
        # Check cache first
        cached_data = self.get_cached_geolocation(ip_address)
        if cached_data:
            return cached_data.get('country'), cached_data.get('city')
        
        # If not in cache, check database cache
        db_cached = self.get_db_cached_geolocation(ip_address)
        if db_cached:
            # Cache in memory for future requests
            self.cache_geolocation(ip_address, db_cached.country, db_cached.city)
            return db_cached.country, db_cached.city
        
        # If not cached anywhere, fetch from API
        country, city = self.fetch_geolocation_from_api(ip_address)
        
        if country or city:
            # Cache the result
            self.cache_geolocation(ip_address, country, city)
            self.save_to_db_cache(ip_address, country, city)
        
        return country, city
    
    def is_private_ip(self, ip_address):
        """
        Check if IP address is private/local
        """
        if ip_address in ['127.0.0.1', 'localhost']:
            return True
        
        # Check for private IP ranges
        if ip_address.startswith('10.') or ip_address.startswith('192.168.') or ip_address.startswith('172.'):
            return True
        
        return False
    
    def get_cached_geolocation(self, ip_address):
        """
        Get geolocation from Django cache
        """
        cache_key = f'geolocation_{ip_address}'
        return cache.get(cache_key)
    
    def cache_geolocation(self, ip_address, country, city):
        """
        Cache geolocation data for 24 hours
        """
        cache_key = f'geolocation_{ip_address}'
        cache_data = {
            'country': country,
            'city': city,
            'timestamp': timezone.now().isoformat()
        }
        cache.set(cache_key, cache_data, timeout=60*60*24)  # 24 hours
    
    def get_db_cached_geolocation(self, ip_address):
        """
        Get geolocation from database cache
        """
        try:
            cached = GeolocationCache.objects.get(ip_address=ip_address)
            if not cached.is_expired():
                return cached
            else:
                # Remove expired cache entry
                cached.delete()
        except GeolocationCache.DoesNotExist:
            pass
        return None
    
    def save_to_db_cache(self, ip_address, country, city):
        """
        Save geolocation data to database cache
        """
        try:
            # Update existing or create new cache entry
            GeolocationCache.objects.update_or_create(
                ip_address=ip_address,
                defaults={
                    'country': country or 'Unknown',
                    'city': city or 'Unknown'
                }
            )
        except Exception as e:
            # Silently fail on cache save errors
            pass
    
    def fetch_geolocation_from_api(self, ip_address):
        """
        Fetch geolocation data from ipgeolocation API
        """
        try:
            # Create geolocation parameters
            params = GeolocationParams()
            params.set_ip_address(ip_address)
            params.set_fields('country_name,city')
            
            # Get geolocation data
            response = self.geolocation_api.get_geolocation(params=params)
            
            if response and not response.get('message'):
                country = response.get('country_name')
                city = response.get('city')
                return country, city
            
        except Exception as e:
            # Handle API errors gracefully
            print(f"Geolocation API error for IP {ip_address}: {str(e)}")
        
        return None, None
    
    def log_request(self, request):
        """
        Log the request details to the database with geolocation
        """
        try:
            ip_address = self.get_client_ip(request)
            path = request.path
            
            # Get geolocation data
            country, city = self.get_geolocation_data(ip_address)
            
            # Create and save the log entry
            RequestLog.objects.create(
                ip_address=ip_address,
                path=path,
                country=country,
                city=city
            )
        except Exception as e:
            # Log the error but don't break the application
            print(f"Error logging request: {str(e)}")            
            # Create and save the log entry
            RequestLog.objects.create(
                ip_address=ip_address,
                path=path
            )
        except Exception as e:
            # Log the error but don't break the application
            # You might want to add proper logging here
            pass
