from django.core.management.base import BaseCommand
from django.core.management import CommandError
from ip_tracking.models import BlockedIP

class Command(BaseCommand):
    help = 'Block one or more IP addresses by adding them to the BlockedIP model'
    
    def add_arguments(self, parser):
        parser.add_argument(
            'ip_addresses',
            nargs='+',
            type=str,
            help='One or more IP addresses to block'
        )
        parser.add_argument(
            '--reason',
            type=str,
            help='Reason for blocking the IP address(es)'
        )
    
    def handle(self, *args, **options):
        ip_addresses = options['ip_addresses']
        reason = options.get('reason')
        
        blocked_count = 0
        skipped_count = 0
        
        for ip in ip_addresses:
            # Validate IP address format
            try:
                # This will raise ValueError if IP is invalid
                BlockedIP._meta.get_field('ip_address').to_python(ip)
            except ValueError:
                self.stdout.write(
                    self.style.WARNING(f"Skipping invalid IP address: {ip}")
                )
                skipped_count += 1
                continue
            
            # Check if IP is already blocked
            if BlockedIP.objects.filter(ip_address=ip).exists():
                self.stdout.write(
                    self.style.WARNING(f"IP address already blocked: {ip}")
                )
                skipped_count += 1
                continue
            
            # Create new blocked IP entry
            try:
                BlockedIP.objects.create(ip_address=ip, reason=reason)
                self.stdout.write(
                    self.style.SUCCESS(f"Successfully blocked IP: {ip}")
                )
                blocked_count += 1
            except Exception as e:
                self.stdout.write(
                    self.style.ERROR(f"Error blocking IP {ip}: {str(e)}")
                )
                skipped_count += 1
        
        # Summary
        self.stdout.write(
            self.style.SUCCESS(
                f"\nBlocked {blocked_count} IP(s), skipped {skipped_count} IP(s)"
            )
        )
