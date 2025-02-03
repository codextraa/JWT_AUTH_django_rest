"""
WSGI config for backend project.

It exposes the WSGI callable as a module-level variable named ``application``.

For more information on this file, see
https://docs.djangoproject.com/en/5.1/howto/deployment/wsgi/
"""

import os, threading, time
from django.core.wsgi import get_wsgi_application
from django.utils.timezone import now
from rest_framework_simplejwt.tokens import OutstandingToken

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'backend.settings')

application = get_wsgi_application()

def cleanup_task():
    while True:
        expired_tokens = OutstandingToken.objects.filter(expires_at__lt=now())
        count = expired_tokens.count()
        expired_tokens.delete()
        print(f"Deleted {count} expired refresh tokens")
        
        time.sleep(86400)  # Wait for 24 hours (86400 seconds)

# Start background thread
thread = threading.Thread(target=cleanup_task, daemon=True)
thread.start()
