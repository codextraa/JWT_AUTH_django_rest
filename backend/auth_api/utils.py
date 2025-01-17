import random, uuid
from django.core.cache import cache
from django.conf import settings
from django.core.mail import EmailMessage


class EmailOtp:
    """Email Otp Sender (used during Login)"""
    
    @staticmethod
    def generate_otp():
        otp = random.randint(100000, 999999)
        cache.set(f'otp_{otp}', otp, timeout=600)
        return otp
    
    @staticmethod
    def send_email_otp(email, otp):
        try:
            email = EmailMessage(
                subject = '2 Factor Login Authentication',
                body = f'{email} your OTP code is: {otp}',
                to = [email]
            )
            email.send()
            
            return True
        except Exception as e:
            return False
        
    @staticmethod
    def verify_otp(request_otp):
        stored_otp = cache.get(f'otp_{request_otp}')
        
        if not stored_otp:
            return False
        else:
            cache.delete(f'otp_{request_otp}')
            return True
            