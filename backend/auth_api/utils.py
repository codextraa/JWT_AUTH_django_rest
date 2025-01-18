import random, uuid
from datetime import datetime, timezone, timedelta
from urllib.parse import urlencode
from django.core.cache import cache
from django.conf import settings
from django.core.mail import EmailMessage
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired


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
                body = f'Hi {email},\n\nYour OTP code is: {otp}\n\nThe OTP will expire in 10 minutes',
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
        
class EmailLink:
    """Email Link Sender and Verifier."""
    SECRET_KEY = settings.SECRET_KEY
    SALT = "email-verification"
    EXPIRY_SECONDS = 600  # 10 minutes

    @classmethod
    def _generate_link(cls, email, action):
        """Generate a signed token for the email."""
        serializer = URLSafeTimedSerializer(cls.SECRET_KEY)
        token = serializer.dumps(email, salt=cls.SALT)
        
        # Adding expiry metadata 
        expiry_time = datetime.now(timezone.utc) + timedelta(seconds=cls.EXPIRY_SECONDS)
        expiry_timestamp = int(expiry_time.timestamp())
        
        params = {
            "token": token,
            "expiry": expiry_timestamp,
        }
        query_string = urlencode(params)
        
        # return f"{settings.FRONTEND_URL}/verify-email/{token}"
        if action == 'email-verification':
            return f"{settings.BACKEND_URL}/verify-email/?{query_string}"
        elif action == 'password-reset':
            return f"{settings.BACKEND_URL}/reset-password/?{query_string}"
        else:
            raise ValueError("Invalid action.")

    @classmethod
    def verify_link(cls, token):
        """Verify the token and return the email."""
        serializer = URLSafeTimedSerializer(cls.SECRET_KEY)
        try:
            email = serializer.loads(token, salt=cls.SALT, max_age=cls.EXPIRY_SECONDS)
            return email
        except SignatureExpired:
            raise ValueError("The verification link has expired.")
        except BadSignature:
            raise ValueError("Invalid verification link.")

    @classmethod
    def send_email_link(cls, email):
        """Send the email with the verification link."""
        link = cls._generate_link(email, 'email-verification')
        
        try:
            email_message = EmailMessage(
                subject="Verify Your Email",
                body=f"Hi {email},\n\nPlease verify your email using the following link: {link}\n\nThis link will expire in 10 minutes.",
                to=[email]
            )
            email_message.send()
            return True
        except Exception as e:
            return False
        
    @classmethod
    def send_password_reset_link(cls, email):
        link = cls._generate_link(email, 'password-reset')
        
        try:
            email_message = EmailMessage(
                subject="Reset Your Password",
                body=f"Hi {email},\n\nPlease reset your password using the following link: {link}\n\nThis link will expire in 10 minutes.",
                to=[email]
            )
            email_message.send()
            return True
        except Exception as e:
            return False
        
          
          
