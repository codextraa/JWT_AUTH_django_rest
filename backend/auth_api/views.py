"""Views for Auth API."""
import requests, json
from datetime import datetime, timezone, timedelta
from rest_framework import status
from rest_framework.viewsets import ModelViewSet
from rest_framework.views import APIView
from rest_framework.permissions import AllowAny, IsAuthenticated, IsAdminUser
from rest_framework.throttling import ScopedRateThrottle
from rest_framework.response import Response
from rest_framework.decorators import action
from rest_framework.parsers import MultiPartParser, FormParser
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView
from rest_framework_simplejwt.exceptions import InvalidToken, TokenError
from django_filters.rest_framework import DjangoFilterBackend
from drf_spectacular.utils import extend_schema, OpenApiResponse, OpenApiParameter
from django.conf import settings
from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group
from django.core.cache import cache
from django.utils.timezone import now
from django.middleware.csrf import get_token
from django.utils.decorators import method_decorator
from django.views.decorators.csrf import csrf_protect, csrf_exempt
from social_django.utils import load_backend, load_strategy
from social_core.exceptions import AuthException
from .renderers import ViewRenderer
from .paginations import UserPagination
from .filters import UserFilter
from .utils import (
    EmailOtp,
    EmailLink,
    PhoneOtp
)
from .serializers import (
    UserSerializer,
    UserImageSerializer,
    UserListSerializer,
    UserActionSerializer,
    LoginSerializer,
    LogoutSerializer,
    ResendOtpSerializer,
    TokenRequestSerializer,
    PhoneVerificationSerializer,
    PasswordResetSerializer,
    VerificationThroughEmailSerializer,
    InputPasswordResetSerializer,
    SocialOAuthSerializer
)


def check_token_validity(request):
    token = request.query_params.get('token')
    expiry = request.query_params.get('expiry')
    
    if not token or not expiry:
        return Response({"error": "Invalid or missing verification link."}, status=status.HTTP_400_BAD_REQUEST)
    
    expiry_time = datetime.fromtimestamp(int(expiry), tz=timezone.utc)
    
    if datetime.now(timezone.utc) > expiry_time:
        return Response({"error": "The verification link has expired."}, status=status.HTTP_400_BAD_REQUEST)
    
    try:
        email = EmailLink.verify_link(token)
    except ValueError as e:
        return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)
    
    return email
    
def check_user_validity(email):
    user = get_user_model().objects.filter(email=email).first()
        
    # Check if user exists
    if not user:
        return Response({"error": "Invalid credentials"}, status=status.HTTP_400_BAD_REQUEST)
    
    if user.auth_provider != 'email':
        return Response({"error": f"This process cannot be used, as user is created using {user.auth_provider}"}, status=status.HTTP_400_BAD_REQUEST)
    
    # Check if user is email verified
    if not user.is_email_verified:
        return Response({"error": "Email is not verified. You must verify your email first"}, status=status.HTTP_400_BAD_REQUEST)
    
    # Check if user is active
    if not user.is_active:
        return Response({"error": "Account is deactivated. Contact your admin"}, status=status.HTTP_400_BAD_REQUEST)
    
    return user

def get_user_role(user):
    """Get user role."""
    user_groups = user.groups.all()
    
    if user_groups.filter(name='Default').exists():
        user_role = 'Default'
    elif user_groups.filter(name='Admin').exists():
        user_role = 'Admin'
    elif user_groups.filter(name='Superuser').exists():
        user_role = 'Superuser'
    else:
        user_role = 'UnAuthorized'
        
    return user_role

def check_user_id(user_id):
    """Check if user id exists."""
    if not user_id:
        return Response({"error": "Session expired. Please login again."}, status=status.HTTP_400_BAD_REQUEST)
    
    try:
        user_id = int(user_id)
    except ValueError:
        return Response({"error": "Invalid Session"}, status=status.HTTP_400_BAD_REQUEST)
    
    user = get_user_model().objects.filter(id=user_id).first()
    
    if not user:
        return Response({"error": "Invalid Session"}, status=status.HTTP_400_BAD_REQUEST)
    
    return check_user_validity(user.email)

def create_otp(user_id, email, password):
    # Generate OTP
    otp = EmailOtp.generate_otp()
    otp_email = EmailOtp.send_email_otp(email, otp)
    
    # Check if the email was sent
    if otp_email:
        # Setting the cache data
        cache.set(f"id_{user_id}", user_id, timeout=60) # Cache id for 1 minute (used for email verification)
        cache.set(f"otp_{user_id}", otp, timeout=600) # Cache otp for 1 minute (used for otp verification)
        cache.set(f"email_{user_id}", email, timeout=600) # Cache email for 10 minutes (used for otp verification)
        cache.set(f"password_{user_id}", password, timeout=600)  # Store password in cache for verification
        return Response({"success": "Email sent", "otp": True, "user_id": user_id}, status=status.HTTP_200_OK)
    else:
        return Response({"error": "Something went wrong, could not send OTP. Try again", "otp": False}, status=status.HTTP_400_BAD_REQUEST)

def check_throttle_duration(self, request):
    """
    Check duration for throttling
    """
    throttle_durations = []
    for throttle in self.get_throttles():
        if not throttle.allow_request(request, self):
            throttle_durations.append(throttle.wait())
            
    return throttle_durations

def start_throttle(self, throttle_durations, request):
    # Filter out `None` values which may happen in case of config / rate
    # changes, see #1438
    durations = [
        duration for duration in throttle_durations
        if duration is not None
    ]

    duration = max(durations, default=None)
    self.throttled(request, duration)
    
class CSRFTokenView(APIView):
    permission_classes = [AllowAny]
    renderer_classes = [ViewRenderer]
    
    def get(self, request, *args, **kwargs):
        csrf_token = get_token(request)
        csrf_token_expiry = datetime.now(timezone.utc) + timedelta(days=1)
        return Response({"csrf_token": csrf_token, "csrf_token_expiry": csrf_token_expiry.isoformat()}, status=status.HTTP_200_OK)
    
class RecaptchaValidationView(APIView):
    permission_classes = [AllowAny]
    renderer_classes = [ViewRenderer]
    
    @method_decorator(csrf_exempt)
    def post(self, request, *args, **kwargs):
        try:
            recaptcha_token = request.data.get('recaptcha_token')
            
            recaptcha_response = requests.post(
                'https://www.google.com/recaptcha/api/siteverify',
                data={
                    'secret': settings.RECAPTCHA_SECRET_KEY,
                    'response': recaptcha_token
                }
            )
            result = recaptcha_response.json()
            
            if result.get('success'):
                return Response({'success': 'reCAPTCHA validation successful.'}, status=status.HTTP_200_OK)
            else:
                return Response({'error': 'Invalid reCAPTCHA token.'}, status=status.HTTP_400_BAD_REQUEST)
        except json.JSONDecodeError:
            return Response({'error': 'Invalid JSON.'}, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class LoginView(APIView):
    """Login to get an otp."""
    permission_classes = [AllowAny]
    renderer_classes = [ViewRenderer]
    throttle_classes = [ScopedRateThrottle]
    throttle_scope = 'email_otp'
    
    def check_throttles(self, request):
        """
        Check if request should be throttled.
        Raises an appropriate exception if the request is throttled.
        """
        throttle_durations = check_throttle_duration(self, request)
                
        user = get_user_model().objects.filter(email=request.data.get('email')).first()
        
        if user:
            cached_id = cache.get(f"id_{user.id}")
        else:
            cached_id = None

        if throttle_durations and cached_id:
            start_throttle(self, throttle_durations, request)

    @extend_schema(
        request=LoginSerializer,
        responses={
            200: OpenApiResponse(
                description="Email sent",
                response={
                    "type": "object",
                    "properties": {
                        "success": {"type": "string", "example": "Email sent"}
                    }
                }
            ),
            400: OpenApiResponse(
                description="Error response",
                response={
                    "type": "object",
                    "properties": {
                        "error": {"type": "string", "example": "Invalid credentials"}
                    }
                }
            ),
        }
    )
    @method_decorator(csrf_protect)
    def post(self, request, *args, **kwargs):
        # Get email and password
        email = request.data.get('email')
        password = request.data.get('password')
        
        if not email or not password:
            return Response({"error": "Email and password are required"}, status=status.HTTP_400_BAD_REQUEST)
        
        user = check_user_validity(email)
        
        if isinstance(user, Response):
            return user
        
        # Check if password is correct
        if not user.check_password(password):
            return Response({"error": "Invalid credentials"}, status=status.HTTP_400_BAD_REQUEST)
        
        # Generate OTP
        response = create_otp(user.id, email, password)
        
        return response
    
class ResendOtpView(APIView):
    """Resend OTP."""
    permission_classes = [AllowAny]
    renderer_classes = [ViewRenderer]
    throttle_classes = [ScopedRateThrottle]
    throttle_scope = 'email_otp'
    
    def check_throttles(self, request):
        """
        Check if request should be throttled.
        Raises an appropriate exception if the request is throttled.
        """
        throttle_durations = check_throttle_duration(self, request)
                
        cached_id = cache.get(f"id_{request.data.get('user_id')}")

        if throttle_durations and cached_id:
            start_throttle(self, throttle_durations, request)
    
    @extend_schema(
        request=ResendOtpSerializer,
        responses={
            200: OpenApiResponse(
                description="Email sent",
                response={
                    "type": "object",
                    "properties": {
                        "success": {"type": "string", "example": "Email sent"},
                        "otp": {"type": "boolean", "example": True},
                        "user_id": {"type": "integer", "example": 1}
                    },
                },
            ),
            400: OpenApiResponse(
                description="Error response",
                response={
                    "type": "object",
                    "properties": {
                        "error": {"type": "string", "example": "Invalid credentials"}
                    }
                }
            ),
        }
    )
    @method_decorator(csrf_protect)
    def post(self, request, *args, **kwargs):
        # Get email and password
        user_id = request.data.get('user_id')
        
        user = check_user_id(user_id)
        
        if isinstance(user, Response):
            return user
        
        email = cache.get(f"email_{user.id}")
        password = cache.get(f"password_{user.id}")
        
        if not email or not password:
            return Response({"error": "Session expired. Please login again."}, status=status.HTTP_400_BAD_REQUEST)
        
        # Generate OTP
        response = create_otp(user.id, email, password)
        
        return response
    
class TokenView(TokenObtainPairView):
    """Generate token after OTP verification."""
    renderer_classes = [ViewRenderer]

    @extend_schema(
        request=TokenRequestSerializer,
        responses={
            200: OpenApiResponse(
                description="Token response",
                response={
                    "type": "object",
                    "properties": {
                        "access": {"type": "string", "example": "JWT access token"},
                        "refresh": {"type": "string", "example": "JWT refresh token"},
                        "user_role": {"type": "string", "example": "Admin"},
                        "user_id": {"type": "integer", "example": 1},
                    }
                }
            ),
            400: OpenApiResponse(
                description="Error response",
                response={
                    "type": "object",
                    "properties": {
                        "error": {"type": "string", "example": "Invalid OTP"}
                    }
                }
            ),
        }
    )
    @method_decorator(csrf_protect)
    def post(self, request, *args, **kwargs):
        # Get OTP from the request
        user_id = request.data.get("user_id")
        otp_from_request = request.data.pop("otp", None)
        
        user = check_user_id(user_id)
        
        if isinstance(user, Response):
            return Response({"error": "Invalid Session"}, status=status.HTTP_400_BAD_REQUEST)
        
        # Verify OTP
        otp_verify = EmailOtp.verify_otp(user.id, otp_from_request)
        
        if not otp_verify:
            return Response({"error": "Invalid OTP"}, status=status.HTTP_400_BAD_REQUEST)

        # Get email and password from the cache
        email = cache.get(f"email_{user.id}")
        password = cache.get(f"password_{user.id}")

        if not email or not password:
            return Response({"error": "Session expired. Please login again."}, status=status.HTTP_400_BAD_REQUEST)

        # Set email and password in the request
        request.data['email'] = email
        request.data['password'] = password
        
        # Generate token
        response = super().post(request, *args, **kwargs)
        
        response.data['access_token_expiry'] = (now() + timedelta(minutes=5)).isoformat()
        
        cache.delete(f"email_{user.id}")
        cache.delete(f"password_{user.id}")
        
        user_role = get_user_role(user)
        
        response.data['user_role'] = user_role
        response.data['user_id'] = user.id
        response.data['access_token'] = response.data['access']
        response.data['refresh_token'] = response.data['refresh']
        response.data.pop('access')
        response.data.pop('refresh')

        return response
    
class RefreshTokenView(TokenRefreshView):
    renderer_classes = [ViewRenderer]
    
    @method_decorator(csrf_protect)
    def post(self, request, *args, **kwargs):
        # Call the parent method to get the response
        try:
            refresh_token = request.data.get("refresh")
            
            if not refresh_token:
                return Response({"error": "Tokens are required"}, status=status.HTTP_400_BAD_REQUEST)
            
            response = super().post(request, *args, **kwargs)
            response.data['access_token_expiry'] = (now() + timedelta(minutes=5)).isoformat()

            # Extract the access token and refresh token
            refresh_token = response.data.get("refresh")
            access_token = response.data.get("access")

            if not refresh_token or not access_token:
                return Response({"error": "Invalid tokens"}, status=status.HTTP_400_BAD_REQUEST)

            # Decode the access token to extract user details
            decoded_token = RefreshToken(refresh_token)
            user_id = decoded_token.get('user_id', None)
            if not user_id:
                raise InvalidToken("Invalid refresh token")
                
            # Fetch the user from the database
            user = get_user_model().objects.get(id=user_id)
            
            user_role = get_user_role(user)
            
            response.data['user_role'] = user_role
            response.data['user_id'] = user.id
            response.data['access_token'] = response.data['access']
            response.data['refresh_token'] = response.data['refresh']
            response.data.pop('access')
            response.data.pop('refresh')
            
            return response
        except TokenError as e:
            return Response({'error': str(e)}, status=400)
    
class EmailVerifyView(APIView):
    """View for verifying user's email address after registration."""
    permission_classes = [AllowAny]
    renderer_classes = [ViewRenderer]
    throttle_classes = [ScopedRateThrottle]
    throttle_scope = "email_verify"
    
    def check_throttles(self, request):
        """
        Check if request should be throttled.
        Raises an appropriate exception if the request is throttled.
        """
        throttle_durations = check_throttle_duration(self, request)
                
        cached_email = cache.get(f"email_{request.data.get('email')}")

        if throttle_durations and cached_email and request.method == "POST":
            start_throttle(self, throttle_durations, request)
    
    @extend_schema(
        description="This endpoint verifies the user's email address using a token and expiry time sent during registration.",
        parameters=[
            OpenApiParameter(
                name="token",
                description="The unique token for email verification, sent to the user's email.",
                required=True,
                type=str,
                location=OpenApiParameter.QUERY,
            ),
            OpenApiParameter(
                name="expiry",
                description="The expiry timestamp for the verification link (in seconds since the epoch).",
                required=True,
                type=int,
                location=OpenApiParameter.QUERY,
            ),
        ],
        responses={
            200: OpenApiResponse(
                description="Email verification successful",
                response={
                    "type": "object",
                    "properties": {
                        "success": {
                            "type": "string",
                            "example": "Email verified successfully",
                        }
                    },
                },
            ),
            400: OpenApiResponse(
                description="Invalid or expired token or user not found",
                response={
                    "type": "object",
                    "properties": {
                        "error": {
                            "type": "string",
                            "examples": [
                                "Invalid or missing verification link.",
                                "The verification link has expired.",
                                "Invalid token",
                                "User not found",
                            ],
                        }
                    },
                },
            ),
        },
    )
    def get(self, request, *args, **kwargs):
        """Email Link Verification"""
        email = check_token_validity(request)

        if isinstance(email, Response):
            return email
        
        user = get_user_model().objects.filter(email=email).first()
        
        # Check if user exists
        if not user:
            return Response({"error": "Invalid credentials"}, status=status.HTTP_400_BAD_REQUEST)
        
        user.is_active = True
        user.is_email_verified = True
        user.save()
        
        return Response({"success": "Email verified successfully"}, status=status.HTTP_200_OK)
    
    @extend_schema(
        request=VerificationThroughEmailSerializer,  # Use the VerificationThroughEmailSerializer for email input
        responses={
            201: OpenApiResponse(
                description="Verification link sent successfully",
                response={
                    "type": "object",
                    "properties": {
                        "success": {
                            "type": "string",
                            "example": "Verification link sent. Please verify your email to activate your account.",
                        }
                    },
                },
            ),
            400: OpenApiResponse(
                description="Invalid email address or user not found",
                response={
                    "type": "object",
                    "properties": {
                        "error": {
                            "type": "string",
                            "examples": [
                                "Invalid email address",
                                "User not found",
                            ],
                        }
                    },
                },
            ),
            500: OpenApiResponse(
                description="Failed to send email verification link",
                response={
                    "type": "object",
                    "properties": {
                        "error": {
                            "type": "string",
                            "example": "Failed to send email verification link.",
                        }
                    },
                },
            ),
        },
        description="Sends an email verification link to the user with a token.",
        operation_id="send_email_verification_link"
    )
    @method_decorator(csrf_protect)
    def post(self, request, *args, **kwargs):
        email = request.data.get("email")
        
        user = get_user_model().objects.filter(email=email).first()

        # Check if user exists
        if not user:
            return Response({"error": "Invalid credentials"}, status=status.HTTP_400_BAD_REQUEST)
        
        if user.auth_provider != 'email':
            return Response({"error": f"This process cannot be used, as user is created using {user.auth_provider}"}, status=status.HTTP_400_BAD_REQUEST)
        
        if user.is_email_verified:
            return Response({"error": "Email already verified"}, status=status.HTTP_400_BAD_REQUEST)
        
        email_sent = EmailLink.send_email_link(email)
        
        if not email_sent:
            return Response(
                {"error": "Failed to send email verification link."},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
        
        cache.set(f"email_{email}", email, timeout=60) # Cache email for 10 minutes
        
        return Response(
            {"success": "Verification link sent. Please verify your email to activate your account."},
            status=status.HTTP_201_CREATED
        )
    
class PhoneVerifyView(APIView):
    """View for verifying user's phone number after registration."""
    permission_classes = [IsAuthenticated]
    renderer_classes = [ViewRenderer]
    throttle_classes = [ScopedRateThrottle]
    throttle_scope = 'phone_otp'
    
    def check_throttles(self, request):
        """
        Check if request should be throttled.
        Raises an appropriate exception if the request is throttled.
        """
        throttle_durations = check_throttle_duration(self, request)

        if throttle_durations and request.method == "POST":
            start_throttle(self, throttle_durations, request)
    
    @extend_schema(
        request=None,
        responses={
            200: OpenApiResponse(description="OTP sent successfully"),
            400: OpenApiResponse(description="Failed to send OTP"),
        },
        operation_id="send_otp",
        description="Sends OTP to the user's phone number."
    )
    @method_decorator(csrf_protect)
    def post(self, request, *args, **kwargs):
        user = request.user
        email = user.email
        phone = user.phone_number
        
        otp_sent = PhoneOtp.send_otp(email, str(phone))
        
        if otp_sent:
            return Response({"success": "OTP sent successfully"}, status=status.HTTP_200_OK)
        else:
            return Response({"error": "Failed to send OTP"}, status=status.HTTP_400_BAD_REQUEST)
    
    @extend_schema(
        request=PhoneVerificationSerializer,  # Use the PhoneVerificationSerializer for OTP input
        responses={
            200: OpenApiResponse(description="Phone verified successfully"),
            400: OpenApiResponse(description="Invalid OTP"),
        },
        operation_id="verify_otp",
        description="Verifies the OTP provided by the user."
    )
    @method_decorator(csrf_protect)
    def patch(self, request, *args, **kwargs):
        otp = request.data.get("otp")
        
        if not otp:
            return Response({"error": "OTP is required"}, status=status.HTTP_400_BAD_REQUEST)

        user = request.user
        phone_number = user.phone_number
        
        otp_verified = PhoneOtp.verify_otp(phone_number, otp)
        
        if otp_verified:
            user.is_phone_verified = True
            user.save()
            return Response({"success": "Phone verified successfully"}, status=status.HTTP_200_OK)
        else:
            return Response({"error": "Invalid OTP"}, status=status.HTTP_400_BAD_REQUEST)
    
class PasswordResetView(APIView):
    """View for resetting user's password."""
    permission_classes = [AllowAny]
    renderer_classes = [ViewRenderer]
    throttle_classes = [ScopedRateThrottle]
    throttle_scope = 'password_reset'
    
    def check_throttles(self, request):
        """
        Check if request should be throttled.
        Raises an appropriate exception if the request is throttled.
        """
        throttle_durations = check_throttle_duration(self, request)
                
        cached_email = cache.get(f"email_{request.data.get('email')}")

        if throttle_durations and cached_email and request.method == "POST":
            start_throttle(self, throttle_durations, request)
    
    @extend_schema(
        operation_id="password_reset_verify_link",
        description="Verify the token and expiry provided in the query parameters to validate the password reset link.",
        parameters=[
            OpenApiParameter(
                name="token",
                description="The unique token for password reset verification.",
                required=True,
                type=str,
                location=OpenApiParameter.QUERY,
            ),
            OpenApiParameter(
                name="expiry",
                description="The expiry timestamp for the password reset link.",
                required=True,
                type=str,
                location=OpenApiParameter.QUERY,
            ),
        ],
        responses={
            200: OpenApiResponse(
                description="Password reset link verified successfully.",
                response={"type": "object", "properties": {"success": {"type": "string", "example": "Password verification link ok"}}},
            ),
            400: OpenApiResponse(
                description="Invalid or expired password reset link.",
                response={"type": "object", "properties": {"error": {"type": "string", "example": "The verification link has expired."}}},
            ),
        },
    )
    def get(self, request, *args, **kwargs):
        """Email Link Verification"""
        email = check_token_validity(request)
        
        if isinstance(email, Response):
            return email
        
        return Response({"success": "Password verification link ok"}, status=status.HTTP_200_OK)
    
    @extend_schema(
        operation_id="password_reset_request",
        description="Send a password reset link to the user's email address if it is verified and active.",
        request=VerificationThroughEmailSerializer,
        responses={
            201: OpenApiResponse(
                description="Password reset link sent successfully.",
                response={"type": "object", "properties": {"success": {"type": "string", "example": "Password reset link sent. Please check your email to reset your password."}}},
            ),
            400: OpenApiResponse(
                description="User not found or email not verified.",
                response={"type": "object", "properties": {"error": {"type": "string", "example": "User doesn't exist"}}},
            ),
            500: OpenApiResponse(
                description="Failed to send password reset link.",
                response={"type": "object", "properties": {"error": {"type": "string", "example": "Failed to send password reset link."}}},
            ),
        },
    )
    @method_decorator(csrf_protect)
    def post(self, request, *args, **kwargs):
        """Password Reset"""
        email = request.data.get('email')
        
        user = check_user_validity(email)
        
        if isinstance(user, Response):
            return user
        
        email_sent = EmailLink.send_password_reset_link(user.email)
        
        if not email_sent:
            return Response(
                {"error": "Failed to send password reset link."},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
        
        cache.set(f"email_{user.email}", user.email, timeout=60) # Cache email for 10 minutes
        
        return Response(
            {"success": "Password reset link sent. Please check your email to reset your password."},
            status=status.HTTP_201_CREATED
        )
    
    @extend_schema(
        operation_id="password_reset",
        description="Reset the user's password using the provided token, expiry, and new password. Both passwords must match.",
        parameters=[
            OpenApiParameter(
                name="token",
                description="The unique token for password reset verification.",
                required=True,
                type=str,
                location=OpenApiParameter.QUERY,
            ),
            OpenApiParameter(
                name="expiry",
                description="The expiry timestamp for the password reset link.",
                required=True,
                type=str,
                location=OpenApiParameter.QUERY,
            ),
        ],
        request=InputPasswordResetSerializer,
        responses={
            200: OpenApiResponse(
                description="Password reset successful.",
                response={"type": "object", "properties": {"success": {"type": "string", "example": "Password reset successful"}}},
            ),
            400: OpenApiResponse(
                description="Invalid or mismatched passwords, or user not valid.",
                response={"type": "object", "properties": {"error": {"type": "string", "example": "Passwords do not match"}}},
            ),
        },
    )
    @method_decorator(csrf_protect)
    def patch(self, request, *args, **kwargs):
        """Password Reset"""
        email = check_token_validity(request)

        if isinstance(email, Response):
            return email
        
        user = check_user_validity(email)
        
        if isinstance(user, Response):
            return user
        
        password = request.data.get('password')
        c_password = request.data.get('c_password')
        
        if password != c_password:
            return Response({"error": "Passwords do not match"}, status=status.HTTP_400_BAD_REQUEST)
        
        # password reset serializer
        serializer = PasswordResetSerializer(instance=user, data={"password": password})
        
        if not serializer.is_valid():
            return Response({"error": serializer.errors}, status=status.HTTP_400_BAD_REQUEST)
        
        serializer.save()
        
        return Response({"success": "Password reset successful."}, status=status.HTTP_200_OK)
        
class UserViewSet(ModelViewSet):
    """Viewset for User APIs."""
    queryset = get_user_model().objects.all() # get all the users
    serializer_class = UserSerializer # User Serializer initialized
    authentication_classes = [JWTAuthentication] # Using jwtoken
    throttle_classes = [ScopedRateThrottle]
    throttle_scope = 'email_verify'
    renderer_classes = [ViewRenderer]
    filter_backends = [DjangoFilterBackend]
    filterset_class = UserFilter
    pagination_class = UserPagination

    def get_permissions(self):
        """Permission for CRUD operations."""
        if self.action == 'create': # No permission while creating user
            permission_classes = [AllowAny]
        elif self.action == 'deactivate_user': # Only Admins are allowed
            permission_classes = [IsAuthenticated]
        elif (self.action == 'activate_user' or self.action == 'delete'): # Only Admins are allowed
            permission_classes = [IsAuthenticated, IsAdminUser]
        else: # RUD operations need permissions
            permission_classes = [IsAuthenticated]
        return [permission() for permission in permission_classes]

    def get_serializer_class(self):
        """Return the serializer class for the action."""
        if self.action == "list": # List of users handled with different serializer
            return UserListSerializer
        if self.action == "deactivate_user" or self.action == "activate_user": # Deactivation handled with different serializer
            return UserActionSerializer
        if self.action == "upload_image": # Image handled with different serializer
            return UserImageSerializer
        return super().get_serializer_class()
    
    def check_throttles(self, request):
        """
        Check if request should be throttled.
        Raises an appropriate exception if the request is throttled.
        """
        throttle_durations = check_throttle_duration(self, request)
                
        cached_email = cache.get(f"email_{request.data.get('email')}")

        if throttle_durations and cached_email and request.method == "POST":
            start_throttle(self, throttle_durations, request)
    
    @method_decorator(csrf_protect)
    def create(self, request, *args, **kwargs):
        """Create new user and send email verification link."""
        current_user = self.request.user
        
        if ('is_superuser' in request.data):
            return Response(
                {"error": "You do not have permission to create a superuser. Contact Developer."},
                status=status.HTTP_403_FORBIDDEN,
            )
        
        if ('is_staff' in request.data and not current_user.is_superuser):
            return Response(
                {"error": "You do not have permission to create an admin user."},
                status=status.HTTP_403_FORBIDDEN,
            )
            
        password = request.data.get('password')
        if not request.data.get('c_password'):
            return Response({"error": "Please confirm your password."}, status=status.HTTP_400_BAD_REQUEST)
            
        c_password = request.data.pop('c_password')
        if password != c_password:
            return Response({"error": "Passwords do not match"}, status=status.HTTP_400_BAD_REQUEST)
            
        request.data['is_active'] = False
        response = super().create(request, *args, **kwargs)
        
        if response.status_code != status.HTTP_201_CREATED:
            return response
        
        # Send email verification link
        user = get_user_model().objects.get(email=response.data["email"])
        email_sent = EmailLink.send_email_link(user.email)
        
        if not email_sent:
            return Response(
                {"error": "Failed to send email verification link."},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
        
        cache.set(f"email_{user.email}", user.email, timeout=60) # Cache email for 10 minutes
        
        return Response(
            {"success": "User created successfully. Please verify your email to activate your account."},
            status=status.HTTP_201_CREATED
        )
        

    @method_decorator(csrf_protect)
    def update(self, request, *args, **kwargs):
        """Allow only users to update their own profile. SuperUser can do anything."""
        current_user = self.request.user
        user = self.get_object()
        
        if 'email' in request.data:
            return Response(
                {"error": "You cannot update the email field."},
                status=status.HTTP_403_FORBIDDEN
            )
        
        if ('password' in request.data or 'c_password' in request.data):
            return Response(
                {"error": "Password reset cannot be done without verification link."},
                status=status.HTTP_403_FORBIDDEN
            )
            
        if 'profile_img' in request.data:
            return Response(
                {"error": "To update Profile Image, use the Upload Profile button."},
                status=status.HTTP_403_FORBIDDEN
            )

        if ('is_active' in request.data or 'is_staff' in request.data 
            or 'is_superuser' in request.data):
            return Response(
                {"error": "You cannot update the is_active, is_staff or is_superuser field."},
                status=status.HTTP_403_FORBIDDEN
            )

        if current_user.id != user.id and not current_user.is_superuser:
            return Response(
                {"error": "You do not have permission to update this user."},
                status=status.HTTP_403_FORBIDDEN,
            )

        response = super().update(request, *args, **kwargs)
        
        if response.status_code == status.HTTP_200_OK:
            return Response({"success": "User profile updated successfully."}, status=status.HTTP_200_OK)
        
        return response

    @method_decorator(csrf_protect)
    def destroy(self, request, *args, **kwargs):
        """Allow only superusers to delete normal or staff users and clean up profile image."""
        current_user = self.request.user
        user_to_delete = self.get_object()

        if not current_user.is_superuser:
            return Response(
                {"error": "Only superusers can delete users."},
                status=status.HTTP_403_FORBIDDEN,
            )
            
        if user_to_delete.is_active:
            return Response(
                {"error": "You must deactivate the user before deleting it."},
                status=status.HTTP_403_FORBIDDEN,
            )

        if user_to_delete.is_superuser:
            return Response(
                {"error": "You cannot delete superusers"},
                status=status.HTTP_403_FORBIDDEN,
            )

        # Check and delete the profile image if it's not the default image
        default_image_path = 'profile_images/default_profile.jpg'
        if user_to_delete.profile_img and user_to_delete.profile_img.name != default_image_path:
            user_to_delete.profile_img.delete(save=False)

        email = user_to_delete.email
        response = super().destroy(request, *args, **kwargs)
        
        if response.status_code == status.HTTP_204_NO_CONTENT:
            return Response({"success": f"User {email} deleted successfully."}, status=status.HTTP_200_OK)
        
        return response

    @extend_schema(
        operation_id="upload_user_image",
        description="Upload an image for the user's profile",
        request={
            "multipart/form-data": {
                "type": "object",
                "properties": {
                    "profile_img": {
                        "type": "string",
                        "format": "binary",
                        "description": "The image file to upload"
                    }
                }
            }
        },
        responses={200: UserSerializer},
    )
    @method_decorator(csrf_protect)
    @action(detail=True, methods=['PATCH'], url_path='upload-image', parser_classes=[MultiPartParser, FormParser])  # detail=True is only for a single user
    def upload_image(self, request, pk=None):
        """Update user profile image"""
        print(request.data)
        user = self.get_object()  # get the user
        current_user = self.request.user  # Get the user making the request

        # Ensure the request is made by the user themselves or a superuser
        if current_user.id != user.id and not current_user.is_superuser:
            return Response(
                {"error": "You do not have permission to upload an image for this user."},
                status=status.HTTP_403_FORBIDDEN,
            )
            
        default_image_path = 'profile_images/default_profile.jpg'  # Define the default image path

        # Check if the user has an existing image that is not the default image
        if user.profile_img and user.profile_img.name != default_image_path:
            # Remove the previous image file
            user.profile_img.delete(save=False)
        
        serializer = self.get_serializer(
            user,
            data=request.data,
            partial=True  # Only updating profile_img
        )
        serializer.is_valid(raise_exception=True)  # returns 400 if fails
        serializer.save()

        return Response({"success": "Image uploaded successfully."}, status=status.HTTP_200_OK)

    @method_decorator(csrf_protect)
    @action(detail=True, methods=['PATCH'], url_path='deactivate-user')
    def deactivate_user(self, request, pk=None):
        """Deactivate a user (only staff and superuser can do to other users)"""
        user_to_deactivate = self.get_object()
        current_user = self.request.user

        if not user_to_deactivate.is_active:
            return Response(
                {"error": "User is already deactivated."},
                status=status.HTTP_400_BAD_REQUEST
            )

        if not (current_user.is_superuser or current_user.is_staff):
            if user_to_deactivate != current_user:
                return Response(
                    {"error": "You do not have permission to deactivate users."},
                    status=status.HTTP_403_FORBIDDEN
                )

        if user_to_deactivate == current_user and current_user.is_staff:
            if current_user.is_superuser:
                detail = "You cannot deactivate yourself as a superuser."
            else:
                detail = "You cannot deactivate yourself as a staff. Contact a superuser"

            return Response(
                {"error": detail},
                status=status.HTTP_403_FORBIDDEN
            )

        if user_to_deactivate.is_staff and not current_user.is_superuser:
            return Response(
                {"error": "Only superusers can deactivate staff users."},
                status=status.HTTP_403_FORBIDDEN
            )

        if user_to_deactivate.is_superuser:
            return Response(
                {"error": "You cannot deactivate a superuser."},
                status=status.HTTP_403_FORBIDDEN
            )
        
        user_to_deactivate.is_active = False
        user_to_deactivate.save()

        return Response(
            {"success": f"User {user_to_deactivate.email} has been deactivated."},
            status=status.HTTP_200_OK,
        )

    @method_decorator(csrf_protect)
    @action(detail=True, methods=['PATCH'], url_path='activate-user')
    def activate_user(self, request, pk=None):
        """Activate a user (only staff and superuser can do this)"""
        user_to_activate = self.get_object()
        current_user = self.request.user

        if user_to_activate.is_active:
            return Response(
                {"error": "User is not deactivated."},
                status=status.HTTP_400_BAD_REQUEST
            )

        if not (current_user.is_superuser or current_user.is_staff):
            return Response(
                {"error": "You do not have permission to activate users."},
                status=status.HTTP_403_FORBIDDEN
            )

        if user_to_activate == current_user:
            return Response(
                {"error": "You cannot activate yourself."},
                status=status.HTTP_403_FORBIDDEN
            )

        if user_to_activate.is_staff and not current_user.is_superuser:
            return Response(
                {"error": "Only superusers can activate staff users."},
                status=status.HTTP_403_FORBIDDEN
            )

        user_to_activate.is_active = True
        user_to_activate.save()

        return Response(
            {"success": f"User {user_to_activate.email} has been reactivated."},
            status=status.HTTP_200_OK,
        )

class LogoutView(APIView):
    """
    Logout by blacklisting the refresh token.
    """
    permission_classes = [AllowAny]
    renderer_classes = [ViewRenderer]

    @extend_schema(
        request=LogoutSerializer,
        responses={
            200: OpenApiResponse(
                description="Logout successful",
                response={
                    "type": "object",
                    "properties": {
                        "success": {"type": "string", "example": "Logged out successfully"}
                    }
                }
            ),
            400: OpenApiResponse(
                description="Invalid request",
                response={
                    "type": "object",
                    "properties": {
                        "error": {"type": "string", "example": "Invalid token"}
                    }
                }
            ),
        }
    )
    @method_decorator(csrf_protect)
    def post(self, request, *args, **kwargs):
        try:
            # Extract tokens from the request
            refresh_token = request.data.get("refresh")

            if not refresh_token:
                return Response({"error": "Tokens are required"}, status=status.HTTP_400_BAD_REQUEST)

            # Blacklist refresh token
            token = RefreshToken(refresh_token)
            token.blacklist()

            return Response({"success": "Logged out successfully"}, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)
        
class SocialAuthView(APIView):
    permission_classes = [AllowAny]
    renderer_classes = [ViewRenderer]

    @extend_schema(
        request=SocialOAuthSerializer,
        responses={
            200: OpenApiResponse(
                description="Login successful",
                response={
                    "type": "object",
                    "properties": {
                        "success": {"type": "string", "example": "Logged in successfully"}
                    }
                }
            ),
        }
    )
    @method_decorator(csrf_protect)
    def post(self, request, *args, **kwargs):
        token = request.data.get("token")
        provider = request.data.get("provider")
        if not token or not provider:
            return Response({"error": "Token and provider are required"}, status=400)

        try:
            # Load social auth backend dynamically
            strategy = load_strategy(request)
            backend = load_backend(strategy, provider, redirect_uri=None)
            user = backend.do_auth(token)
            
            if isinstance(user, Response):
                return user
            
            if not user.is_active:
                return Response({"error": "Account is deactivated. Contact your admin."}, status=400)
            
            if user:
                # Generate JWT tokens for the authenticated user
                refresh = RefreshToken.for_user(user)
                access_token_expiry = (now() + timedelta(minutes=5)).isoformat()
                user_role = get_user_role(user)
                
                return Response({
                    "access_token": str(refresh.access_token),
                    "refresh_token": str(refresh),
                    "access_token_expiry": access_token_expiry,
                    "user_role": user_role,
                    "user_id": user.id
                }, status=200)
            else:
                return Response({"error": "Authentication failed"}, status=400)
        except AuthException as e:
            return Response({"error": str(e)}, status=400)
        except Exception as e:
            return Response({"error": str(e)}, status=400)
        