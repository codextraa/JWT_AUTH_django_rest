from datetime import datetime, timezone, timedelta
from django.conf import settings
from django.middleware.csrf import get_token
from django.core.cache import cache
from django.contrib.auth import get_user_model, authenticate
from django.views.decorators.csrf import csrf_protect
from django.utils.decorators import method_decorator
from rest_framework import status
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import AllowAny
from rest_framework.throttling import ScopedRateThrottle
from rest_framework.exceptions import ValidationError, Throttled
from rest_framework_simplejwt.tokens import RefreshToken
from drf_spectacular.utils import extend_schema, OpenApiResponse, OpenApiExample

from server.renderers import ViewRenderer
from server.utils.exception import ForbiddenValidationError
from server.utils.recaptcha import verify_recaptcha_token
from server.utils.encryption import generate_cache_key
from server.utils.throttle import OTPCooldownThrottle
from server.schema_serializers import (
    SuccessResponseSerializer,
    ErrorResponseSerializer,
)
from .utils import get_user_role, create_otp
from .validation_serializers import ValidUserSerializer
from .request_serializers import RecaptchaRequestSerializer, LoginRequestSerializer
from .response_serializers import (
    CSRFTokenResponseSerializer,
    OTPResponseSerializer,
    TokenResponseSerializer,
)


class CSRFTokenView(APIView):
    """CSRF Token View."""

    permission_classes = [AllowAny]
    renderer_classes = [ViewRenderer]

    @extend_schema(
        summary="Get CSRF Token",
        description="Returns a CSRF token along with its expiration time.",
        tags=["Authentication"],
        request=None,
        responses={
            status.HTTP_200_OK: OpenApiResponse(
                response=CSRFTokenResponseSerializer,
                description="CSRF token returned",
            ),
            status.HTTP_400_BAD_REQUEST: OpenApiResponse(
                response=ErrorResponseSerializer,
                description=("Bad Request - Invalid request parameters"),
            ),
            status.HTTP_500_INTERNAL_SERVER_ERROR: OpenApiResponse(
                response=ErrorResponseSerializer,
                description="Internal Server Error.",
            ),
        },
        examples=[
            OpenApiExample(
                name="Sucess",
                response_only=True,
                status_codes=["200"],
                value={
                    "csrf_token": "9b2c8e3a1f7d6e4c0a5b2f8e3d1c4a9b-CSRFToken",
                    "csrf_token_expiry": "2023-01-01T00:00:00Z",
                },
            ),
            OpenApiExample(
                name="Bad Request",
                response_only=True,
                status_codes=["400"],
                value={"error": "Invalid request parameters"},
            ),
            OpenApiExample(
                name="Internal Server Error",
                response_only=True,
                status_codes=["500"],
                value={"error": "Internal Server Error"},
            ),
        ],
    )
    def get(self, request, *args, **kwargs):
        """Get Method for CSRF Token."""
        try:
            csrf_token = get_token(request)
            csrf_token_expiry = (
                datetime.now(timezone.utc)
                + timedelta(seconds=settings.CSRF_TOKEN_TTL)
                - timedelta(seconds=10)
            )

            raw_data = {
                "csrf_token": csrf_token,
                "csrf_token_expiry": csrf_token_expiry,
            }

            serializer = CSRFTokenResponseSerializer(data=raw_data)

            serializer.is_valid(raise_exception=True)

            return Response(serializer.data, status=status.HTTP_200_OK)
        except Exception as e:  # pylint: disable=W0718
            if isinstance(e, ValidationError):
                raise e
            return Response(
                {"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class RecaptchaValidationView(APIView):
    """Recaptcha Validation View."""

    permission_classes = [AllowAny]
    renderer_classes = [ViewRenderer]

    @extend_schema(
        summary="Validate reCAPTCHA",
        description="Validates the provided reCAPTCHA token with Google's reCAPTCHA service.",
        tags=["Authentication"],
        request=RecaptchaRequestSerializer,
        responses={
            status.HTTP_200_OK: OpenApiResponse(
                response=SuccessResponseSerializer,
                description="reCAPTCHA validation successful",
            ),
            status.HTTP_400_BAD_REQUEST: OpenApiResponse(
                response=ErrorResponseSerializer,
                description=("Bad Request - Invalid request parameters"),
            ),
            status.HTTP_403_FORBIDDEN: OpenApiResponse(
                response=ErrorResponseSerializer,
                description=("Forbidden - reCAPTCHA validation failed"),
            ),
            status.HTTP_500_INTERNAL_SERVER_ERROR: OpenApiResponse(
                response=ErrorResponseSerializer,
                description="Internal Server Error.",
            ),
        },
        examples=[
            OpenApiExample(
                name="Sucess",
                response_only=True,
                status_codes=["200"],
                value={
                    "success": "reCAPTCHA validation successful.",
                },
            ),
            OpenApiExample(
                name="Action Missing",
                response_only=True,
                status_codes=["400"],
                value={"errors": {"expected_action": ["Action is required."]}},
            ),
            OpenApiExample(
                name="Missing reCAPTCHA Token",
                response_only=True,
                status_codes=["400"],
                value={"errors": {"recaptcha_token": ["Missing reCAPTCHA token."]}},
            ),
            OpenApiExample(
                name="Missing reCAPTCHA Version",
                response_only=True,
                status_codes=["400"],
                value={"errors": {"recaptcha_version": ["Missing reCAPTCHA version."]}},
            ),
            OpenApiExample(
                name="Missing User Agent",
                response_only=True,
                status_codes=["400"],
                value={"errors": {"user_agent": ["Missing User Agent Header."]}},
            ),
            OpenApiExample(
                name="Missing User IP Address",
                response_only=True,
                status_codes=["400"],
                value={"errors": {"user_ip": ["Missing User IP Address."]}},
            ),
            OpenApiExample(
                name="Invalid reCAPTCHA Token",
                response_only=True,
                status_codes=["403"],
                value={"error": "Invalid token reason: Invalid"},
            ),
            OpenApiExample(
                name="Action Mismatch",
                response_only=True,
                status_codes=["403"],
                value={"error": "Action mismatch. Expected 'login', got 'signup'"},
            ),
            OpenApiExample(
                name="Low Score",
                response_only=True,
                status_codes=["403"],
                value={"error": "High risk transaction blocked. Score: 0.3"},
            ),
            OpenApiExample(
                name="Internal Server Error",
                response_only=True,
                status_codes=["500"],
                value={"error": "Internal Server Error"},
            ),
        ],
    )
    @method_decorator(csrf_protect)
    def post(self, request, *args, **kwargs):
        """Post a request to validate reCAPTCHA.
        Returns a response with success or error message."""
        try:
            serializer = RecaptchaRequestSerializer(
                data=request.data, context={"request": request}
            )

            serializer.is_valid(raise_exception=True)

            validated_data = serializer.validated_data

            is_human, message = verify_recaptcha_token(
                token=validated_data["recaptcha_token"],
                expected_action=validated_data["expected_action"],
                recaptcha_version=validated_data["recaptcha_version"],
                user_ip_address=validated_data["user_ip"],
                user_agent=validated_data["user_agent"],
            )

            if not is_human:
                return Response(
                    {"error": message},
                    status=status.HTTP_403_FORBIDDEN,
                )

            return Response({"success": message}, status=status.HTTP_200_OK)
        except Exception as e:  # pylint: disable=W0718
            if isinstance(e, ValidationError):
                raise e
            return Response(
                {"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class LoginView(APIView):
    """Login View."""

    permission_classes = [AllowAny]
    renderer_classes = [ViewRenderer]
    throttle_classes = [OTPCooldownThrottle, ScopedRateThrottle]
    throttle_scope = "email_otp"

    def handle_exception(self, exc):
        if isinstance(exc, Throttled):
            return Response(
                {
                    "error": (
                        f"Please wait {exc.wait} seconds before"
                        " requesting another OTP."
                    )
                },
                status=status.HTTP_429_TOO_MANY_REQUESTS,
            )

        return super().handle_exception(exc)

    @extend_schema(
        summary="Login to get an OTP",
        description=(
            "Authenticates the user with email and password. "
            "If valid, an OTP is sent to the registered email."
        ),
        request=LoginRequestSerializer,
    )
    @method_decorator(csrf_protect)
    def post(self, request, *args, **kwargs):  # pylint: disable=R0911
        """Post a request to login. Returns an OTP or JWTTokens to the registered email."""
        try:
            req_serializer = LoginRequestSerializer(
                data=request.data, context={"request": request}
            )

            req_serializer.is_valid(raise_exception=True)

            req_validated_data = req_serializer.validated_data

            is_human, message = verify_recaptcha_token(
                token=req_validated_data["recaptcha_token"],
                expected_action="login",
                recaptcha_version=req_validated_data["recaptcha_version"],
                user_ip_address=req_validated_data["user_ip"],
                user_agent=req_validated_data["user_agent"],
            )

            if not is_human:
                return Response(
                    {"error": message},
                    status=status.HTTP_403_FORBIDDEN,
                )

            user = authenticate(
                request=request,
                username=req_validated_data["email_or_username"],
                password=req_validated_data["password"],
            )

            valid_serializer = ValidUserSerializer(
                data={}, context={"user": user, "request": request}
            )

            valid_serializer.is_valid(raise_exception=True)

            validated_user = valid_serializer.validated_data["user"]

            if validated_user.is_two_fa:
                otp_success = create_otp(user.id, req_validated_data["user_ip"])
                if not otp_success.get("success"):
                    return Response(
                        {
                            "error": "Something went wrong, could not send OTP. Try again"
                        },
                        status=status.HTTP_424_FAILED_DEPENDENCY,
                    )

                otp_res_serializer = OTPResponseSerializer(data=otp_success)

                otp_res_serializer.is_valid(raise_exception=True)

                hashed_user_key = generate_cache_key(validated_user.id)
                cache.delete(f"login_failures:{hashed_user_key}")

                return Response(otp_res_serializer.data, status=status.HTTP_200_OK)
            else:
                refresh = RefreshToken.for_user(validated_user)
                access_token_expiry = (
                    datetime.now(timezone.utc)
                    + timedelta(seconds=settings.ACCESS_TOKEN_TTL)
                    - timedelta(seconds=10)
                ).isoformat()

                csrf_token = get_token(request)
                csrf_token_expiry = (
                    datetime.now(timezone.utc)
                    + timedelta(seconds=settings.CSRF_TOKEN_TTL)
                    - timedelta(seconds=10)
                )

                raw_data = {
                    "refresh_token": str(refresh),
                    "access_token": str(refresh.access_token),
                    "access_token_expiry": access_token_expiry,
                    "user_id": validated_user.id,
                    "user_role": get_user_role(validated_user),
                    "csrf_token": csrf_token,
                    "csrf_token_expiry": csrf_token_expiry,
                }

                token_res_serializer = TokenResponseSerializer(data=raw_data)

                token_res_serializer.is_valid(raise_exception=True)

                hashed_user_key = generate_cache_key(validated_user.id)
                cache.delete(f"login_failures:{hashed_user_key}")

                return Response(token_res_serializer.data, status=status.HTTP_200_OK)
        except Exception as e:  # pylint: disable=W0718
            if isinstance(e, ValidationError) or isinstance(
                e, ForbiddenValidationError
            ):
                raise e
            return Response(
                {"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
