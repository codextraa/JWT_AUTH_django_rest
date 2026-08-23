from rest_framework import serializers
from server.schema_serializers import SuccessBoolResponseSerializer


class CSRFTokenResponseSerializer(serializers.Serializer):  # pylint: disable=W0223
    """Standard CSRF token structure."""

    csrf_token = serializers.CharField(
        required=True,
        allow_null=False,
        allow_blank=False,
        help_text="The CSRF token to be used in subsequent requests.",
        error_messages={
            "required": "CSRF token is required.",
            "blank": "CSRF token is required.",
            "null": "CSRF token is required.",
        },
    )

    csrf_token_expiry = serializers.DateTimeField(
        required=True,
        allow_null=False,
        help_text="CSRF Token Expiry in ISO 8601 format",
        error_messages={
            "required": "CSRF expiration timestamp is required.",
            "null": "CSRF expiration timestamp is required.",
            "invalid": "CSRF expiration timestamp is invalid.",
        },
    )


class OTPResponseSerializer(SuccessBoolResponseSerializer):  # pylint: disable=W0223
    """OTP response structure."""

    pre_auth_token = serializers.CharField(
        required=True,
        allow_null=False,
        allow_blank=False,
        help_text="The raw pre-auth token to be used in subsequent requests.",
        error_messages={
            "required": "Raw pre-auth token is required.",
            "blank": "Raw pre-auth token is required.",
            "null": "Raw pre-auth token is required.",
        },
    )


class TokenResponseSerializer(CSRFTokenResponseSerializer):  # pylint: disable=W0223
    """Token response structure."""

    access_token = serializers.CharField(
        required=True,
        allow_null=False,
        allow_blank=False,
        help_text="The access token to be used in subsequent requests.",
        error_messages={
            "required": "Access token is required.",
            "blank": "Access token is required.",
            "null": "Access token is required.",
        },
    )

    refresh_token = serializers.CharField(
        required=True,
        allow_null=False,
        allow_blank=False,
        help_text="The refresh token to be used in subsequent requests.",
        error_messages={
            "required": "Refresh token is required.",
            "blank": "Refresh token is required.",
            "null": "Refresh token is required.",
        },
    )

    access_token_expiry = serializers.DateTimeField(
        required=True,
        allow_null=False,
        help_text="Access Token Expiry in ISO 8601 format",
        error_messages={
            "required": "Access token expiry is required.",
            "null": "Access token expiry is required.",
            "invalid": "Access token expiry is invalid.",
        },
    )

    user_id = serializers.IntegerField(
        required=True,
        allow_null=False,
        help_text="A unique identifier for the user.",
        error_messages={
            "required": "User ID is required.",
            "null": "User ID is required.",
            "invalid": "User ID is invalid.",
        },
    )

    user_role = serializers.CharField(
        required=True,
        allow_null=False,
        allow_blank=False,
        help_text="The role of the user in the system.",
        error_messages={
            "required": "User role is required.",
            "blank": "User role is required.",
            "null": "User role is required.",
        },
    )


class ReqChangePassResponseSerializer(
    SuccessBoolResponseSerializer
):  # pylint: disable=W0223
    """Request Change Password response structure."""

    pass_token = serializers.CharField(
        required=True,
        allow_null=False,
        allow_blank=False,
        help_text="The raw password token to be used in subsequent requests.",
        error_messages={
            "required": "Raw password token is required.",
            "blank": "Raw password token is required.",
            "null": "Raw password token is required.",
        },
    )
