from rest_framework import serializers


class CSRFTokenResponseSerializer(serializers.Serializer):  # pylint: disable=W0223
    """Standard CSRF token structure."""

    csrf_token = serializers.CharField(
        help_text="The CSRF token to be used in subsequent requests.",
        error_messages={
            "required": "CSRF token value generation failed.",
            "blank": "Generated CSRF token cannot be empty.",
            "null": "Generated CSRF token cannot be null.",
        },
    )
    csrf_token_expiry = serializers.DateTimeField(
        help_text="CSRF Token Expiry in ISO 8601 format",
        error_messages={
            "required": "CSRF expiration tracking context is required.",
            "invalid": "Invalid expiration timestamp format produced.",
            "null": "Generated CSRF token cannot be null.",
        },
    )


# class OTPSuccessResponse(serializers.Serializer):  # pylint: disable=W0223
#     success = serializers.CharField(
#         help_text="A descriptive message indicating the success of the operation."
#     )
#     otp = serializers.BooleanField(
#         help_text="A boolean value indicating whether OTP is sent in email or not."
#     )
#     user_id = serializers.IntegerField(help_text="A unique identifier for the user.")


# class TokenSuccessResponse(serializers.Serializer):  # pylint: disable=W0223
#     access_token = serializers.CharField(
#         help_text="The access token to be used in subsequent requests.",
#     )
#     refresh_token = serializers.CharField(
#         help_text="The refresh token to be used in subsequent requests.",
#     )
#     access_token_expiry = serializers.DateTimeField(
#         help_text="Access Token Expiry in ISO 8601 format",
#     )
#     user_id = serializers.IntegerField(
#         help_text="A unique identifier for the user.",
#     )
#     user_role = serializers.CharField(
#         help_text="The role of the user in the system.",
#     )
#     csrf_token = serializers.CharField(
#         help_text="The CSRF token to be used in subsequent requests.",
#     )
#     csrf_token_expiry = serializers.DateTimeField(
#         help_text="CSRF Token Expiry in ISO 8601 format.",
#     )
