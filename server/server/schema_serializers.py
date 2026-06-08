from rest_framework import serializers


class CSRFTokenResponseSerializer(serializers.Serializer):  # pylint: disable=W0223
    """Standard CSRF token structure."""

    csrf_token = serializers.CharField(
        help_text="The CSRF token to be used in subsequent requests.",
    )
    csrf_token_expiry = serializers.DateTimeField(
        help_text="CSRF Token Expiry in ISO 8601 format",
    )


class ErrorResponseSerializer(serializers.Serializer):  # pylint: disable=W0223
    """Standard error response structure."""

    error = serializers.CharField(
        help_text="A descriptive error message explaining the failure or status."
    )
