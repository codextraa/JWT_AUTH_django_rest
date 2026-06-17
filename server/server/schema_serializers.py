from rest_framework import serializers


class SuccessResponseSerializer(serializers.Serializer):  # pylint: disable=W0223
    """Standard success response structure."""

    success = serializers.CharField(
        help_text="A descriptive success message explaining the success or status."
    )


class ErrorResponseSerializer(serializers.Serializer):  # pylint: disable=W0223
    """Standard error response structure."""

    error = serializers.CharField(
        help_text="A descriptive error message explaining the failure or status."
    )
