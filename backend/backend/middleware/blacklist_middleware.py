from django.core.cache import cache
from django.http import JsonResponse
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework.exceptions import AuthenticationFailed

class BlacklistAccessTokenMiddleware:
    """
    Middleware to check if the access token is blacklisted.
    """

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        auth_header = request.META.get('HTTP_AUTHORIZATION', '')
        if auth_header.startswith('Bearer '):
            token = auth_header.split(' ')[1]
            if cache.get(f"blacklisted_access_token_{token}"):
                return JsonResponse(
                    {"errors": "Access token has been revoked."},
                    status=401
                )
        return self.get_response(request)