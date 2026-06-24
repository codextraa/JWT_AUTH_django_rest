from django.urls import reverse
from django.core.cache import cache
from django.contrib.auth import get_user_model
from rest_framework import status
from rest_framework.test import APITestCase, APIClient
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.token_blacklist.models import (
    BlacklistedToken,
    OutstandingToken,
)

User = get_user_model()


class RefreshViewTests(APITestCase):

    def setUp(self):
        self.client = APIClient(enforce_csrf_checks=True)

        self.url = reverse("logout")

        self.valid_payload = {
            "refresh_token": "mock_refresh_token",
        }

        csrf_url = reverse("csrf-token")
        response = self.client.get(csrf_url)
        token = response.data["csrf_token"]

        self.headers = {
            "HTTP_USER_AGENT": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
            "HTTP_X_REAL_IP": "192.168.1.1",
            "HTTP_X_CSRFTOKEN": token,
        }

    def tearDown(self):
        cache.clear()

    # ==========================================
    # SUCCESS TEST (200)
    # ==========================================

    def test_logout_success_without_valid_refresh_token(self):
        """Test logout with an invalid/expired token returns success."""
        initial_blacklist_count = BlacklistedToken.objects.count()

        response = self.client.post(self.url, data=self.valid_payload, **self.headers)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data, {"success": "Logged out successfully"})

        self.assertEqual(BlacklistedToken.objects.count(), initial_blacklist_count)

    # ==========================================
    # REQUEST SERIALIZER VALIDATION FAILURE (400)
    # ==========================================

    def test_missing_refresh_token(self):
        """Test 400 bad request when refresh token is missing."""
        payload = self.valid_payload.copy()
        del payload["refresh_token"]

        response = self.client.post(self.url, payload, format="json", **self.headers)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("refresh_token", response.data)
        self.assertEqual(response.data["refresh_token"][0], "Token is required.")

        payload["refresh_token"] = None

        response = self.client.post(self.url, payload, format="json", **self.headers)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("refresh_token", response.data)
        self.assertEqual(response.data["refresh_token"][0], "Token is required.")

        payload["refresh_token"] = ""

        response = self.client.post(self.url, payload, format="json", **self.headers)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("refresh_token", response.data)
        self.assertEqual(response.data["refresh_token"][0], "Token is required.")

    # ==========================================
    # CSRFTOKEN FAILURE TEST
    # ==========================================

    def test_logout_fails_when_csrf_token_is_missing(self):
        """Ensure the view rejects requests completely if CSRF is absent."""
        csrf_less_headers = {
            "HTTP_USER_AGENT": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
            "HTTP_X_REAL_IP": "192.168.1.1",
        }

        response = self.client.post(
            self.url, self.valid_payload, format="json", **csrf_less_headers
        )

        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)


class RefreshViewDBTests(APITestCase):

    def setUp(self):
        self.client = APIClient(enforce_csrf_checks=True)
        self.url = reverse("logout")

        csrf_url = reverse("csrf-token")
        response = self.client.get(csrf_url)
        self.csrf_token = response.data["csrf_token"]

        self.headers = {
            "HTTP_USER_AGENT": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
            "HTTP_X_REAL_IP": "192.168.1.1",
            "HTTP_X_CSRFTOKEN": self.csrf_token,
        }

        self.user = User.objects.create_user(
            email="defaultuser@example.com", password="SecurePassword123!"
        )

        self.real_refresh = RefreshToken.for_user(self.user)

        self.payload = {
            "refresh_token": str(self.real_refresh),
        }

    def tearDown(self):
        User.objects.all().delete()
        cache.clear()

    # ==========================================
    # SUCCESS TEST (200)
    # ==========================================

    def test_logout_success_with_valid_refresh_token(self):
        """Test successful logout with a valid refresh token."""
        # Ensure the token exists in outstanding tokens first
        self.assertTrue(
            OutstandingToken.objects.filter(token=str(self.real_refresh)).exists()
        )

        logout_response = self.client.post(self.url, data=self.payload, **self.headers)

        self.assertEqual(logout_response.status_code, status.HTTP_200_OK)
        self.assertEqual(logout_response.data, {"success": "Logged out successfully"})

        # Assert token is now blacklisted in the DB
        is_blacklisted = BlacklistedToken.objects.filter(
            token__token=str(self.real_refresh)
        ).exists()
        self.assertTrue(is_blacklisted)
