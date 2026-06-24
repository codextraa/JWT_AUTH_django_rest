from django.urls import reverse
from django.core.cache import cache
from django.contrib.auth import get_user_model
from rest_framework import status
from rest_framework.test import APITestCase, APIClient
from rest_framework_simplejwt.tokens import RefreshToken

User = get_user_model()


class RefreshViewTests(APITestCase):

    def setUp(self):
        self.client = APIClient(enforce_csrf_checks=True)

        self.url = reverse("refresh")

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
    # UNAUTHORIZED VALIDATION (401)
    # ==========================================

    def test_invalid_refresh_token(self):
        """Test 401 unauthorized when refresh token is invalid."""
        payload = self.valid_payload.copy()

        response = self.client.post(self.url, payload, format="json", **self.headers)

        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
        error_msg = str(response.data["error"])
        self.assertEqual(
            error_msg,
            "Token is invalid or expired",
        )

    # ==========================================
    # CSRFTOKEN FAILURE TEST
    # ==========================================

    def test_refresh_fails_when_csrf_token_is_missing(self):
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
        self.url = reverse("refresh")

        csrf_url = reverse("csrf-token")
        response = self.client.get(csrf_url)
        self.csrf_token = response.data["csrf_token"]

        self.headers = {
            "HTTP_USER_AGENT": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
            "HTTP_X_REAL_IP": "192.168.1.1",
            "HTTP_X_CSRFTOKEN": self.csrf_token,
        }

        self.user = User.objects.create_user(
            email="defaultuser@example.com",
            password="SecurePassword123!",
            auth_provider="google",
            is_email_verified=True,
            is_active=True,
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

    def test_refresh_token_success(self):
        """Test successful token rotation with a valid, live refresh token."""
        refresh_response = self.client.post(self.url, data=self.payload, **self.headers)

        self.assertEqual(refresh_response.status_code, status.HTTP_200_OK)

        expected_keys = [
            "refresh_token",
            "access_token",
            "access_token_expiry",
            "user_id",
            "user_role",
            "csrf_token",
            "csrf_token_expiry",
        ]
        for key in expected_keys:
            self.assertIn(key, refresh_response.data)
            self.assertIsNotNone(refresh_response.data[key])

        self.assertEqual(refresh_response.data["user_id"], self.user.id)

        new_refresh_token = refresh_response.data["refresh_token"]
        self.assertNotEqual(self.real_refresh, new_refresh_token)

        # Check whether the blacklisted token is no longer valid
        second_response = self.client.post(self.url, data=self.payload, **self.headers)

        self.assertEqual(second_response.status_code, status.HTTP_401_UNAUTHORIZED)
        error_msg = str(second_response.data["error"])
        self.assertEqual(
            error_msg,
            "Token is invalid or expired",
        )

    # ==========================================
    # USER STATE VALIDATION (403)
    # ==========================================

    def test_refresh_token_fails_user_not_active(self):
        """Test that the view raises a validation error if the user is deactivated."""
        self.user.is_active = False
        self.user.save()

        response = self.client.post(self.url, data=self.payload, **self.headers)

        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
        error_msg = str(response.data["error"])
        self.assertEqual(
            error_msg,
            "Account has been deactivated. Contact your admin",
        )

    def test_refresh_token_fails_email_not_verified(self):
        """Test that rotation is blocked if the user's email verification status flag is dropped."""
        self.user.is_email_verified = False
        self.user.save()

        response = self.client.post(self.url, data=self.payload, **self.headers)

        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
        error_msg = str(response.data["error"])
        self.assertEqual(
            error_msg,
            "Email is not verified. You must verify your email first",
        )

    # ==========================================
    # UNAUTHORIZED VALIDATION (401)
    # ==========================================

    def test_refresh_token_fails_user_does_not_exist(self):
        """Test that validation fails gracefully if the user model entry is deleted from the database entirely."""
        self.user.delete()

        response = self.client.post(self.url, data=self.payload, **self.headers)

        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
        error_msg = str(response.data["error"])
        self.assertEqual(
            error_msg,
            "User does not exist",
        )
