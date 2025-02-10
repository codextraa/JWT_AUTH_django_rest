import os, io, json
from django.conf import settings
from django.urls import reverse
from django.contrib.auth import get_user_model
from django.core.cache import cache
from django.core.exceptions import ValidationError
from django.core.files.uploadedfile import SimpleUploadedFile
from PIL import Image
from rest_framework import status
from rest_framework.response import Response
from rest_framework.test import APITestCase, APIClient
from datetime import datetime, timedelta, timezone
from unittest.mock import patch, MagicMock


CSRF_TOKEN_URL = reverse('csrf-token')
RECAPTCHA_VERIFY_URL = reverse('recaptcha-verify')
LOGIN_URL = reverse('login')
TOKEN_USER_URL = reverse('token')
TOKEN_REFRESH_URL = reverse('token-refresh')
USER_URL = reverse('user-list')

def detail_url(user_id):
    """Create and return a user detail URL"""
    return reverse('user-detail', args=[user_id])

def image_upload_url(user_id):
    """Create and return a user image upload URL"""
    return reverse('user-upload-image', args=[user_id])

def deactivate_user_url(user_id):
    """Deactivate user URL"""
    return reverse('user-deactivate-user', args=[user_id])

def activate_user_url(user_id):
    """Activate user URL"""
    return reverse('user-activate-user', args=[user_id])

def create_user(**params):
    """Create and return a new user"""
    return get_user_model().objects.create_user(**params)

class CSRFTokenViewTests(APITestCase):
    """Test the CSRFTokenView"""
    
    def setUp(self):
        self.client = APIClient()
    
    def test_get_csrf_token_success(self):
        """
        Test that the view successfully returns a CSRF token and expiry.
        """
        response = self.client.get(CSRF_TOKEN_URL)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('csrf_token', response.data)
        self.assertIn('csrf_token_expiry', response.data)

        # Validate the expiry is a valid datetime and is in the future (approximately 1 day)
        try:
            expiry = datetime.fromisoformat(response.data['csrf_token_expiry'].replace('Z', '+00:00'))  # Handle the Z for timezone
        except ValueError:
            self.fail("csrf_token_expiry is not a valid datetime format")

        now = datetime.now(timezone.utc)
        expected_expiry_min = now + timedelta(days=0.9)
        expected_expiry_max = now + timedelta(days=1.1)  # Give a bit of leeway

        self.assertTrue(expected_expiry_min <= expiry <= expected_expiry_max, "Expiry is not approximately 1 day from now")

        # Validate that the csrf token is not empty:
        self.assertTrue(len(response.data['csrf_token']) > 0)

    @patch('auth_api.views.get_token')
    def test_get_csrf_token_internal_server_error(self, mock_get_token):
        """
        Test that the view returns a 500 error when get_token raises an exception.
        """
        mock_get_token.side_effect = Exception("Simulated error")  # Simulate an error
        response = self.client.get(CSRF_TOKEN_URL)

        self.assertEqual(response.status_code, status.HTTP_500_INTERNAL_SERVER_ERROR)
        self.assertIn('error', response.data)
        self.assertEqual(response.data['error'], "Simulated error")

class RecaptchaValidationViewTests(APITestCase):
    """Test the RecaptchaValidationView"""
    
    def setUp(self):
        self.client = APIClient()
    
    @patch('auth_api.views.requests.post')
    def test_recaptcha_validation_success(self, mock_post):
        """
        Test that the view returns a success message when reCAPTCHA validation is successful.
        """
        mock_post.return_value.json.return_value = {'success': True}
        mock_post.return_value.status_code = 200

        data = {'recaptcha_token': 'valid_token'}
        response = self.client.post(RECAPTCHA_VERIFY_URL, data, format='json')

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('success', response.data)
        self.assertEqual(response.data['success'], 'reCAPTCHA validation successful.')

    @patch('auth_api.views.requests.post')
    def test_recaptcha_validation_failure(self, mock_post):
        """
        Test that the view returns an error message when reCAPTCHA validation fails.
        """
        mock_post.return_value.json.return_value = {'success': False}
        mock_post.return_value.status_code = 200


        data = {'recaptcha_token': 'invalid_token'}
        response = self.client.post(RECAPTCHA_VERIFY_URL, data, format='json')

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('error', response.data)
        self.assertEqual(response.data['error'], 'Invalid reCAPTCHA token.')

    @patch('auth_api.views.requests.post')
    def test_recaptcha_validation_invalid_json(self, mock_post):
        """
        Test that the view returns an error message when the reCAPTCHA service returns invalid JSON.
        """
        mock_post.return_value.json.side_effect = json.JSONDecodeError("Simulated JSON error", "doc", 0)
        mock_post.return_value.status_code = 200

        data = {'recaptcha_token': 'some_token'}
        response = self.client.post(RECAPTCHA_VERIFY_URL, data, format='json')

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('error', response.data)
        self.assertEqual(response.data['error'], 'Invalid JSON.')

    @patch('auth_api.views.requests.post')
    def test_recaptcha_validation_internal_server_error(self, mock_post):
        """
        Test that the view returns a 500 error when an unexpected exception occurs.
        """
        mock_post.side_effect = Exception("Simulated internal server error")

        data = {'recaptcha_token': 'some_token'}
        response = self.client.post(RECAPTCHA_VERIFY_URL, data, format='json')

        self.assertEqual(response.status_code, status.HTTP_500_INTERNAL_SERVER_ERROR)
        self.assertIn('error', response.data)
        self.assertIn("Simulated internal server error", response.data['error'])

class LoginViewTests(APITestCase):
    """Test the LoginView"""

    def setUp(self):
        self.url = LOGIN_URL
        self.User = get_user_model()
        self.test_user = self.User.objects.create_user(
            email='test@example.com',
            password='TestP@ssw0rd',
            is_active=True,
            is_email_verified=True
        )
        self.client = APIClient()
        
    def tearDown(self):
        cache.clear()

    @patch('auth_api.views.create_otp')
    def test_login_success(self, mock_create_otp):
        """
        Test successful login returns 200 OK and the expected data.
        """
        # Return a proper Response object instead of a MagicMock
        mock_create_otp.return_value = Response(
            {'success': 'Email sent', 'otp': True, 'user_id': self.test_user.id},
            status=status.HTTP_200_OK
        )

        data = {'email': 'test@example.com', 'password': 'TestP@ssw0rd'}
        response = self.client.post(self.url, data, format='json')

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['success'], 'Email sent')
        self.assertEqual(response.data['otp'], True)
        self.assertEqual(response.data['user_id'], self.test_user.id)

    def test_login_missing_credentials(self):
        """
        Test that missing email or password returns 400 Bad Request.
        """
        data = {'email': 'test@example.com'}  # Missing password
        response = self.client.post(self.url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('error', response.data)
        self.assertEqual(response.data['error'], "Email and password are required")

        data = {'password': 'TestP@ssw0rd'}  # Missing email
        response = self.client.post(self.url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('error', response.data)
        self.assertEqual(response.data['error'], "Email and password are required")

    def test_login_invalid_email(self):
        """
        Test that invalid credentials (wrong password) return 400 Bad Request.
        """
        data = {'email': 'test2@example.com', 'password': 'TestP@ssw0rd'}
        response = self.client.post(self.url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('error', response.data)
        self.assertEqual(response.data['error'], "Invalid credentials")
        
    def test_login_invalid_credentials(self):
        """
        Test that invalid credentials (wrong password) return 400 Bad Request.
        """
        data = {'email': 'test@example.com', 'password': 'wrongpassword'}
        response = self.client.post(self.url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('error', response.data)
        self.assertEqual(response.data['error'], "Invalid credentials")

    def test_login_unverified_email(self):
        """Test case for login with unverified email."""
        # Create a test user with an unverified email address
        unverified_user = self.User.objects.create_user(
            email='unverified@example.com',
            password='TestP@ssw0rd',
            is_active=True,
            is_email_verified=False  # Set is_verified to False
        )

        data = {'email': 'unverified@example.com', 'password': 'TestP@ssw0rd'}
        response = self.client.post(self.url, data, format='json')
        
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)  # Or whatever status code you return
        self.assertIn('error', response.data)
        self.assertEqual(response.data['error'], "Email is not verified. You must verify your email first")

    def test_login_inactive_account(self):
        """Test case for login with an inactive account."""
        # Create a test user with an inactive account
        inactive_user = self.User.objects.create_user(
            email='inactive@example.com',
            password='TestP@ssw0rd',
            is_active=False,  # Set is_active to False
            is_email_verified=True
        )

        data = {'email': 'inactive@example.com', 'password': 'TestP@ssw0rd'}
        response = self.client.post(self.url, data, format='json')
        
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)  # Or whatever status code you return
        self.assertIn('error', response.data)
        self.assertEqual(response.data['error'], "Account is deactivated. Contact your admin")
        
    def test_login_auth_not_email(self):
        """Test case for login with an inactive account."""
        # Create a test user with an inactive account
        diff_auth_user = self.User.objects.create_user(
            email='diffauth@example.com',
            password='TestP@ssw0rd',
            is_active=False,  # Set is_active to False
            is_email_verified=True,
            auth_provider='google'
        )

        data = {'email': 'diffauth@example.com', 'password': 'TestP@ssw0rd'}
        response = self.client.post(self.url, data, format='json')
        
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)  # Or whatever status code you return
        self.assertIn('error', response.data)
        self.assertEqual(response.data['error'], f"This process cannot be used, as user is created using {diff_auth_user.auth_provider}")

    @patch('auth_api.views.EmailOtp.send_email_otp')
    def test_login_otp_failure_bad_request(self, mock_send_email):
        """
        Test that if sending the OTP email fails (i.e., EmailOtp.send_email_otp returns False),
        the LoginView returns a 400 Bad Request with the expected error message.
        """
        # Arrange: simulate the failure of sending the OTP email by returning False.
        mock_send_email.return_value = False

        data = {'email': 'test@example.com', 'password': 'TestP@ssw0rd'}
        # Act: perform a POST request to the login view.
        response = self.client.post(self.url, data, format='json')

        # Assert: verify that the view returns a 400 response and the correct error message.
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('error', response.data)
        self.assertEqual(
            response.data['error'],
            "Something went wrong, could not send OTP. Try again"
        )
    
    @patch('auth_api.views.create_otp')
    def test_login_otp_failure(self, mock_create_otp):
        """
        Test that a failure during OTP creation returns 500 Internal Server Error.
        """
        mock_create_otp.side_effect = Exception("Simulated OTP creation error")

        data = {'email': 'test@example.com', 'password': 'TestP@ssw0rd'}
        response = self.client.post(self.url, data, format='json')

        self.assertEqual(response.status_code, status.HTTP_500_INTERNAL_SERVER_ERROR)
        self.assertIn('error', response.data)
        self.assertIn("Simulated OTP creation error", response.data['error']) # Verify the error message

    @patch('auth_api.views.create_otp')
    def test_login_internal_server_error(self, mock_create_otp):
        """
        Test for a generic internal server error within the view.
        """
        # Simulate an internal error in create_otp.
        mock_create_otp.side_effect = Exception("Simulated Internal Server Error")

        data = {'email': 'test@example.com', 'password': 'TestP@ssw0rd'}
        response = self.client.post(self.url, data, format='json')

        self.assertEqual(response.status_code, status.HTTP_500_INTERNAL_SERVER_ERROR)
        self.assertIn('error', response.data)
        self.assertIn("Simulated Internal Server Error", response.data['error'])

    @patch('auth_api.views.check_user_validity')
    def test_login_throttled(self, mock_check_user_validity):
        """
        Test that the login view is throttled after exceeding the rate limit,
        considering the caching mechanism.
        """

        mock_check_user_validity.return_value = self.test_user
        data = {'email': 'test@example.com', 'password': 'TestP@ssw0rd'}

        # ** Crucial: Seed the cache for the throttle to work
        cache.set(f"id_{self.test_user.id}", self.test_user.id, timeout=60)

        # Make the first request (should succeed)
        response1 = self.client.post(self.url, data, format='json')
        self.assertEqual(response1.status_code, status.HTTP_200_OK)

        # Make the second request immediately (should be throttled)
        response2 = self.client.post(self.url, data, format='json')
        self.assertEqual(response2.status_code, status.HTTP_429_TOO_MANY_REQUESTS)
        self.assertIn('detail', response2.data)

class PublicUserApiTests(APITestCase):
    """Test the public feature of user API"""
    
    def setUp(self):
        self.client = APIClient()
        
    def test_create_user_success(self):
        """Test creating a user is successful"""
        payload = {
            'email': 'test@example.com',
            'password': 'Django@123',
            'c_password': 'Django@123'
        }

        res = self.client.post(USER_URL, payload, format='json')
        self.assertEqual(res.status_code, status.HTTP_201_CREATED)
        user = get_user_model().objects.get(email=payload['email'])
        self.assertTrue(user.check_password(payload['password']))
        self.assertNotIn('password', res.data)

        default_image_path = 'profile_images/default_profile.jpg'
        self.assertEqual(user.profile_img.name, default_image_path)

