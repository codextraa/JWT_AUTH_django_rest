import os, io, json
from django.conf import settings
from django.urls import reverse
from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group
from django.core.cache import cache
from django.core.exceptions import ValidationError
from django.core.files.uploadedfile import SimpleUploadedFile
from django.utils.timezone import now, timedelta
from PIL import Image
from rest_framework import status
from rest_framework.response import Response
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.token_blacklist.models import BlacklistedToken, OutstandingToken
from rest_framework.test import APITestCase, APIClient
from datetime import datetime, timedelta, timezone
from unittest.mock import patch


CSRF_TOKEN_URL = reverse('csrf-token')
RECAPTCHA_VERIFY_URL = reverse('recaptcha-verify')
LOGIN_URL = reverse('login')
RESEND_OTP_URL = reverse('resend-otp')
TOKEN_USER_URL = reverse('token')
TOKEN_REFRESH_URL = reverse('token-refresh')
VERIFY_EMAIL_URL = reverse('email-verify')
VERIFY_PHONE_URL = reverse('phone-verify')
RESET_PASSWORD_URL = reverse('password-reset')
USER_URL = reverse('user-list')
SOCIAL_LOGIN_URL = reverse('social-auth')
LOGOUT_URL = reverse('logout')

def generate_otp():
    return 123456

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
       
class ResendOtpViewTests(APITestCase): 
    """Test the ResendOtpView"""

    def setUp(self):
        self.client = APIClient()
        self.url = RESEND_OTP_URL
        self.User = get_user_model()
        self.test_user = self.User.objects.create_user(
            email='test@example.com',
            password='TestP@ssw0rd', # Hash the password!
            is_active=True,
            is_email_verified=True, # Use is_email_verified
            auth_provider='email'  # Add auth_provider
        )
        self.user_id = self.test_user.id

        # Cache user data to simulate a valid session
        cache.set(f"id_{self.user_id}", self.user_id, timeout=60)
        cache.set(f"email_{self.user_id}", 'test@example.com', timeout=600)
        cache.set(f"password_{self.user_id}", 'TestP@ssw0rd', timeout=600)

        self.client.force_login(self.test_user) # Log in the client for consistent testing

    def tearDown(self):
        cache.clear()  # Clear cache after each test

    @patch('auth_api.views.create_otp')
    @patch('auth_api.views.check_user_id')
    def test_resend_otp_success(self, mock_check_user_id, mock_create_otp):
        """
        Test successful OTP resend returns 200 OK and the expected data.
        """
        mock_check_user_id.return_value = self.test_user # Mock successful check_user_id
        mock_create_otp.return_value = Response(
            {'success': 'Email sent', 'otp': True, 'user_id': self.test_user.id},
            status=status.HTTP_200_OK
        )

        data = {'user_id': self.user_id}
        response = self.client.post(self.url, data, format='json')

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['success'], 'Email sent')
        self.assertEqual(response.data['otp'], True)
        self.assertEqual(response.data['user_id'], self.user_id)

    def test_resend_otp_missing_user_id(self):
        """
        Test that missing user_id returns 400 Bad Request.
        """
        data = {}  # Missing user_id
        response = self.client.post(self.url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('error', response.data)

    @patch('auth_api.views.check_user_id')
    def test_resend_otp_invalid_user_id(self, mock_check_user_id):
        """
        Test that invalid user_id returns 400 Bad Request.
        """
        mock_check_user_id.return_value = Response({"error": "Invalid Session"}, status=status.HTTP_400_BAD_REQUEST) # Mock an invalid user ID error

        data = {'user_id': 999}  # Nonexistent user_id
        response = self.client.post(self.url, data, format='json')

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('error', response.data)
        self.assertEqual(response.data['error'], 'Invalid Session') # Specific error check

    def test_resend_otp_expired_session(self):
        """
        Test that an expired session returns 400 Bad Request.
        """
        # Clear cache to simulate expired session
        cache.clear()

        data = {'user_id': self.user_id}
        response = self.client.post(self.url, data, format='json')

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('error', response.data)
        self.assertIn("Session expired. Please login again.", response.data['error'])

    @patch('auth_api.views.check_user_id')
    def test_resend_otp_check_user_id_failure(self, mock_check_user_id):
        """
        Test that if check_user_id fails, a 400 Bad Request is returned.
        """
        mock_check_user_id.return_value = Response({"error": "Account is deactivated. Contact your admin"}, status=status.HTTP_400_BAD_REQUEST)

        data = {'user_id': self.user_id}
        response = self.client.post(self.url, data, format='json')

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('error', response.data)
        self.assertIn("Account is deactivated. Contact your admin", response.data['error'])

    @patch('auth_api.views.create_otp')
    @patch('auth_api.views.check_user_id')
    def test_resend_otp_create_otp_failure(self, mock_check_user_id, mock_create_otp):
        """
        Test that a failure during OTP creation returns 400 Bad Request.
        """
        mock_check_user_id.return_value = self.test_user  # Ensure check_user_id succeeds
        mock_create_otp.return_value = Response({"error": "Something went wrong, could not send OTP. Try again", "otp": False}, status=status.HTTP_400_BAD_REQUEST)

        data = {'user_id': self.user_id}
        response = self.client.post(self.url, data, format='json')

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('error', response.data)
        self.assertEqual(response.data['error'], "Something went wrong, could not send OTP. Try again")

    @patch('auth_api.views.create_otp')
    def test_resend_otp_internal_server_error(self, mock_create_otp):
        """
        Test for a generic internal server error within the view.
        """
        # Simulate an error condition within the view's post method.
        mock_create_otp.side_effect = Exception("Simulated Internal Server Error")
        
        data = {'user_id': self.user_id}
        response = self.client.post(self.url, data, format='json')

        self.assertEqual(response.status_code, status.HTTP_500_INTERNAL_SERVER_ERROR)
        self.assertIn('error', response.data)
        self.assertIn("Simulated Internal Server Error", response.data['error']) # Validate error message

    @patch('auth_api.views.check_user_id')
    def test_resend_otp_throttled(self, mock_check_user_id):
        """
        Test that the resend OTP view is throttled after exceeding the rate limit.
        """
        mock_check_user_id.return_value = self.test_user

        data = {'user_id': self.user_id}

        # ** Crucial: Seed the cache for the throttle to work
        cache.set(f"id_{self.test_user.id}", self.test_user.id, timeout=60)

        # Make the first request (should succeed)
        response1 = self.client.post(self.url, data, format='json')
        self.assertEqual(response1.status_code, status.HTTP_200_OK)

        # Make the second request immediately (should be throttled)
        response2 = self.client.post(self.url, data, format='json')
        self.assertEqual(response2.status_code, status.HTTP_429_TOO_MANY_REQUESTS)
        self.assertIn('detail', response2.data)

    @patch('auth_api.views.check_user_id')
    def test_resend_otp_invalid_cache_data(self, mock_check_user_id):
        """
        Test that an expired session due to missing cache data returns 400 Bad Request.
        """
        mock_check_user_id.return_value = self.test_user

        # Clear only email and password, leave id to pass check_throttles
        cache.delete(f"email_{self.user_id}")
        cache.delete(f"password_{self.user_id}")

        data = {'user_id': self.user_id}
        response = self.client.post(self.url, data, format='json')

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('error', response.data)
        self.assertIn("Session expired. Please login again.", response.data['error'])

class TokenViewTests(APITestCase):
    """Test the TokenView"""
    # Part of it which uses check_user_validity is already tested in TokenViewTests

    def setUp(self):
        self.url = TOKEN_USER_URL  # Assuming you named your URL 'token_obtain_pair' (or whatever your token URL is)
        self.User = get_user_model()
        self.test_user = self.User.objects.create_user(
            email='test@example.com',
            password='TestP@ssw0rd', # Hash the password!
            is_active=True,
            is_email_verified=True, # Use is_email_verified
            auth_provider='email'  # Add auth_provider
        )
        self.user_id = self.test_user.id

        # Cache user data to simulate a valid session and OTP
        self.otp = generate_otp() # Generate an OTP
        cache.set(f"id_{self.user_id}", self.user_id, timeout=60)
        cache.set(f"otp_{self.user_id}", self.otp, timeout=600)
        cache.set(f"email_{self.user_id}", 'test@example.com', timeout=600)
        cache.set(f"password_{self.user_id}", 'TestP@ssw0rd', timeout=600)
        cache.set(f"otp_{self.user_id}", self.otp, timeout=600) # Cache otp

        self.client.force_login(self.test_user)

    def tearDown(self):
        cache.clear()

    @patch('auth_api.views.check_user_id')
    def test_token_generation_success(self, mock_check_user_id):
        """
        Test successful token generation after OTP verification.
        """
        mock_check_user_id.return_value = self.test_user  # Mock check_user_id success

        data = {
            'user_id': self.user_id,
            'otp': f"{self.otp}", # Provide the OTP that's stored in the cache
        }

        response = self.client.post(self.url, data, format='json')

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('access_token_expiry', response.data)
        self.assertIn('access_token', response.data)
        self.assertIn('refresh_token', response.data)
        self.assertIn('user_role', response.data)
        self.assertIn('user_id', response.data)

    def test_token_generation_missing_user_id(self):
        """
        Test that missing user_id returns 400 Bad Request.
        """
        data = {'otp': '123456'}  # Missing user_id
        response = self.client.post(self.url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('error', response.data)
        self.assertEqual("Session expired. Please login again.", response.data['error'])

    def test_token_generation_invalid_user_id(self):
        """
        Test that invalid user_id returns 400 Bad Request.
        """
        data = {'user_id': 999999999, 'otp': '123456'}  # Nonexistent user_id
        response = self.client.post(self.url, data, format='json')

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('error', response.data)
        self.assertEqual(response.data['error'], 'Invalid Session') # Specific error check
        
    def test_token_generation_invalid_str_user_id(self):
        """
        Test that invalid user_id returns 400 Bad Request.
        """
        data = {'user_id': "some", 'otp': '123456'}  # Nonexistent user_id
        response = self.client.post(self.url, data, format='json')

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('error', response.data)
        self.assertEqual(response.data['error'], 'Invalid Session') # Specific error check

    def test_token_generation_expired_session(self):
        """
        Test that an expired session returns 400 Bad Request.
        """
        cache.clear() # Simulate an expired session by clearing the cache

        data = {'user_id': self.user_id, 'otp': '123456'}
        response = self.client.post(self.url, data, format='json')

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('error', response.data)
        self.assertIn("Session expired. Please login again.", response.data['error'])

    def test_token_generation_missing_otp(self):
        """
        Test that missing OTP returns 400 Bad Request.
        """
        data = {'user_id': self.user_id}  # Missing otp
        response = self.client.post(self.url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('error', response.data)
        self.assertEqual(response.data['error'], "Invalid OTP")

    def test_token_generation_invalid_otp(self):
        """
        Test that invalid OTP returns 400 Bad Request.
        """
        data = {'user_id': self.user_id, 'otp': 'wrongotp'}
        response = self.client.post(self.url, data, format='json')

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('error', response.data)
        self.assertEqual(response.data['error'], "Invalid OTP")

    @patch('auth_api.views.check_user_id')  # Patch check_user_id to simulate failure
    def test_token_generation_internal_server_error(self, mock_check_user_id):
        """
        Test that an exception in token generation is caught by TokenView and returns a 500 error.
        """
        # Simulate an exception being raised in check_user_id.
        mock_check_user_id.side_effect = Exception("Simulated Internal Server Error")

        data = {'user_id': self.user_id, 'otp': '123456'}

        response = self.client.post(self.url, data, format='json')

        self.assertEqual(response.status_code, status.HTTP_500_INTERNAL_SERVER_ERROR)
        self.assertIn('error', response.data)
        self.assertIn("Simulated Internal Server Error", response.data['error'])
        
class RefreshTokenViewTests(APITestCase):
    def setUp(self):
        self.client = APIClient()
        self.refresh_url = TOKEN_REFRESH_URL # Assuming you named your URL 'token_refresh'

        # Create a user for testing
        self.User = get_user_model()
        self.email = "test@example.com"
        self.password = "Test@123"
        self.user = self.User.objects.create_user(email=self.email, password=self.password)
        
        self.admin_group, _ = Group.objects.get_or_create(name="Admin")
        self.superuser_group, _ = Group.objects.get_or_create(name="Superuser")

        # Generate initial refresh and access tokens for the user
        self.refresh = RefreshToken.for_user(self.user)
        self.access = self.refresh.access_token
        self.refresh_token = str(self.refresh)
        self.access_token = str(self.access)
        
    def generate_expired_refresh_token(self):
        """Manually generate an expired refresh token."""
        refresh = RefreshToken.for_user(self.user)
        refresh.payload["exp"] = now() - timedelta(days=1)  # Set expiry in the past
        return str(refresh)

    def test_successful_token_refresh(self):
        """Test successful refresh token exchange."""
        data = {"refresh": self.refresh_token}
        response = self.client.post(self.refresh_url, data, format="json")

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn("access_token", response.data)
        self.assertIn("refresh_token", response.data)
        self.assertIn("user_role", response.data)
        self.assertIn("user_id", response.data)
        self.assertIn("access_token_expiry", response.data)

        self.assertEqual(response.data["user_id"], self.user.id)
        self.assertEqual(response.data["user_role"], "Default")  # Verify the user role

    def test_successful_token_refresh_admin_role(self):
        """Test successful refresh token exchange when user is in Admin group."""
        # Assign user to 'Admin' group and remove from 'Default'
        self.user.groups.clear()  # Remove from all groups
        self.user.groups.add(self.admin_group)

        # Generate new tokens after group change
        refresh = RefreshToken.for_user(self.user)
        refresh_token = str(refresh)

        data = {"refresh": refresh_token}
        response = self.client.post(self.refresh_url, data, format="json")

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["user_role"], "Admin")

    def test_successful_token_refresh_superuser_role(self):
        """Test successful refresh token exchange when user is in Superuser group."""
        # Assign user to 'Superuser' group and remove from other groups
        self.user.groups.clear()
        self.user.groups.add(self.superuser_group)

        # Generate new tokens after group change
        refresh = RefreshToken.for_user(self.user)
        refresh_token = str(refresh)

        data = {"refresh": refresh_token}
        response = self.client.post(self.refresh_url, data, format="json")

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["user_role"], "Superuser")

    def test_token_refresh_no_group(self):
        """Test refresh token exchange when user is not in any group."""
        # Remove user from all groups
        self.user.groups.clear()

        # Generate new tokens after group change
        refresh = RefreshToken.for_user(self.user)
        refresh_token = str(refresh)

        data = {"refresh": refresh_token}
        response = self.client.post(self.refresh_url, data, format="json")

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["user_role"], "UnAuthorized")

    def test_missing_refresh_token(self):
        """Test request with missing refresh token."""
        response = self.client.post(self.refresh_url, {}, format="json")
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("error", response.data)

    def test_invalid_refresh_token(self):
        """Test request with an invalid refresh token."""
        data = {"refresh": "invalid_refresh_token"}
        response = self.client.post(self.refresh_url, data, format="json")
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED) # Or 401 depending on your exact error handling
        self.assertIn("error", response.data)

    def test_expired_refresh_token(self):
        """Test request with an expired refresh token."""
        expired_token = self.generate_expired_refresh_token()
        data = {"refresh": expired_token}
        
        response = self.client.post(self.refresh_url, data, format="json")

        # Since SimpleJWT raises `TokenError`, it should return 401 Unauthorized
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
        self.assertIn("error", response.data)

    def test_blacklisted_refresh_token(self):
        """Test that a blacklisted refresh token is rejected."""

        # Ensure the refresh token is saved in the `OutstandingToken` table
        outstanding_token = OutstandingToken.objects.get(token=str(self.refresh_token))

        # Blacklist the token
        BlacklistedToken.objects.create(token=outstanding_token)

        data = {"refresh": str(self.refresh_token)}
        response = self.client.post(self.refresh_url, data, format="json")

        # A blacklisted token should return 401 Unauthorized
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
        self.assertIn("error", response.data)

    def test_user_not_found(self):
        """Test the case where the user associated with the token doesn't exist."""
        # Generate a valid token for a non-existent user ID
        refresh = RefreshToken()
        refresh['user_id'] = 9999  # Non-existent user ID
        refresh_token = str(refresh)

        data = {"refresh": refresh_token}
        response = self.client.post(self.refresh_url, data, format="json")
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)  # Or 401
        self.assertIn("error", response.data)

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

