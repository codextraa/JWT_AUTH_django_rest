"""Custom user creation pipeline function."""
from django.contrib.auth import get_user_model
from django.contrib.auth.models import BaseUserManager


def user_creation(backend, user, response, *args, **kwargs):
    User = get_user_model()
    
    email = response.get('email')
    normalized_email = BaseUserManager.normalize_email(email)
    
    if User.objects.filter(email=normalized_email).exists():
        return User.objects.get(email=normalized_email)
    
    # Set the username to email, first_name and last_name are capitalized
    new_user = User(
        username=normalized_email,  # Using the normalized email as username
        email=normalized_email,
        first_name=response.get('given_name', '').capitalize(),
        last_name=response.get('family_name', '').capitalize(),
        is_active=True,
        is_email_verified=True,
    )
    
    random_password = User.create_random_password()
    new_user.set_password(random_password)
    
    if backend.name == 'google-oauth2':
        new_user.auth_provider = 'google'
    elif backend.name == 'facebook':
        new_user.auth_provider = 'facebook'
    elif backend.name == 'instagram':
        new_user.auth_provider = 'instagram'
    elif backend.name == 'twitter':
        new_user.auth_provider = 'twitter'
    elif backend.name == 'github':
        new_user.auth_provider = 'github'
    elif backend.name == 'linkedin':
        new_user.auth_provider = 'linkedin'

    # Set profile image if it exists
    profile_img_url = None
    if backend.name == 'google-oauth2':
        profile_img_url = response.get('picture')
    elif backend.name in ['facebook', 'instagram']:
        profile_img_url = response.get('profile_image')  # Adjust key based on API response
        
    new_user.profile_img = profile_img_url

    new_user.save()
        
    return new_user