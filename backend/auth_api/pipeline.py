"""Custom user creation pipeline function."""
from django.contrib.auth import get_user_model
from django.contrib.auth.models import BaseUserManager
from rest_framework.response import Response
from rest_framework import status


def user_creation(backend, user, response, *args, **kwargs):
    # print('response', response)
    # print('backend name', backend.name)
    # print('user', user)
    
    try:
        User = get_user_model()
        
        email = response.get('email')
        normalized_email = BaseUserManager.normalize_email(email)
        
        if User.objects.filter(email=normalized_email).exists():
            found_user = User.objects.get(email=normalized_email)
            if backend.name == 'google-oauth2' and found_user.auth_provider == 'google':
                return found_user
            elif found_user.auth_provider == backend.name:
                return found_user
            elif found_user.auth_provider == 'email':
                return Response({"error": f"User with this email already created using password. Please login using password."}, 
                                status=status.HTTP_400_BAD_REQUEST)
            else:
                return Response({"error": f"User with this email already created using {found_user.auth_provider}. Please login using {found_user.auth_provider}."}, 
                                status=status.HTTP_400_BAD_REQUEST)
        
        # Set the username to email, first_name and last_name are capitalized
        new_user = User(
            email=normalized_email,
            username=normalized_email,  # Using the normalized email as username
            is_active=True,
            is_email_verified=True,
        )
        
        random_password = User.create_random_password()
        new_user.set_password(random_password)
        
        if backend.name == 'google-oauth2':
            new_user.first_name = response.get('given_name')
            new_user.last_name = response.get('family_name')
            new_user.auth_provider = 'google'
        elif backend.name in ['facebook', 'instagram', 'github']:
            name_parts = response.get('name').split()

            if len(name_parts) == 0:
                first_name = ''
                last_name = ''
            elif len(name_parts) == 1:
                first_name = name_parts[0]
                last_name = ''
            else:
                first_name = name_parts[0]
                last_name = ' '.join(name_parts[1:])
                
            new_user.first_name = first_name
            new_user.last_name = last_name

        if backend.name == 'facebook':
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
            image_data = response.get('picture')
            if image_data:
                profile_img_url = image_data['data']['url']
        elif backend.name == 'github':
            profile_img_url = response.get('avatar_url')
            
        new_user.profile_img = profile_img_url

        new_user.save()
            
        return new_user
    except Exception as e:
        print('An error occurred: ', e)
        return Response({"error": f"An error occurred: {e}"}, status=status.HTTP_400_BAD_REQUEST)