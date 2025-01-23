"""Custom user creation pipeline function."""


def user_creation(backend, user, response, *args, **kwargs):
    print('response', response)
    print('backend', backend)
    print('user', user)
    if backend.name == 'google':
        user.auth_provider = 'google'
    elif backend.name == 'facebook':
        user.auth_provider = 'facebook'
    elif backend.name == 'instagram':
        user.auth_provider = 'instagram'
    elif backend.name == 'twitter':
        user.auth_provider = 'twitter'
    elif backend.name == 'github':
        user.auth_provider = 'github'
    elif backend.name == 'linkedin':
        user.auth_provider = 'linkedin'
    
    # Set the username to email, first_name and last_name are capitalized
    if not user.username:
        user.username = user.email
    user.first_name = user.first_name.capitalize() if user.first_name else ''
    user.last_name = user.last_name.capitalize() if user.last_name else ''
    user.is_email_verified = True

    # Set profile image if it exists
    profile_img_url = None
    if backend.name == 'google':
        profile_img_url = response.get('picture')
    elif backend.name in ['facebook', 'instagram']:
        profile_img_url = response.get('profile_image')  # Adjust key based on API response
        
    user.profile_img = profile_img_url

    # if profile_img_url and not user.profile_img:
    #     try:
    #         image_response = urlopen(profile_img_url)
    #         user.profile_img.save(
    #             f"{user.username}_profile.jpg",
    #             ContentFile(image_response.read()),
    #             save=True,
    #         )
    #     except Exception as e:
    #         # Log the error (optional)
    #         print(f"Failed to save profile image: {e}")

    user.save()
    return user