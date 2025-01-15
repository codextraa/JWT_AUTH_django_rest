from django.contrib.auth import get_user_model
from rest_framework import serializers
import re


class UserSerializer(serializers.ModelSerializer):
    """User Serializer"""
    
    class Meta:
        model = get_user_model()
        fields = ('id', 'email', 'password1', 'password2', 'username', 'first_name', 
                  'last_name', 'phone_number', 'profile_img', 'slug', 
                  'is_active', 'is_staff', 'is_superuser')
        read_only_fields = ('id', 'is_superuser')
        extra_kwargs = {
            'password': {
                'write_only': True,
                'style': {'input_type': 'password'} 
            }
        }
        
    def _validate_email(self, email):
        """Email validation"""
        errors = {}
        
        if not self.instance and get_user_model().objects.filter(email=email).exists():
            errors['email'] = 'Email is already in use. Please use a different email.'
            
        if errors:
            raise serializers.ValidationError(errors)
        
    def _validate_username(self, username):
        """Username validation"""
        errors = {}
        
        if not self.instance and get_user_model().objects.filter(username=username).exists():
            errors['username'] = 'Username is already in use. Please use a different username.'
            
        if errors:
            raise serializers.ValidationError(errors)
        
    def _validate_password(self, password1, password2):
        """Password Validation"""
        errors = {}
        
        if len(password1) < 8:
            errors['short'] = 'Password must be at least 8 characters long.'
            
        if not re.search(r"[a-z]", password1):
            errors['lower'] = 'Password must contain at least one lowercase letter.'
            
        if not re.search(r"[A-Z]", password1):
            errors['upper'] = 'Password must contain at least one uppercase letter.'
            
        if not re.search(r"[0-9]", password1):
            errors['number'] = 'Password must contain at least one number.'
            
        if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password1):
            errors['special'] = 'Password must contain at least one special character.'
            
        if password1 != password2:
            errors['match'] = 'Passwords do not match.'
            
        if errors:
            raise serializers.ValidationError(errors)
        
    def validate(self, attrs):
        """Validate all data"""
        
        email = attrs.get('email')
        if email:
            self._validate_email(email)
            
        username = attrs.get('username')
        if username:
            self._validate_username(username)
        
        password1 = attrs.get('password1')
        password2 = attrs.get('password2')
        if password1 and password2:
            self._validate_password(password1, password2)
        
        attrs = super().validate(attrs)
        
        if attrs.get('first_name'):
            attrs['first_name'] = attrs['first_name'].title()
        if attrs.get('last_name'):
            attrs['last_name'] = attrs['last_name'].title()
        
        return attrs
    
    def create(self, validated_data):
        """Create and return a user with encrypted password."""
        errors = {}
        email = validated_data['email']
        username = validated_data['username']
        password1 = validated_data['password1']
        password2 = validated_data['password2']
        
        if not email:
            errors['email'] = 'Email is required.'
        
        if not username:
            errors['username'] = 'Username is required.'
            
        if not password1:
            errors['password1'] = 'Password is required.'
            
        if not password2:
            errors['password2'] = 'Password confirmation is required.'
        
        if errors:
            raise serializers.ValidationError(errors)
            
        profile_img = validated_data.pop('profile_img', None)
        
        if not profile_img:
            """Set default profile image if not provided"""
            default_image_path = 'profile_images/default_profile.jpg'
            validated_data['profile_img'] = default_image_path

        return get_user_model().objects.create_user(**validated_data)

    def update(self, instance, validated_data):
        """Update and return an existing user"""
        password = validated_data.pop("password", None)
        instance = super().update(instance, validated_data)

        if password:
            instance.set_password(password)
            instance.save()

        return instance
    
class UserImageSerializer(serializers.ModelSerializer):
    class Meta:
        model = get_user_model()
        fields = ('id', 'profile_img')
        read_only_fields = ('id',)

    def validate_profile_img(self, value):
        """Validate profile image"""
        max_size = 5 * 1024 * 1024 # 5MB
        valid_file_types = ['image/jpeg', 'image/png', 'image/gif'] # valid image types

        errors = {}
        
        if value.size > max_size:
            errors['size'] = 'Profile image size should not exceed 5MB.'

        if value.content_type not in valid_file_types:
            errors['type'] = 'Profile image type should be JPEG, PNG or GIF.'
            
        if errors:
            raise serializers.ValidationError(errors)

        return value
    
    
# class MediaFileSerializer(serializers.ModelSerializer):
#     file_url = serializers.SerializerMethodField()

#     class Meta:
#         model = MediaFile
#         fields = ('id', 'name', 'file_url')

#     def get_file_url(self, obj):
#         request = self.context.get('request')
#         if request:
#             return request.build_absolute_uri(obj.file.url)
#         return obj.file.url