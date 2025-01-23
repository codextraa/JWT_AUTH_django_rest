import re, django_filters
from django.contrib.auth import get_user_model
from rest_framework import serializers


def validate_password(password):
    """Password Validation"""
    errors = {}
    
    if len(password) < 8:
        errors['short'] = 'Password must be at least 8 characters long.'
        
    if not re.search(r"[a-z]", password):
        errors['lower'] = 'Password must contain at least one lowercase letter.'
        
    if not re.search(r"[A-Z]", password):
        errors['upper'] = 'Password must contain at least one uppercase letter.'
        
    if not re.search(r"[0-9]", password):
        errors['number'] = 'Password must contain at least one number.'
        
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        errors['special'] = 'Password must contain at least one special character.'
        
    if errors:
        raise serializers.ValidationError(errors)
    
class PasswordResetSerializer(serializers.ModelSerializer):
    """Password Reset Serializer"""
    
    class Meta:
        model = get_user_model()
        fields = ('id', 'password')
        read_only_fields = ('id',)
        extra_kwargs = {
            'password': {
                'write_only': True,
                'style': {'input_type': 'password'} 
            }
        }
        
    def validate(self, attrs):
        """Validate all data"""
        password = attrs.get('password')
        if password:
            validate_password(password)
            
        return super().validate(attrs)
        
    def update(self, instance, validated_data):
        """Update and return an existing user"""
        password = validated_data.pop("password", None)
        
        if not password:
            raise serializers.ValidationError("Password is required.")
        
        if instance.check_password(password):
            raise serializers.ValidationError("New password cannot be the same as the old password.")
        
        validate_password(password)
        instance.set_password(password)
        instance.save()

        return instance

class UserFilterSerializer(django_filters.FilterSet):
    """User Filter"""
    email = django_filters.CharFilter(lookup_expr='icontains')
    username = django_filters.CharFilter(lookup_expr='icontains')
    
    class Meta:
        model = get_user_model()
        fields = ('email', 'username')

class UserListSerializer(serializers.ModelSerializer):
    """List User Serializer"""

    class Meta:
        model = get_user_model()
        fields = ('id', 'email', 'username', 'is_active', 'is_staff', 'is_superuser')
        read_only_fields = ('id', 'email', 'username', 'is_active', 'is_staff', 'is_superuser')
        
class UserActionSerializer(serializers.ModelSerializer):
    """Action User Serializer"""

    class Meta:
        model = get_user_model()
        fields = ('id',)
        read_only_fields = ('id',)

class UserSerializer(serializers.ModelSerializer):
    """User Serializer"""
    
    class Meta:
        model = get_user_model()
        fields = ('id', 'email', 'password', 'username', 'first_name', 
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
        
    def validate(self, attrs):
        """Validate all data"""
        
        email = attrs.get('email')
        if email:
            self._validate_email(email)
            
        username = attrs.get('username')
        if username:
            self._validate_username(username)
        
        password = attrs.get('password')
        if password:
            validate_password(password)
        
        attrs = super().validate(attrs)
        
        if attrs.get('first_name'):
            attrs['first_name'] = attrs['first_name'].title()
        if attrs.get('last_name'):
            attrs['last_name'] = attrs['last_name'].title()
        
        return attrs
    
    def create(self, validated_data):
        """Create and return a user with encrypted password."""
        profile_img = validated_data.pop('profile_img', None)
        
        if not profile_img:
            """Set default profile image if not provided"""
            default_image_path = 'profile_images/default_profile.jpg'
            validated_data['profile_img'] = default_image_path

        return get_user_model().objects.create_user(**validated_data)
    
class UserImageSerializer(serializers.ModelSerializer):
    class Meta:
        model = get_user_model()
        fields = ('id', 'profile_img')
        read_only_fields = ('id',)

    def validate_profile_img(self, value):
        """Validate profile image"""
        errors = {}
        max_size = 3 * 1024 * 1024 # 3MB
        valid_file_types = ['image/jpeg', 'image/png'] # valid image types
        
        if value.size > max_size:
            errors['size'] = 'Profile image size should not exceed 3MB.'

        if value.content_type not in valid_file_types:
            errors['type'] = 'Profile image type should be JPEG, PNG'
            
        if errors:
            raise serializers.ValidationError(errors)

        return value
    
class LoginSerializer(serializers.Serializer):
    email = serializers.EmailField(required=True)
    password = serializers.CharField(required=True, write_only=True)
    
class LogoutSerializer(serializers.Serializer):
    refresh = serializers.CharField(required=True)
    
class ResendOtpSerializer(serializers.Serializer):
    user_id = serializers.CharField(required=True)

class TokenRequestSerializer(serializers.Serializer):
    user_id = serializers.CharField(required=True)
    otp = serializers.CharField(required=True)
    
class PasswordResetRequestSerializer(serializers.Serializer):
    email = serializers.EmailField(required=True)
    
class InputPasswordResetSerializer(serializers.Serializer):
    password = serializers.CharField(required=True)
    c_password = serializers.CharField(required=True)
    
class SocialOAuthSerializer(serializers.Serializer):
    token = serializers.CharField(required=True)
    provider = serializers.CharField(required=True)