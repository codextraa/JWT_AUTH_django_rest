"""Views for Auth API."""
from rest_framework import status
from rest_framework.viewsets import ModelViewSet
from rest_framework.permissions import AllowAny, IsAuthenticated, IsAdminUser
from rest_framework.response import Response
from rest_framework.decorators import action
from rest_framework_simplejwt.authentication import JWTAuthentication
from django_filters.rest_framework import DjangoFilterBackend
from drf_spectacular.utils import extend_schema
from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group
from .renderers import (
    UserRenderer
)
from .serializers import (
    UserSerializer,
    UserImageSerializer,
    UserListSerializer,
    UserActionSerializer,
    UserFilterSerializer
)


class UserViewSet(ModelViewSet):
    """Viewset for User APIs."""
    queryset = get_user_model().objects.all() # get all the users
    serializer_class = UserSerializer # User Serializer initialized
    authentication_classes = [JWTAuthentication] # Using jwtoken
    renderer_classes = [UserRenderer]
    filter_backends = [DjangoFilterBackend]
    filterset_class = UserFilterSerializer

    def get_permissions(self):
        """Permission for CRUD operations."""
        if self.action == 'create': # No permission while creating user
            permission_classes = [AllowAny]
        elif (self.action == 'activate_user' or self.action == 'deactivate_user' 
               or self.action == 'delete'): # Only Admins are allowed
            permission_classes = [IsAuthenticated, IsAdminUser]
        else: # RUD operations need permissions
            permission_classes = [IsAuthenticated]
        return [permission() for permission in permission_classes]

    def get_serializer_class(self):
        """Return the serializer class for the action."""
        if self.action == "list": # List of users handled with different serializer
            return UserListSerializer
        if self.action == "deactivate_user" or self.action == "activate_user": # Deactivation handled with different serializer
            return UserActionSerializer
        if self.action == "upload_image": # Image handled with different serializer
            return UserImageSerializer
        return super().get_serializer_class()

    def update(self, request, *args, **kwargs):
        """Allow only users to update their own profile."""
        current_user = self.request.user
        print(request.data)
        user = self.get_object()

        if ('is_active' in request.data or 'is_staff' in request.data or 
            'is_superuser' in request.data):
            return Response(
                {"error": "You cannot update the is_active, is_staff or is_superuser field."},
                status=status.HTTP_403_FORBIDDEN
            )

        if current_user.id != user.id and not current_user.is_superuser:
            return Response(
                {"error": "You do not have permission to update this user."},
                status=status.HTTP_403_FORBIDDEN,
            )

        return super().update(request, *args, **kwargs)

    def destroy(self, request, *args, **kwargs):
        """Allow only superusers to delete normal or staff users and clean up profile image."""
        current_user = self.request.user
        user_to_delete = self.get_object()

        if not current_user.is_superuser:
            return Response(
                {"error": "Only superusers can delete users."},
                status=status.HTTP_403_FORBIDDEN,
            )

        if user_to_delete.is_superuser:
            return Response(
                {"error": "You cannot delete superusers"},
                status=status.HTTP_403_FORBIDDEN,
            )

        # Check and delete the profile image if it's not the default image
        default_image_path = 'profile_images/default_profile.jpg'
        print(user_to_delete)
        if user_to_delete.profile_img and user_to_delete.profile_img.name != default_image_path:
            user_to_delete.profile_img.delete(save=False)

        return super().destroy(request, *args, **kwargs)

    @extend_schema(
        operation_id="upload_user_image",
        description="Upload an image for the user's profile",
        request={
            "multipart/form-data": {
                "type": "object",
                "properties": {
                    "profile_img": {
                        "type": "string",
                        "format": "binary",
                        "description": "The image file to upload"
                    }
                }
            }
        },
        responses={200: UserSerializer},
    )
    @action(detail=True, methods=['PATCH'], url_path='upload-image')  # detail=True is only for a single user
    def upload_image(self, request, pk=None):
        """Update user profile image"""
        user = self.get_object()  # get the user
        current_user = self.request.user  # Get the user making the request

        # Ensure the request is made by the user themselves or a superuser
        if current_user.id != user.id and not current_user.is_superuser:
            return Response(
                {"error": "You do not have permission to upload an image for this user."},
                status=status.HTTP_403_FORBIDDEN,
            )
            
        default_image_path = 'profile_images/default_profile.jpg'  # Define the default image path

        # Check if the user has an existing image that is not the default image
        if user.profile_img and user.profile_img.name != default_image_path:
            # Remove the previous image file
            user.profile_img.delete(save=False)
        
        serializer = self.get_serializer(
            user,
            data=request.data,
            partial=True  # Only updating profile_img
        )
        serializer.is_valid(raise_exception=True)  # returns 400 if fails
        serializer.save()

        return Response(serializer.data, status=status.HTTP_200_OK)    

    @action(detail=True, methods=['PATCH'], url_path='deactivate-user')
    def deactivate_user(self, request, pk=None):
        """Deactivate a user (only staff and superuser can do to other users)"""
        user_to_deactivate = self.get_object()
        current_user = self.request.user

        if not user_to_deactivate.is_active:
            return Response(
                {"error": "User is already deactivated."},
                status=status.HTTP_400_BAD_REQUEST
            )

        if not (current_user.is_superuser or current_user.is_staff):
            if user_to_deactivate != current_user:
                return Response(
                    {"error": "You do not have permission to deactivate users."},
                    status=status.HTTP_403_FORBIDDEN
                )

        if user_to_deactivate == current_user and current_user.is_staff:
            if current_user.is_superuser:
                detail = "You cannot deactivate yourself as a superuser."
            else:
                detail = "You cannot deactivate yourself as a staff. Contact a superuser"

            return Response(
                {"error": detail},
                status=status.HTTP_403_FORBIDDEN
            )

        if user_to_deactivate.is_staff and not current_user.is_superuser:
            return Response(
                {"error": "Only superusers can deactivate staff users."},
                status=status.HTTP_403_FORBIDDEN
            )

        if user_to_deactivate.is_superuser:
            return Response(
                {"error": "You cannot deactivate a superuser."},
                status=status.HTTP_403_FORBIDDEN
            )

        deactivated, _ = Group.objects.get_or_create(name="Deactivated")
        user_to_deactivate.groups.clear()
        user_to_deactivate.groups.add(deactivated)
        user_to_deactivate.is_active = False
        user_to_deactivate.save()

        return Response(
            {"error": f"User {user_to_deactivate.email} has been deactivated."},
            status=status.HTTP_200_OK,
        )

    @action(detail=True, methods=['PATCH'], url_path='activate-user')
    def activate_user(self, request, pk=None):
        """Activate a user (only staff and superuser can do this)"""
        user_to_activate = self.get_object()
        current_user = self.request.user

        if user_to_activate.is_active:
            return Response(
                {"error": "User is not deactivated."},
                status=status.HTTP_400_BAD_REQUEST
            )

        if not (current_user.is_superuser or current_user.is_staff):
            return Response(
                {"error": "You do not have permission to activate users."},
                status=status.HTTP_403_FORBIDDEN
            )

        if user_to_activate == current_user:
            return Response(
                {"error": "You cannot activate yourself."},
                status=status.HTTP_403_FORBIDDEN
            )

        if user_to_activate.is_staff and not current_user.is_superuser:
            return Response(
                {"error": "Only superusers can activate staff users."},
                status=status.HTTP_403_FORBIDDEN
            )

        default = Group.objects.get(name="Default")
        user_to_activate.groups.clear()
        user_to_activate.groups.add(default)
        user_to_activate.is_active = True
        user_to_activate.save()

        return Response(
            {f"User {user_to_activate.email} has been reactivated."},
            status=status.HTTP_200_OK,
        )