from django.urls import path, include
from rest_framework.routers import DefaultRouter
from rest_framework_simplejwt.views import (
    TokenRefreshView,
)
from . import views


# basename will be singluar eg user
# basename-list (Get /users/ and Post /users/)
# basename-detail (Get /users/id, Put/patch /users/id, Delete /users/id)
# basename-action-name (Post /users/id/upload-image/)
router = DefaultRouter()
router.register(r'users', views.UserViewSet)


urlpatterns = [
    path('', include(router.urls)),
    path('login/', views.LoginView.as_view(), name='login'),
    path('token/', views.TokenView.as_view(), name='token'),
    path('token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
   
]