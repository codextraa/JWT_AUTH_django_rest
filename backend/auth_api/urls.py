from django.urls import path, include
from rest_framework.routers import DefaultRouter
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
    path('logout/', views.LogoutView.as_view(), name='logout'),
    path('resend-otp/', views.ResendOtpView.as_view(), name='resend-otp'),
    path('verify-email/', views.EmailVerifyView.as_view(), name='email-verify'),
    path('reset-password/', views.PasswordResetView.as_view(), name='password-reset'),
    path('token/', views.TokenView.as_view(), name='token'),
    path('token/refresh/', views.RefreshTokenView.as_view(), name='token-refresh'),
]