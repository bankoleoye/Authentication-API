from django.urls import path
from .views import Logout, RegisterView, VerifyEmail, Login, ForgotPassword, PasswordReset


urlpatterns = [
    path('register/', RegisterView.as_view(), name="register"),
    path('email-verify/', VerifyEmail.as_view(), name="email-verify"),
    path('login/', Login.as_view(), name="login"),
    path('logout/', Logout.as_view(),name='logout'),
    path('forgot-password/', ForgotPassword.as_view(), name="forgot-password"),
    path('reset-password/', PasswordReset.as_view(), name="reset-password"),
]
