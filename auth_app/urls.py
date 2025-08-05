"""
URL configuration for otp_auth project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/5.0/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""

from django.urls import path
from . import views

urlpatterns = [
    path('', views.home, name="home"),
    path('signup/', views.signup, name="signup"),
    path('signin/', views.signin, name="signin"),
    path('signout/', views.signout, name="signout"),
    path('verify-otp/<str:username>/', views.verify_otp, name="verify_otp"),
    path('login-otp/<str:username>/', views.login_with_otp, name="login_with_otp"),
    path('resend-otp/', views.resend_otp, name="resend_otp"),
    path('forgot-password/', views.forgot_password, name="forgot_password"),
    path('reset-password/<uidb64>/<token>/', views.reset_password, name="reset_password"),
    path('change-password/', views.change_pass, name="change_pass"),
]
