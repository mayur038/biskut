from django.conf import settings
from django.core.mail import send_mail
from rest_framework_simplejwt.tokens import RefreshToken

def generate_verification_token(user):
    refresh = RefreshToken.for_user(user)
    return str(refresh.access_token)

def send_verification_email(user):
    token = generate_verification_token(user)
    verify_url = f"http://127.0.0.1:8000/api/verify-email/?token={token}"

    subject = "Verify Your Email"
    message = f"Hi {user.username},\n\nPlease verify your email by clicking the link below:\n{verify_url}"
    send_mail(subject, message, settings.DEFAULT_FROM_EMAIL, [user.email])
