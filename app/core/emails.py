"""
Transactional email sending via Resend: email verification and password
reset links. Link base URL is configurable via settings.app_base_url.
"""
import resend
from app.config import settings

resend.api_key = settings.resend_api_key
resend_email = settings.resend_email_address

def send_verification_email(email,verification_token):
    link = f"{settings.app_base_url}/auth/verify-email?token={verification_token}"
    html_body = f"""
    <p>Hi,</p>
    <p> Please verify your email by clicking the link below:</p>
    <p><a href = "{link}">Verify Email</a></p>
    <p> This link expires in 24 hours.</p>
    """
    resend.Emails.send({
        "from": resend_email,
        "to": email,
        "subject": "Verify your email",
        "html": html_body,
    })

def send_password_reset_email(email,reset_token):
    link = f"{settings.app_base_url}/auth/reset-password?token={reset_token}"
    html_body = f"""
    <p>Hi,</p>
    <p> You requested a reset of passwords, please follow the below link to reset your password</p>
    <p><a href = "{link}">Reset Your Password</a></p>
    <p> This link expires in 1 hour.</p>
    """
    resend.Emails.send({
        "from": resend_email,
        "to": email,
        "subject": "Password reset",
        "html": html_body,
    })