"""
TOTP (Time-based One-Time Password) utilities for MFA.

This module provides utilities for generating and verifying TOTP codes
for Multi-Factor Authentication (MFA).

Security Considerations:
- TOTP secrets should be encrypted at rest in production
- QR codes are generated for easy setup with authenticator apps
- Window parameter allows for clock skew tolerance
"""

import pyotp
import qrcode
from io import BytesIO
import base64
from django.conf import settings
from django.contrib.auth import get_user_model

User = get_user_model()


def generate_totp_secret() -> str:
    """
    Generate a new TOTP secret for a user.
    
    Returns:
        str: Base32-encoded TOTP secret
    """
    return pyotp.random_base32()


def get_totp_uri(user: User, secret: str = None) -> str:
    """
    Generate TOTP URI for QR code generation.
    
    Args:
        user: User object
        secret: TOTP secret (if None, uses user's existing secret)
        
    Returns:
        str: TOTP URI (otpauth:// format)
    """
    if secret is None:
        secret = user.mfa_secret
    
    if not secret:
        raise ValueError("TOTP secret is required")
    
    issuer = getattr(settings, 'TOTP_ISSUER_NAME', 'Secure E-Commerce')
    totp = pyotp.TOTP(secret)
    
    return totp.provisioning_uri(
        name=user.email,
        issuer_name=issuer,
    )


def generate_qr_code(uri: str) -> str:
    """
    Generate QR code image as base64-encoded string.
    
    Args:
        uri: TOTP URI to encode in QR code
        
    Returns:
        str: Base64-encoded PNG image data
    """
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_L,
        box_size=10,
        border=4,
    )
    qr.add_data(uri)
    qr.make(fit=True)
    
    img = qr.make_image(fill_color="black", back_color="white")
    
    # Convert to base64
    buffer = BytesIO()
    img.save(buffer, format='PNG')
    img_str = base64.b64encode(buffer.getvalue()).decode()
    
    return f"data:image/png;base64,{img_str}"


def verify_totp_code(secret: str, code: str) -> bool:
    """
    Verify a TOTP code against a secret.
    
    Args:
        secret: TOTP secret (base32-encoded)
        code: TOTP code to verify (6-digit string)
        
    Returns:
        bool: True if code is valid, False otherwise
    """
    if not secret or not code:
        return False
    
    try:
        interval = getattr(settings, 'TOTP_INTERVAL', 30)
        digits = getattr(settings, 'TOTP_DIGITS', 6)
        window = getattr(settings, 'TOTP_WINDOW', 1)
        
        totp = pyotp.TOTP(secret, interval=interval, digits=digits)
        
        # Verify with window to allow for clock skew
        return totp.verify(code, valid_window=window)
    except Exception:
        return False


def setup_totp_for_user(user: User) -> dict:
    """
    Set up TOTP for a user and return QR code.
    
    Args:
        user: User object
        
    Returns:
        dict: Contains 'secret', 'uri', and 'qr_code' (base64 image)
    """
    # Generate new secret
    secret = generate_totp_secret()
    
    # Generate URI
    uri = get_totp_uri(user, secret)
    
    # Generate QR code
    qr_code = generate_qr_code(uri)
    
    return {
        'secret': secret,
        'uri': uri,
        'qr_code': qr_code,
    }

