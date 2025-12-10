"""
Advanced Security Features for the secure e-commerce application.

This module provides advanced security implementations including:
- Secrets Management
- Enhanced Rate Limiting
- Security Headers Management
- Biometric Authentication Support (WebAuthn)
- Encryption Utilities
- Security Event Monitoring

These features represent enterprise-grade security practices.
"""

import hashlib
import hmac
import secrets
import time
from typing import Optional, Dict, Any, Tuple
from django.conf import settings
from django.core.cache import cache
from django.utils import timezone
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
import base64


# ============================================================================
# SECRETS MANAGEMENT
# ============================================================================

class SecretsManager:
    """
    Secure secrets management utility.
    
    In production, use HashiCorp Vault or AWS Secrets Manager.
    This is a simplified implementation for demonstration.
    
    Security Features:
    - Encryption at rest using Fernet (symmetric encryption)
    - Key derivation using PBKDF2
    - Secure key storage (should use environment variables or key management service)
    """
    
    @staticmethod
    def _get_encryption_key() -> bytes:
        """
        Derive encryption key from Django secret key.
        
        WARNING: In production, use a dedicated key management service.
        """
        secret_key = settings.SECRET_KEY.encode()
        salt = b'secure_ecommerce_salt'  # In production, use a unique salt per secret
        
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        key = base64.urlsafe_b64encode(kdf.derive(secret_key))
        return key
    
    @staticmethod
    def encrypt_secret(plaintext: str) -> str:
        """
        Encrypt a secret value.
        
        Args:
            plaintext: Secret to encrypt
            
        Returns:
            str: Base64-encoded encrypted secret
        """
        key = SecretsManager._get_encryption_key()
        f = Fernet(key)
        encrypted = f.encrypt(plaintext.encode())
        return base64.b64encode(encrypted).decode()
    
    @staticmethod
    def decrypt_secret(ciphertext: str) -> str:
        """
        Decrypt a secret value.
        
        Args:
            ciphertext: Encrypted secret (base64-encoded)
            
        Returns:
            str: Decrypted secret
        """
        key = SecretsManager._get_encryption_key()
        f = Fernet(key)
        encrypted = base64.b64decode(ciphertext.encode())
        decrypted = f.decrypt(encrypted)
        return decrypted.decode()


# ============================================================================
# ENHANCED RATE LIMITING
# ============================================================================

class EnhancedRateLimiter:
    """
    Enhanced rate limiting with sliding window algorithm.
    
    Features:
    - Sliding window instead of fixed window
    - Per-user and per-IP limiting
    - Different limits for different endpoints
    - Automatic cleanup of expired entries
    """
    
    @staticmethod
    def is_allowed(
        identifier: str,
        limit: int,
        window_seconds: int,
        cache_key_prefix: str = 'ratelimit'
    ) -> Tuple[bool, int]:
        """
        Check if request is allowed based on rate limit.
        
        Args:
            identifier: Unique identifier (user ID, IP address, etc.)
            limit: Maximum number of requests allowed
            window_seconds: Time window in seconds
            cache_key_prefix: Prefix for cache keys
            
        Returns:
            tuple: (is_allowed: bool, remaining: int)
        """
        cache_key = f"{cache_key_prefix}:{identifier}"
        now = time.time()
        window_start = now - window_seconds
        
        # Get existing requests from cache
        requests = cache.get(cache_key, [])
        
        # Filter out expired requests (outside window)
        requests = [req_time for req_time in requests if req_time > window_start]
        
        # Check if limit exceeded
        if len(requests) >= limit:
            return False, 0
        
        # Add current request
        requests.append(now)
        
        # Store back in cache
        cache.set(cache_key, requests, window_seconds)
        
        remaining = limit - len(requests)
        return True, remaining
    
    @staticmethod
    def get_remaining(
        identifier: str,
        limit: int,
        window_seconds: int,
        cache_key_prefix: str = 'ratelimit'
    ) -> int:
        """
        Get remaining requests for an identifier.
        
        Args:
            identifier: Unique identifier
            limit: Maximum number of requests allowed
            window_seconds: Time window in seconds
            cache_key_prefix: Prefix for cache keys
            
        Returns:
            int: Number of remaining requests
        """
        cache_key = f"{cache_key_prefix}:{identifier}"
        now = time.time()
        window_start = now - window_seconds
        
        requests = cache.get(cache_key, [])
        requests = [req_time for req_time in requests if req_time > window_start]
        
        return max(0, limit - len(requests))


# ============================================================================
# SECURITY HEADERS MANAGEMENT
# ============================================================================

class SecurityHeadersManager:
    """
    Centralized management of security headers.
    
    Provides consistent security headers across all responses
    and allows for easy customization.
    """
    
    @staticmethod
    def get_security_headers() -> Dict[str, str]:
        """
        Get all security headers as a dictionary.
        
        Returns:
            dict: Security headers with their values
        """
        return {
            'X-Content-Type-Options': 'nosniff',
            'X-Frame-Options': 'DENY',
            'X-XSS-Protection': '1; mode=block',
            'Referrer-Policy': 'strict-origin-when-cross-origin',
            'Content-Security-Policy': SecurityHeadersManager._get_csp(),
            'Permissions-Policy': SecurityHeadersManager._get_permissions_policy(),
            'Strict-Transport-Security': SecurityHeadersManager._get_hsts(),
        }
    
    @staticmethod
    def _get_csp() -> str:
        """
        Get Content Security Policy header value.
        
        Customize based on your application's needs.
        """
        return (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline' 'unsafe-eval'; "  # Allow inline for admin
            "style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data: https:; "
            "font-src 'self' https:; "
            "connect-src 'self'; "
            "frame-ancestors 'none';"
        )
    
    @staticmethod
    def _get_permissions_policy() -> str:
        """
        Get Permissions Policy header value.
        """
        return (
            "accelerometer=(), "
            "ambient-light-sensor=(), "
            "autoplay=(), "
            "camera=(), "
            "display-capture=(), "
            "document-domain=(), "
            "encrypted-media=(), "
            "fullscreen=(), "
            "geolocation=(), "
            "gyroscope=(), "
            "magnetometer=(), "
            "microphone=(), "
            "midi=(), "
            "payment=(), "
            "usb=()"
        )
    
    @staticmethod
    def _get_hsts() -> str:
        """
        Get HTTP Strict Transport Security header value.
        
        Only include if HTTPS is properly configured.
        """
        hsts_seconds = getattr(settings, 'SECURE_HSTS_SECONDS', 0)
        if hsts_seconds > 0:
            include_subdomains = getattr(settings, 'SECURE_HSTS_INCLUDE_SUBDOMAINS', False)
            preload = getattr(settings, 'SECURE_HSTS_PRELOAD', False)
            
            hsts = f"max-age={hsts_seconds}"
            if include_subdomains:
                hsts += "; includeSubDomains"
            if preload:
                hsts += "; preload"
            
            return hsts
        return ""


# ============================================================================
# BIOMETRIC AUTHENTICATION (WebAuthn Support)
# ============================================================================

class BiometricAuthManager:
    """
    Manager for biometric authentication using WebAuthn.
    
    This is a foundation for WebAuthn implementation.
    In production, use libraries like 'django-webauthn' or 'py_webauthn'.
    
    WebAuthn allows:
    - Fingerprint authentication
    - Face recognition
    - Hardware security keys (FIDO2)
    - Platform authenticators
    """
    
    @staticmethod
    def generate_challenge() -> str:
        """
        Generate a random challenge for WebAuthn registration/authentication.
        
        Returns:
            str: Base64-encoded random challenge
        """
        challenge = secrets.token_bytes(32)
        return base64.urlsafe_b64encode(challenge).decode().rstrip('=')
    
    @staticmethod
    def verify_challenge(challenge: str, stored_challenge: str) -> bool:
        """
        Verify that the challenge matches the stored challenge.
        
        Args:
            challenge: Challenge from client
            stored_challenge: Challenge stored server-side
            
        Returns:
            bool: True if challenges match
        """
        return hmac.compare_digest(challenge, stored_challenge)
    
    @staticmethod
    def store_credential(user_id: int, credential_id: str, public_key: str) -> None:
        """
        Store WebAuthn credential for a user.
        
        In production, implement proper database storage.
        
        Args:
            user_id: User ID
            credential_id: Credential ID from WebAuthn
            public_key: Public key from WebAuthn
        """
        # In production, store in database
        cache_key = f"webauthn_credential:{user_id}:{credential_id}"
        cache.set(cache_key, {
            'credential_id': credential_id,
            'public_key': public_key,
            'created_at': timezone.now().isoformat(),
        }, timeout=86400 * 365)  # 1 year
    
    @staticmethod
    def get_user_credentials(user_id: int) -> list:
        """
        Get all WebAuthn credentials for a user.
        
        Args:
            user_id: User ID
            
        Returns:
            list: List of credential dictionaries
        """
        # In production, query database
        # This is a simplified implementation
        return []


# ============================================================================
# ENCRYPTION UTILITIES
# ============================================================================

class EncryptionUtils:
    """
    Utility functions for encryption and hashing.
    """
    
    @staticmethod
    def hash_sensitive_data(data: str, salt: Optional[str] = None) -> Tuple[str, str]:
        """
        Hash sensitive data with salt.
        
        Args:
            data: Data to hash
            salt: Optional salt (generated if not provided)
            
        Returns:
            tuple: (hashed_data, salt)
        """
        if salt is None:
            salt = secrets.token_hex(16)
        
        # Use PBKDF2 for key derivation
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt.encode(),
            iterations=100000,
            backend=default_backend()
        )
        hashed = kdf.derive(data.encode())
        return base64.b64encode(hashed).decode(), salt
    
    @staticmethod
    def generate_secure_token(length: int = 32) -> str:
        """
        Generate a cryptographically secure random token.
        
        Args:
            length: Token length in bytes
            
        Returns:
            str: Hex-encoded token
        """
        return secrets.token_hex(length)
    
    @staticmethod
    def constant_time_compare(val1: str, val2: str) -> bool:
        """
        Compare two strings in constant time to prevent timing attacks.
        
        Args:
            val1: First string
            val2: Second string
            
        Returns:
            bool: True if strings are equal
        """
        return hmac.compare_digest(val1.encode(), val2.encode())


# ============================================================================
# SECURITY EVENT MONITORING
# ============================================================================

class SecurityEventMonitor:
    """
    Monitor and analyze security events for threat detection.
    
    Features:
    - Detect suspicious patterns
    - Track failed authentication attempts
    - Monitor API usage patterns
    - Alert on anomalies
    """
    
    @staticmethod
    def detect_brute_force_attempt(ip_address: str, threshold: int = 10) -> bool:
        """
        Detect potential brute force attack from an IP address.
        
        Args:
            ip_address: IP address to check
            threshold: Number of failed attempts to trigger alert
            
        Returns:
            bool: True if brute force detected
        """
        cache_key = f"security:failed_attempts:{ip_address}"
        failed_attempts = cache.get(cache_key, 0)
        
        return failed_attempts >= threshold
    
    @staticmethod
    def record_failed_attempt(ip_address: str, user_identifier: Optional[str] = None) -> None:
        """
        Record a failed authentication attempt.
        
        Args:
            ip_address: IP address of the attempt
            user_identifier: Optional user identifier
        """
        cache_key = f"security:failed_attempts:{ip_address}"
        attempts = cache.get(cache_key, 0)
        cache.set(cache_key, attempts + 1, timeout=3600)  # 1 hour
        
        if user_identifier:
            user_key = f"security:failed_attempts:user:{user_identifier}"
            user_attempts = cache.get(user_key, 0)
            cache.set(user_key, user_attempts + 1, timeout=3600)
    
    @staticmethod
    def reset_failed_attempts(ip_address: str, user_identifier: Optional[str] = None) -> None:
        """
        Reset failed attempt counters.
        
        Args:
            ip_address: IP address
            user_identifier: Optional user identifier
        """
        cache_key = f"security:failed_attempts:{ip_address}"
        cache.delete(cache_key)
        
        if user_identifier:
            user_key = f"security:failed_attempts:user:{user_identifier}"
            cache.delete(user_key)
    
    @staticmethod
    def detect_anomalous_activity(user_id: int, activity_type: str) -> bool:
        """
        Detect anomalous user activity.
        
        Args:
            user_id: User ID
            activity_type: Type of activity
            
        Returns:
            bool: True if activity is anomalous
        """
        # In production, implement machine learning or rule-based detection
        # This is a simplified implementation
        cache_key = f"security:activity:{user_id}:{activity_type}"
        activity_count = cache.get(cache_key, 0)
        
        # Example: Alert if more than 100 requests in 1 minute
        if activity_count > 100:
            return True
        
        cache.set(cache_key, activity_count + 1, timeout=60)
        return False

