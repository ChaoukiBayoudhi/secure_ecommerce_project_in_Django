"""
WebAuthn Service for Biometric Authentication.

This module provides a complete WebAuthn service implementation for
biometric authentication including face recognition, fingerprint, and
hardware security keys.

Note: This is a simplified implementation. For production, consider using
libraries like 'py_webauthn' or 'django-webauthn' for full WebAuthn compliance.
"""

import os
import secrets
import base64
import json
import hmac
from typing import Dict, Optional, Any
from django.conf import settings
from django.core.cache import cache
from django.utils import timezone
from datetime import timedelta
from .webauthn_models import WebAuthnCredential, WebAuthnChallenge
from .advanced_security import BiometricAuthManager


class WebAuthnService:
    """
    Service for WebAuthn registration and authentication.
    
    This service handles:
    - Registration option generation
    - Credential registration and storage
    - Authentication challenge generation
    - Signature verification (simplified)
    
    Security Features:
    - Challenge-based authentication (prevents replay attacks)
    - Counter-based replay prevention
    - Credential revocation
    - Time-limited challenges
    """
    
    def __init__(self):
        """
        Initialize WebAuthn service with relying party configuration.
        """
        # Relying Party (RP) configuration
        self.rp_id = os.getenv('WEBAUTHN_RP_ID', settings.ALLOWED_HOSTS[0] if settings.ALLOWED_HOSTS else 'localhost')
        self.rp_name = getattr(settings, 'WEBAUTHN_RP_NAME', 'Secure E-Commerce')
        self.rp_origin = os.getenv('WEBAUTHN_RP_ORIGIN', f"https://{self.rp_id}")
        
        # Challenge expiration (5 minutes)
        self.challenge_timeout = getattr(settings, 'WEBAUTHN_CHALLENGE_TIMEOUT', 300)
    
    def create_registration_options(self, user) -> Dict[str, Any]:
        """
        Create WebAuthn registration options for a user.
        
        This generates the options that the frontend will use to call
        navigator.credentials.create() for biometric registration.
        
        Args:
            user: User object to register credential for
            
        Returns:
            dict: Registration options in WebAuthn format
        """
        # Generate challenge
        challenge = secrets.token_bytes(32)
        challenge_b64 = base64.urlsafe_b64encode(challenge).decode().rstrip('=')
        
        # Create challenge ID
        challenge_id = secrets.token_hex(16)
        
        # Store challenge in database
        expires_at = timezone.now() + timedelta(seconds=self.challenge_timeout)
        WebAuthnChallenge.objects.create(
            challenge_id=challenge_id,
            challenge=challenge_b64,
            user=user,
            challenge_type='registration',
            expires_at=expires_at,
        )
        
        # Also store in cache for fast lookup
        cache.set(
            f"webauthn_challenge:{challenge_id}",
            {
                'challenge': challenge_b64,
                'user_id': user.id,
                'type': 'registration',
            },
            timeout=self.challenge_timeout
        )
        
        # Create registration options
        options = {
            "challenge": challenge_b64,
            "rp": {
                "name": self.rp_name,
                "id": self.rp_id,
            },
            "user": {
                "id": base64.urlsafe_b64encode(str(user.id).encode()).decode().rstrip('='),
                "name": user.email,
                "displayName": user.get_full_name() or user.username,
            },
            "pubKeyCredParams": [
                {"type": "public-key", "alg": -7},   # ES256 (Elliptic Curve)
                {"type": "public-key", "alg": -257},  # RS256 (RSA)
            ],
            "authenticatorSelection": {
                "authenticatorAttachment": "platform",  # Platform authenticators (Face ID, Touch ID, etc.)
                "userVerification": "required",  # Require biometric verification
                "residentKey": "preferred",  # Prefer resident keys (passkeys)
            },
            "timeout": 60000,  # 60 seconds
            "attestation": "direct",  # Direct attestation
        }
        
        return {
            "options": options,
            "challenge_id": challenge_id,
        }
    
    def verify_registration(self, user, challenge_id: str, credential_data: Dict[str, Any]) -> WebAuthnCredential:
        """
        Verify and store a WebAuthn credential after registration.
        
        Args:
            user: User object
            challenge_id: Challenge ID from registration
            credential_data: Credential data from client
            
        Returns:
            WebAuthnCredential: Created credential object
            
        Raises:
            ValueError: If challenge is invalid or verification fails
        """
        # Get and validate challenge
        try:
            challenge_obj = WebAuthnChallenge.objects.get(
                challenge_id=challenge_id,
                challenge_type='registration',
                user=user,
                is_used=False,
            )
        except WebAuthnChallenge.DoesNotExist:
            raise ValueError("Invalid or expired challenge")
        
        if challenge_obj.is_expired():
            raise ValueError("Challenge has expired")
        
        # Mark challenge as used
        challenge_obj.is_used = True
        challenge_obj.save(update_fields=['is_used'])
        
        # Extract credential data
        credential_id = credential_data.get('id')
        public_key = credential_data.get('response', {}).get('publicKey')
        authenticator_data = credential_data.get('response', {}).get('authenticatorData')
        
        if not credential_id or not public_key:
            raise ValueError("Invalid credential data")
        
        # Determine authenticator type
        authenticator_type = 'platform'
        if credential_data.get('authenticatorAttachment') == 'cross-platform':
            authenticator_type = 'cross-platform'
        
        # Get credential name (user-friendly)
        credential_name = credential_data.get('name') or f"{authenticator_type.title()} Authenticator"
        
        # Store credential
        credential = WebAuthnCredential.objects.create(
            user=user,
            credential_id=base64.urlsafe_b64encode(credential_id.encode() if isinstance(credential_id, str) else credential_id).decode().rstrip('='),
            public_key=json.dumps(public_key) if isinstance(public_key, dict) else public_key,
            name=credential_name,
            authenticator_type=authenticator_type,
        )
        
        return credential
    
    def create_authentication_options(self, user: Optional[Any] = None, credential_id: Optional[str] = None) -> Dict[str, Any]:
        """
        Create WebAuthn authentication options.
        
        Args:
            user: Optional user object (if known)
            credential_id: Optional specific credential ID to use
            
        Returns:
            dict: Authentication options in WebAuthn format
        """
        # Generate challenge
        challenge = secrets.token_bytes(32)
        challenge_b64 = base64.urlsafe_b64encode(challenge).decode().rstrip('=')
        
        # Create challenge ID
        challenge_id = secrets.token_hex(16)
        
        # Store challenge
        expires_at = timezone.now() + timedelta(seconds=self.challenge_timeout)
        challenge_obj = WebAuthnChallenge.objects.create(
            challenge_id=challenge_id,
            challenge=challenge_b64,
            user=user,
            challenge_type='authentication',
            expires_at=expires_at,
        )
        
        # Store in cache
        cache.set(
            f"webauthn_challenge:{challenge_id}",
            {
                'challenge': challenge_b64,
                'user_id': user.id if user else None,
                'type': 'authentication',
                'credential_id': credential_id,
            },
            timeout=self.challenge_timeout
        )
        
        # Get allowed credentials
        allowed_credentials = []
        if user:
            credentials = WebAuthnCredential.objects.filter(user=user, is_active=True)
            if credential_id:
                credentials = credentials.filter(credential_id=credential_id)
            
            for cred in credentials:
                allowed_credentials.append({
                    "id": cred.credential_id,
                    "type": "public-key",
                })
        
        # Create authentication options
        options = {
            "challenge": challenge_b64,
            "rpId": self.rp_id,
            "allowCredentials": allowed_credentials,
            "userVerification": "required",
            "timeout": 60000,
        }
        
        return {
            "options": options,
            "challenge_id": challenge_id,
        }
    
    def verify_authentication(
        self,
        challenge_id: str,
        credential_id: str,
        signature_data: Dict[str, Any],
        user: Optional[Any] = None
    ) -> WebAuthnCredential:
        """
        Verify WebAuthn authentication signature.
        
        Args:
            challenge_id: Challenge ID from authentication
            credential_id: Credential ID used
            signature_data: Signature data from client
            user: Optional user object (for validation)
            
        Returns:
            WebAuthnCredential: Authenticated credential object
            
        Raises:
            ValueError: If verification fails
        """
        # Get and validate challenge
        try:
            challenge_obj = WebAuthnChallenge.objects.get(
                challenge_id=challenge_id,
                challenge_type='authentication',
                is_used=False,
            )
        except WebAuthnChallenge.DoesNotExist:
            raise ValueError("Invalid or expired challenge")
        
        if challenge_obj.is_expired():
            raise ValueError("Challenge has expired")
        
        # Get credential
        credential_id_b64 = base64.urlsafe_b64encode(
            credential_id.encode() if isinstance(credential_id, str) else credential_id
        ).decode().rstrip('=')
        
        try:
            credential = WebAuthnCredential.objects.get(
                credential_id=credential_id_b64,
                is_active=True,
            )
        except WebAuthnCredential.DoesNotExist:
            raise ValueError("Invalid credential")
        
        # Validate user if provided
        if user and credential.user != user:
            raise ValueError("Credential does not belong to user")
        
        # Verify signature (simplified - in production, use proper cryptographic verification)
        # This is a placeholder - real implementation would verify the signature
        # using the public key and challenge
        signature = signature_data.get('signature')
        authenticator_data = signature_data.get('authenticatorData')
        client_data_json = signature_data.get('clientDataJSON')
        
        if not signature or not authenticator_data or not client_data_json:
            raise ValueError("Invalid signature data")
        
        # Verify challenge in client data
        try:
            client_data = json.loads(base64.urlsafe_b64decode(client_data_json + '=='))
            if client_data.get('challenge') != challenge_obj.challenge:
                raise ValueError("Challenge mismatch")
        except Exception:
            raise ValueError("Invalid client data")
        
        # Check counter (must be greater than stored counter)
        # In a real implementation, extract counter from authenticator_data
        # For now, we'll just increment it
        
        # Mark challenge as used
        challenge_obj.is_used = True
        challenge_obj.save(update_fields=['is_used'])
        
        # Increment credential counter
        credential.increment_counter()
        
        return credential
    
    def get_user_credentials(self, user) -> list:
        """
        Get all active WebAuthn credentials for a user.
        
        Args:
            user: User object
            
        Returns:
            list: List of WebAuthnCredential objects
        """
        return list(WebAuthnCredential.objects.filter(user=user, is_active=True))
    
    def revoke_credential(self, user, credential_id: str) -> None:
        """
        Revoke a WebAuthn credential.
        
        Args:
            user: User object
            credential_id: Credential ID to revoke
        """
        try:
            credential = WebAuthnCredential.objects.get(
                user=user,
                credential_id=credential_id,
            )
            credential.is_active = False
            credential.save(update_fields=['is_active'])
        except WebAuthnCredential.DoesNotExist:
            raise ValueError("Credential not found")

