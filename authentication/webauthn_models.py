"""
WebAuthn/Biometric Authentication Models.

This module defines models for storing WebAuthn credentials which enable
biometric authentication including:
- Face recognition
- Fingerprint authentication
- Hardware security keys (FIDO2)
- Platform authenticators
"""

from django.db import models
from django.utils.translation import gettext_lazy as _


class WebAuthnCredential(models.Model):
    """
    Stores WebAuthn credentials for biometric authentication.
    
    WebAuthn enables passwordless authentication using:
    - Face recognition (Face ID, Windows Hello)
    - Fingerprint (Touch ID, Android fingerprint)
    - Hardware security keys (YubiKey, etc.)
    - Platform authenticators
    
    Security Considerations:
    - Credential ID is unique and used for authentication
    - Public key is stored (private key never leaves device)
    - Counter prevents replay attacks
    - Credentials can be revoked (is_active=False)
    """
    
    user = models.ForeignKey(
        'authentication.User',
        on_delete=models.CASCADE,
        related_name='webauthn_credentials',
        help_text=_("User who owns this credential"),
    )
    
    # Credential identification
    credential_id = models.CharField(
        max_length=255,
        unique=True,
        db_index=True,
        help_text=_("Unique credential identifier from WebAuthn"),
    )
    
    # Public key (base64-encoded)
    public_key = models.TextField(
        help_text=_("Public key for signature verification (base64-encoded)"),
    )
    
    # Counter for replay attack prevention
    counter = models.PositiveIntegerField(
        default=0,
        help_text=_("Usage counter (incremented on each authentication)"),
    )
    
    # User-friendly name for the credential
    name = models.CharField(
        max_length=100,
        help_text=_("User-friendly name (e.g., 'iPhone Face ID', 'YubiKey')"),
    )
    
    # Authenticator type
    authenticator_type = models.CharField(
        max_length=50,
        choices=[
            ('platform', _('Platform Authenticator (Face ID, Touch ID, Windows Hello)')),
            ('cross-platform', _('Cross-Platform (Hardware Security Key)')),
        ],
        default='platform',
        help_text=_("Type of authenticator used"),
    )
    
    # Status
    is_active = models.BooleanField(
        default=True,
        help_text=_("If False, credential is revoked and cannot be used"),
    )
    
    # Timestamps
    created_at = models.DateTimeField(
        auto_now_add=True,
        help_text=_("Timestamp when credential was registered"),
    )
    last_used = models.DateTimeField(
        null=True,
        blank=True,
        help_text=_("Timestamp when credential was last used for authentication"),
    )
    
    class Meta:
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['user', 'is_active']),  # User's active credentials
            models.Index(fields=['credential_id']),  # Fast credential lookup
        ]
        verbose_name = _("WebAuthn Credential")
        verbose_name_plural = _("WebAuthn Credentials")
        unique_together = ['user', 'credential_id']
    
    def __str__(self):
        return f"{self.user.email} - {self.name} ({self.authenticator_type})"
    
    def increment_counter(self) -> None:
        """
        Increment usage counter (prevents replay attacks).
        
        Security: Counter must always increase. If a lower counter is received,
        it indicates a potential replay attack.
        """
        from django.utils import timezone
        self.counter += 1
        self.last_used = timezone.now()
        self.save(update_fields=['counter', 'last_used'])


class WebAuthnChallenge(models.Model):
    """
    Stores WebAuthn challenges for registration and authentication.
    
    Security Considerations:
    - Challenges are single-use and time-limited
    - Stored temporarily (should be cleaned up after use)
    - Used to prevent replay attacks
    """
    
    # Challenge identification
    challenge_id = models.CharField(
        max_length=100,
        unique=True,
        db_index=True,
        help_text=_("Unique challenge identifier"),
    )
    
    # Challenge data (base64-encoded)
    challenge = models.TextField(
        help_text=_("Challenge data (base64-encoded)"),
    )
    
    # User (nullable for authentication challenges)
    user = models.ForeignKey(
        'authentication.User',
        on_delete=models.CASCADE,
        null=True,
        blank=True,
        related_name='webauthn_challenges',
        help_text=_("User for registration challenges (null for authentication)"),
    )
    
    # Challenge type
    challenge_type = models.CharField(
        max_length=20,
        choices=[
            ('registration', _('Registration')),
            ('authentication', _('Authentication')),
        ],
        help_text=_("Type of challenge"),
    )
    
    # Expiration
    expires_at = models.DateTimeField(
        help_text=_("Timestamp when challenge expires"),
    )
    
    # Status
    is_used = models.BooleanField(
        default=False,
        help_text=_("If True, challenge has been used and cannot be reused"),
    )
    
    # Timestamp
    created_at = models.DateTimeField(
        auto_now_add=True,
        help_text=_("Timestamp when challenge was created"),
    )
    
    class Meta:
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['challenge_id', 'is_used']),  # Fast lookup
            models.Index(fields=['user', 'challenge_type']),  # User challenges
            models.Index(fields=['expires_at']),  # Cleanup queries
        ]
        verbose_name = _("WebAuthn Challenge")
        verbose_name_plural = _("WebAuthn Challenges")
    
    def __str__(self):
        return f"{self.challenge_type} challenge for {self.user or 'authentication'}"
    
    def is_expired(self) -> bool:
        """
        Check if challenge has expired.
        
        Returns:
            bool: True if challenge is expired, False otherwise
        """
        from django.utils import timezone
        return timezone.now() > self.expires_at
    
    def is_valid(self) -> bool:
        """
        Check if challenge is valid (not used and not expired).
        
        Returns:
            bool: True if challenge is valid, False otherwise
        """
        return not self.is_used and not self.is_expired()

