"""
Secure File Upload Models.

This module defines models for secure file uploads with comprehensive
security features including:
- File type validation
- File size limits
- Content validation
- Virus scanning integration
- Secure storage
- Access control
"""

import os
import hashlib
import uuid
from pathlib import Path
from django.db import models
from django.core.validators import FileExtensionValidator
from django.utils.translation import gettext_lazy as _
from django.conf import settings


def secure_file_upload_path(instance, filename):
    """
    Generate secure file upload path.
    
    Security Features:
    - Uses UUID to prevent filename guessing
    - Organizes by file type
    - Prevents path traversal
    - Separates by user for access control
    
    Args:
        instance: FileUpload instance
        filename: Original filename
        
    Returns:
        str: Secure file path
    """
    # Get file extension
    ext = Path(filename).suffix.lower()
    
    # Generate unique filename using UUID
    unique_filename = f"{uuid.uuid4()}{ext}"
    
    # Organize by file type and user
    user_id = instance.uploaded_by.id if instance.uploaded_by else 'anonymous'
    file_type = instance.file_type or 'other'
    
    # Create path: uploads/{file_type}/{user_id}/{unique_filename}
    return os.path.join('uploads', file_type, str(user_id), unique_filename)


class FileUpload(models.Model):
    """
    Secure file upload model with comprehensive security features.
    
    Security Considerations:
    - Files are stored with UUID-based names (prevents guessing)
    - File types are validated
    - File sizes are limited
    - Content is scanned (if virus scanning enabled)
    - Access is controlled by user/role
    - Original filenames are stored separately
    """
    
    # File Information
    original_filename = models.CharField(
        max_length=255,
        help_text=_("Original filename (sanitized)"),
    )
    stored_filename = models.CharField(
        max_length=255,
        unique=True,
        help_text=_("Stored filename (UUID-based, secure)"),
    )
    file_path = models.FileField(
        upload_to=secure_file_upload_path,
        max_length=500,
        help_text=_("File storage path"),
    )
    
    # File Metadata
    file_type = models.CharField(
        max_length=50,
        choices=[
            ('image', _('Image')),
            ('document', _('Document')),
            ('product_image', _('Product Image')),
            ('avatar', _('Avatar')),
            ('other', _('Other')),
        ],
        default='other',
        help_text=_("Type of file"),
    )
    
    mime_type = models.CharField(
        max_length=100,
        help_text=_("MIME type of the file"),
    )
    
    file_size = models.PositiveIntegerField(
        help_text=_("File size in bytes"),
    )
    
    # Security Information
    file_hash = models.CharField(
        max_length=64,
        db_index=True,
        help_text=_("SHA-256 hash of file content (for integrity verification)"),
    )
    
    is_verified = models.BooleanField(
        default=False,
        help_text=_("If True, file has passed security checks"),
    )
    
    is_quarantined = models.BooleanField(
        default=False,
        help_text=_("If True, file is quarantined pending security review"),
    )
    
    virus_scan_status = models.CharField(
        max_length=20,
        choices=[
            ('pending', _('Pending')),
            ('clean', _('Clean')),
            ('infected', _('Infected')),
            ('error', _('Error')),
        ],
        default='pending',
        help_text=_("Virus scan status"),
    )
    
    # Access Control
    uploaded_by = models.ForeignKey(
        'authentication.User',
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='uploaded_files',
        help_text=_("User who uploaded the file"),
    )
    
    is_public = models.BooleanField(
        default=False,
        help_text=_("If True, file is publicly accessible"),
    )
    
    allowed_roles = models.ManyToManyField(
        'authentication.Role',
        blank=True,
        related_name='accessible_files',
        help_text=_("Roles that can access this file"),
    )
    
    # Metadata
    description = models.TextField(
        blank=True,
        help_text=_("Optional file description"),
    )
    
    # Timestamps
    created_at = models.DateTimeField(
        auto_now_add=True,
        help_text=_("Timestamp when file was uploaded"),
    )
    updated_at = models.DateTimeField(
        auto_now=True,
        help_text=_("Timestamp when file was last updated"),
    )
    verified_at = models.DateTimeField(
        null=True,
        blank=True,
        help_text=_("Timestamp when file was verified"),
    )
    
    class Meta:
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['file_hash']),  # Fast duplicate detection
            models.Index(fields=['uploaded_by', 'created_at']),  # User's files
            models.Index(fields=['file_type', 'is_verified']),  # File type filtering
            models.Index(fields=['virus_scan_status', 'is_quarantined']),  # Security filtering
        ]
        verbose_name = _("File Upload")
        verbose_name_plural = _("File Uploads")
    
    def __str__(self):
        return f"{self.original_filename} ({self.file_type})"
    
    def calculate_hash(self) -> str:
        """
        Calculate SHA-256 hash of file content.
        
        Returns:
            str: SHA-256 hash (hexadecimal)
        """
        if not self.file_path:
            return ""
        
        sha256 = hashlib.sha256()
        self.file_path.seek(0)
        
        # Read file in chunks to handle large files
        for chunk in self.file_path.chunks():
            sha256.update(chunk)
        
        self.file_path.seek(0)  # Reset file pointer
        return sha256.hexdigest()
    
    def verify_file(self) -> bool:
        """
        Verify file integrity and security.
        
        Returns:
            bool: True if file is verified, False otherwise
        """
        from django.utils import timezone
        
        # Calculate and verify hash
        calculated_hash = self.calculate_hash()
        if calculated_hash != self.file_hash:
            return False
        
        # Mark as verified
        self.is_verified = True
        self.verified_at = timezone.now()
        self.save(update_fields=['is_verified', 'verified_at'])
        
        return True
    
    def get_file_url(self) -> str:
        """
        Get secure file URL.
        
        Returns:
            str: File URL (use secure view for serving)
        """
        return f"/api/files/{self.id}/download/"
    
    def can_access(self, user) -> bool:
        """
        Check if user can access this file.
        
        Args:
            user: User object (can be AnonymousUser)
            
        Returns:
            bool: True if user can access, False otherwise
        """
        # Public files are accessible to everyone
        if self.is_public:
            return True
        
        # Uploader can always access
        if user.is_authenticated and self.uploaded_by == user:
            return True
        
        # Check role-based access
        if user.is_authenticated:
            if user.is_superuser:
                return True
            if self.allowed_roles.filter(id__in=user.roles.values_list('id', flat=True)).exists():
                return True
        
        return False


class FileUploadLog(models.Model):
    """
    Audit log for file upload operations.
    
    Tracks all file operations for security monitoring.
    """
    
    file_upload = models.ForeignKey(
        FileUpload,
        on_delete=models.CASCADE,
        related_name='logs',
        help_text=_("File upload being logged"),
    )
    
    action = models.CharField(
        max_length=50,
        choices=[
            ('upload', _('Upload')),
            ('download', _('Download')),
            ('delete', _('Delete')),
            ('verify', _('Verify')),
            ('quarantine', _('Quarantine')),
            ('release', _('Release from Quarantine')),
        ],
        help_text=_("Action performed"),
    )
    
    user = models.ForeignKey(
        'authentication.User',
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='file_operations',
        help_text=_("User who performed the action"),
    )
    
    ip_address = models.GenericIPAddressField(
        null=True,
        blank=True,
        help_text=_("IP address of the user"),
    )
    
    user_agent = models.TextField(
        blank=True,
        help_text=_("User agent string"),
    )
    
    status = models.CharField(
        max_length=20,
        choices=[
            ('success', _('Success')),
            ('failure', _('Failure')),
            ('blocked', _('Blocked')),
        ],
        default='success',
        help_text=_("Status of the operation"),
    )
    
    metadata = models.JSONField(
        default=dict,
        blank=True,
        help_text=_("Additional metadata"),
    )
    
    timestamp = models.DateTimeField(
        auto_now_add=True,
        help_text=_("Timestamp when action occurred"),
    )
    
    class Meta:
        ordering = ['-timestamp']
        indexes = [
            models.Index(fields=['file_upload', 'timestamp']),
            models.Index(fields=['user', 'timestamp']),
            models.Index(fields=['action', 'status']),
        ]
        verbose_name = _("File Upload Log")
        verbose_name_plural = _("File Upload Logs")
    
    def __str__(self):
        return f"{self.action} on {self.file_upload.original_filename} by {self.user or 'Anonymous'}"

