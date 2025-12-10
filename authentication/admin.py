"""
Django admin configuration for authentication models.
"""

from django.contrib import admin
from django.contrib.auth import get_user_model
from .models import Role, UserRole, AuditLog
from .webauthn_models import WebAuthnCredential, WebAuthnChallenge
from .file_upload_models import FileUpload, FileUploadLog

User = get_user_model()


@admin.register(User)
class UserAdmin(admin.ModelAdmin):
    """Admin interface for User model."""
    list_display = ['email', 'username', 'is_verified', 'mfa_enabled', 'is_active', 'created_at']
    list_filter = ['is_verified', 'mfa_enabled', 'is_active', 'is_superuser']
    search_fields = ['email', 'username', 'first_name', 'last_name']
    readonly_fields = ['created_at', 'updated_at', 'last_login', 'date_joined']
    # Note: 'roles' uses a through model (UserRole), so filter_horizontal cannot be used
    # Use UserRoleAdmin to manage user roles instead


@admin.register(Role)
class RoleAdmin(admin.ModelAdmin):
    """Admin interface for Role model."""
    list_display = ['name', 'display_name', 'is_active', 'created_at']
    list_filter = ['is_active']
    search_fields = ['name', 'display_name']


@admin.register(UserRole)
class UserRoleAdmin(admin.ModelAdmin):
    """Admin interface for UserRole model."""
    list_display = ['user', 'role', 'assigned_by', 'assigned_at']
    list_filter = ['role', 'assigned_at']
    search_fields = ['user__email', 'role__name']


@admin.register(AuditLog)
class AuditLogAdmin(admin.ModelAdmin):
    """Admin interface for AuditLog model."""
    list_display = ['action', 'resource_type', 'user', 'status', 'ip_address', 'timestamp']
    list_filter = ['action', 'resource_type', 'status', 'timestamp']
    search_fields = ['user__email', 'ip_address', 'action', 'resource_type']
    readonly_fields = ['timestamp', 'user', 'action', 'resource_type', 'resource_id', 
                       'ip_address', 'user_agent', 'request_path', 'request_method', 
                       'status', 'metadata']
    date_hierarchy = 'timestamp'
    
    def has_add_permission(self, request):
        """Prevent manual creation of audit logs."""
        return False


@admin.register(WebAuthnCredential)
class WebAuthnCredentialAdmin(admin.ModelAdmin):
    """Admin interface for WebAuthnCredential model."""
    list_display = ['user', 'name', 'authenticator_type', 'is_active', 'counter', 'created_at', 'last_used']
    list_filter = ['authenticator_type', 'is_active', 'created_at']
    search_fields = ['user__email', 'name', 'credential_id']
    readonly_fields = ['credential_id', 'public_key', 'counter', 'created_at', 'last_used']


@admin.register(WebAuthnChallenge)
class WebAuthnChallengeAdmin(admin.ModelAdmin):
    """Admin interface for WebAuthnChallenge model."""
    list_display = ['challenge_id', 'user', 'challenge_type', 'is_used', 'expires_at', 'created_at']
    list_filter = ['challenge_type', 'is_used', 'created_at']
    search_fields = ['challenge_id', 'user__email']
    readonly_fields = ['challenge_id', 'challenge', 'created_at', 'expires_at']


@admin.register(FileUpload)
class FileUploadAdmin(admin.ModelAdmin):
    """Admin interface for FileUpload model."""
    list_display = ['original_filename', 'file_type', 'uploaded_by', 'is_verified', 'is_quarantined', 'virus_scan_status', 'created_at']
    list_filter = ['file_type', 'is_verified', 'is_quarantined', 'virus_scan_status', 'created_at']
    search_fields = ['original_filename', 'stored_filename', 'uploaded_by__email']
    readonly_fields = ['stored_filename', 'file_hash', 'created_at', 'updated_at', 'verified_at']
    filter_horizontal = ['allowed_roles']


@admin.register(FileUploadLog)
class FileUploadLogAdmin(admin.ModelAdmin):
    """Admin interface for FileUploadLog model."""
    list_display = ['file_upload', 'action', 'user', 'status', 'ip_address', 'timestamp']
    list_filter = ['action', 'status', 'timestamp']
    search_fields = ['file_upload__original_filename', 'user__email', 'ip_address']
    readonly_fields = ['timestamp']
    date_hierarchy = 'timestamp'
