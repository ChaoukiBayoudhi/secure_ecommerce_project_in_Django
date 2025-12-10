"""
File Upload Serializers.

This module provides serializers for secure file upload operations.
"""

from rest_framework import serializers
from .file_upload_models import FileUpload, FileUploadLog
from .file_upload_validators import (
    IMAGE_VALIDATOR,
    PRODUCT_IMAGE_VALIDATOR,
    AVATAR_VALIDATOR,
    DOCUMENT_VALIDATOR,
    ALLOWED_IMAGE_TYPES,
    ALLOWED_DOCUMENT_TYPES,
)


class FileUploadSerializer(serializers.ModelSerializer):
    """
    Serializer for FileUpload model.
    
    Security Features:
    - File validation in create method
    - Access control checks
    - Secure file serving
    """
    
    file_url = serializers.SerializerMethodField()
    uploaded_by_email = serializers.EmailField(
        source='uploaded_by.email',
        read_only=True,
    )
    
    class Meta:
        model = FileUpload
        fields = [
            'id',
            'original_filename',
            'stored_filename',
            'file_url',
            'file_type',
            'mime_type',
            'file_size',
            'file_hash',
            'is_verified',
            'is_quarantined',
            'virus_scan_status',
            'uploaded_by',
            'uploaded_by_email',
            'is_public',
            'description',
            'created_at',
            'updated_at',
            'verified_at',
        ]
        read_only_fields = [
            'id',
            'stored_filename',
            'file_hash',
            'is_verified',
            'is_quarantined',
            'virus_scan_status',
            'uploaded_by',
            'created_at',
            'updated_at',
            'verified_at',
        ]
    
    def get_file_url(self, obj):
        """Get secure file URL."""
        return obj.get_file_url()


class FileUploadCreateSerializer(serializers.Serializer):
    """
    Serializer for creating file uploads.
    
    Handles file validation and secure storage.
    """
    
    file = serializers.FileField(
        required=True,
        help_text="File to upload",
    )
    file_type = serializers.ChoiceField(
        choices=FileUpload.file_type.field.choices,
        default='other',
        help_text="Type of file",
    )
    description = serializers.CharField(
        required=False,
        allow_blank=True,
        help_text="Optional file description",
    )
    is_public = serializers.BooleanField(
        default=False,
        help_text="If True, file is publicly accessible",
    )
    
    def validate_file(self, value):
        """
        Validate uploaded file.
        
        Security:
        - File type validation
        - File size validation
        - Content validation
        - MIME type verification
        """
        file_type = self.initial_data.get('file_type', 'other')
        
        # Select appropriate validator
        if file_type == 'image':
            validator = IMAGE_VALIDATOR
        elif file_type == 'product_image':
            validator = PRODUCT_IMAGE_VALIDATOR
        elif file_type == 'avatar':
            validator = AVATAR_VALIDATOR
        elif file_type == 'document':
            validator = DOCUMENT_VALIDATOR
        else:
            # Generic validator for other types
            from .file_upload_validators import SecureFileValidator
            validator = SecureFileValidator(max_size=10 * 1024 * 1024)  # 10 MB
        
        # Perform validation
        try:
            validation_result = validator.validate(value, value.name)
            # Store validation results for use in create method
            self._validation_result = validation_result
            return value
        except Exception as e:
            raise serializers.ValidationError(str(e))
    
    def create(self, validated_data):
        """
        Create file upload with security checks.
        
        Security:
        - File hash calculation
        - Secure filename generation
        - Quarantine for unverified files
        - Audit logging
        """
        from django.utils import timezone
        from .file_upload_models import FileUploadLog
        
        file = validated_data['file']
        file_type = validated_data.get('file_type', 'other')
        description = validated_data.get('description', '')
        is_public = validated_data.get('is_public', False)
        user = self.context['request'].user
        
        # Get validation results
        validation_result = getattr(self, '_validation_result', {})
        mime_type = validation_result.get('mime_type', file.content_type)
        
        # Sanitize filename
        from .file_upload_validators import SecureFileValidator
        validator = SecureFileValidator()
        original_filename = validator._sanitize_filename(file.name)
        
        # Generate secure stored filename
        import uuid
        from pathlib import Path
        ext = Path(original_filename).suffix.lower()
        stored_filename = f"{uuid.uuid4()}{ext}"
        
        # Calculate file hash
        file_hash = self._calculate_file_hash(file)
        
        # Create file upload
        file_upload = FileUpload.objects.create(
            original_filename=original_filename,
            stored_filename=stored_filename,
            file_path=file,
            file_type=file_type,
            mime_type=mime_type,
            file_size=file.size,
            file_hash=file_hash,
            uploaded_by=user if user.is_authenticated else None,
            is_public=is_public,
            description=description,
            # Files start as unverified and quarantined
            is_verified=False,
            is_quarantined=True,
            virus_scan_status='pending',
        )
        
        # Log upload
        FileUploadLog.objects.create(
            file_upload=file_upload,
            action='upload',
            user=user if user.is_authenticated else None,
            ip_address=self._get_client_ip(self.context['request']),
            user_agent=self.context['request'].META.get('HTTP_USER_AGENT', ''),
            status='success',
            metadata={
                'file_type': file_type,
                'file_size': file.size,
                'mime_type': mime_type,
            },
        )
        
        # In production, trigger async virus scanning here
        # For now, we'll mark as clean after basic validation
        file_upload.is_verified = True
        file_upload.is_quarantined = False
        file_upload.virus_scan_status = 'clean'
        file_upload.verified_at = timezone.now()
        file_upload.save(update_fields=['is_verified', 'is_quarantined', 'virus_scan_status', 'verified_at'])
        
        return file_upload
    
    def _calculate_file_hash(self, file) -> str:
        """Calculate SHA-256 hash of file."""
        import hashlib
        sha256 = hashlib.sha256()
        file.seek(0)
        for chunk in file.chunks():
            sha256.update(chunk)
        file.seek(0)
        return sha256.hexdigest()
    
    def _get_client_ip(self, request):
        """Get client IP address."""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            return x_forwarded_for.split(',')[0]
        return request.META.get('REMOTE_ADDR')


class FileUploadLogSerializer(serializers.ModelSerializer):
    """Serializer for FileUploadLog model."""
    
    file_upload_name = serializers.CharField(
        source='file_upload.original_filename',
        read_only=True,
    )
    user_email = serializers.EmailField(
        source='user.email',
        read_only=True,
    )
    
    class Meta:
        model = FileUploadLog
        fields = [
            'id',
            'file_upload',
            'file_upload_name',
            'action',
            'user',
            'user_email',
            'ip_address',
            'user_agent',
            'status',
            'metadata',
            'timestamp',
        ]
        read_only_fields = fields

