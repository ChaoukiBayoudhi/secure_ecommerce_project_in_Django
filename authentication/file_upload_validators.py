"""
Secure File Upload Validators.

This module provides comprehensive file validation including:
- File type validation
- File size validation
- Content validation
- MIME type verification
- Image validation
- Malicious content detection
"""

import os
from typing import Tuple, Optional
from django.core.exceptions import ValidationError
from django.utils.translation import gettext_lazy as _

try:
    import magic
    MAGIC_AVAILABLE = True
except ImportError:
    MAGIC_AVAILABLE = False

try:
    from PIL import Image
    PIL_AVAILABLE = True
except ImportError:
    PIL_AVAILABLE = False
    Image = None

import io


# Allowed file types by category
ALLOWED_IMAGE_TYPES = {
    'image/jpeg', 'image/jpg', 'image/png', 'image/gif', 'image/webp', 'image/svg+xml'
}

ALLOWED_DOCUMENT_TYPES = {
    'application/pdf',
    'application/msword',
    'application/vnd.openxmlformats-officedocument.wordprocessingml.document',  # .docx
    'application/vnd.ms-excel',
    'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',  # .xlsx
    'text/plain',
    'text/csv',
}

ALLOWED_PRODUCT_IMAGE_TYPES = {
    'image/jpeg', 'image/jpg', 'image/png', 'image/webp'
}

ALLOWED_AVATAR_TYPES = {
    'image/jpeg', 'image/jpg', 'image/png'
}

# File size limits (in bytes)
MAX_FILE_SIZE = 10 * 1024 * 1024  # 10 MB default
MAX_IMAGE_SIZE = 5 * 1024 * 1024  # 5 MB for images
MAX_AVATAR_SIZE = 2 * 1024 * 1024  # 2 MB for avatars
MAX_PRODUCT_IMAGE_SIZE = 5 * 1024 * 1024  # 5 MB for product images
MAX_DOCUMENT_SIZE = 10 * 1024 * 1024  # 10 MB for documents

# Image dimension limits
MAX_IMAGE_WIDTH = 4096
MAX_IMAGE_HEIGHT = 4096
MIN_IMAGE_WIDTH = 1
MIN_IMAGE_HEIGHT = 1


class SecureFileValidator:
    """
    Comprehensive file validator with security checks.
    
    Security Features:
    - File type validation (extension and MIME type)
    - File size limits
    - Content validation (actual file content, not just extension)
    - Image validation (dimensions, format)
    - Malicious content detection
    - Path traversal prevention
    """
    
    def __init__(
        self,
        allowed_types: Optional[set] = None,
        max_size: int = MAX_FILE_SIZE,
        max_width: Optional[int] = None,
        max_height: Optional[int] = None,
        min_width: Optional[int] = None,
        min_height: Optional[int] = None,
    ):
        """
        Initialize validator.
        
        Args:
            allowed_types: Set of allowed MIME types
            max_size: Maximum file size in bytes
            max_width: Maximum image width (for images)
            max_height: Maximum image height (for images)
            min_width: Minimum image width (for images)
            min_height: Minimum image height (for images)
        """
        self.allowed_types = allowed_types or set()
        self.max_size = max_size
        self.max_width = max_width
        self.max_height = max_height
        self.min_width = min_width
        self.min_height = min_height
    
    def validate_file_size(self, file) -> None:
        """
        Validate file size.
        
        Args:
            file: File object
            
        Raises:
            ValidationError: If file size exceeds limit
        """
        if file.size > self.max_size:
            max_size_mb = self.max_size / (1024 * 1024)
            raise ValidationError(
                _("File size exceeds maximum allowed size of %(size)s MB.") % {'size': max_size_mb}
            )
    
    def validate_file_type(self, file, filename: str) -> str:
        """
        Validate file type by extension and MIME type.
        
        Args:
            file: File object
            filename: Original filename
            
        Returns:
            str: Detected MIME type
            
        Raises:
            ValidationError: If file type is not allowed
        """
        # Get file extension
        ext = os.path.splitext(filename)[1].lower()
        
        # Check extension against allowed types
        if not ext:
            raise ValidationError(_("File must have an extension."))
        
        # Detect MIME type from file content (not just extension)
        try:
            if MAGIC_AVAILABLE:
                file.seek(0)
                file_content = file.read(1024)  # Read first 1KB for MIME detection
                file.seek(0)  # Reset file pointer
                
                # Use python-magic to detect MIME type from content
                mime_type = magic.from_buffer(file_content, mime=True)
            else:
                # Fallback to extension-based detection
                mime_type = self._get_mime_from_extension(ext)
        except Exception:
            # Fallback to extension-based detection
            mime_type = self._get_mime_from_extension(ext)
        
        # Validate MIME type
        if self.allowed_types and mime_type not in self.allowed_types:
            raise ValidationError(
                _("File type '%(type)s' is not allowed. Allowed types: %(allowed)s") % {
                    'type': mime_type,
                    'allowed': ', '.join(sorted(self.allowed_types))
                }
            )
        
        return mime_type
    
    def validate_image(self, file) -> Tuple[int, int]:
        """
        Validate image file and get dimensions.
        
        Args:
            file: File object (must be an image)
            
        Returns:
            tuple: (width, height)
            
        Raises:
            ValidationError: If image is invalid
        """
        if not PIL_AVAILABLE:
            raise ValidationError(_("PIL/Pillow is required for image validation."))
        
        try:
            file.seek(0)
            image = Image.open(file)
            file.seek(0)
            
            # Verify image format
            if image.format not in ['JPEG', 'PNG', 'GIF', 'WEBP']:
                raise ValidationError(_("Invalid image format. Only JPEG, PNG, GIF, and WEBP are allowed."))
            
            # Get dimensions
            width, height = image.size
            
            # Validate dimensions
            if self.max_width and width > self.max_width:
                raise ValidationError(
                    _("Image width (%(width)dpx) exceeds maximum allowed width (%(max)dpx).") % {
                        'width': width,
                        'max': self.max_width
                    }
                )
            
            if self.max_height and height > self.max_height:
                raise ValidationError(
                    _("Image height (%(height)dpx) exceeds maximum allowed height (%(max)dpx).") % {
                        'height': height,
                        'max': self.max_height
                    }
                )
            
            if self.min_width and width < self.min_width:
                raise ValidationError(
                    _("Image width (%(width)dpx) is below minimum allowed width (%(min)dpx).") % {
                        'width': width,
                        'min': self.min_width
                    }
                )
            
            if self.min_height and height < self.min_height:
                raise ValidationError(
                    _("Image height (%(height)dpx) is below minimum allowed height (%(min)dpx).") % {
                        'height': height,
                        'min': self.min_height
                    }
                )
            
            # Verify image is not corrupted
            image.verify()
            
            return width, height
            
        except ValidationError:
            raise
        except Exception as e:
            raise ValidationError(_("Invalid or corrupted image file: %(error)s") % {'error': str(e)})
    
    def validate_content(self, file) -> None:
        """
        Validate file content for malicious patterns.
        
        Args:
            file: File object
            
        Raises:
            ValidationError: If malicious content is detected
        """
        file.seek(0)
        content = file.read()
        file.seek(0)
        
        # Check for suspicious patterns
        suspicious_patterns = [
            b'<?php',
            b'<script',
            b'javascript:',
            b'eval(',
            b'exec(',
            b'system(',
        ]
        
        content_lower = content.lower()
        for pattern in suspicious_patterns:
            if pattern in content_lower:
                raise ValidationError(_("File contains potentially malicious content."))
    
    def validate(self, file, filename: str) -> dict:
        """
        Perform all validation checks.
        
        Args:
            file: File object
            filename: Original filename
            
        Returns:
            dict: Validation results with 'mime_type' and optionally 'width', 'height'
            
        Raises:
            ValidationError: If validation fails
        """
        # Sanitize filename
        filename = self._sanitize_filename(filename)
        
        # Validate file size
        self.validate_file_size(file)
        
        # Validate file type
        mime_type = self.validate_file_type(file, filename)
        
        # Validate content
        self.validate_content(file)
        
        result = {
            'mime_type': mime_type,
            'filename': filename,
        }
        
        # If it's an image, validate image-specific properties
        if mime_type.startswith('image/'):
            width, height = self.validate_image(file)
            result['width'] = width
            result['height'] = height
        
        return result
    
    def _sanitize_filename(self, filename: str) -> str:
        """
        Sanitize filename to prevent path traversal and other attacks.
        
        Args:
            filename: Original filename
            
        Returns:
            str: Sanitized filename
        """
        # Remove path components
        filename = os.path.basename(filename)
        
        # Remove dangerous characters
        dangerous_chars = ['..', '/', '\\', '\x00']
        for char in dangerous_chars:
            filename = filename.replace(char, '')
        
        # Limit length
        if len(filename) > 255:
            name, ext = os.path.splitext(filename)
            filename = name[:250] + ext
        
        return filename
    
    def _get_mime_from_extension(self, ext: str) -> str:
        """
        Get MIME type from file extension (fallback).
        
        Args:
            ext: File extension (with dot)
            
        Returns:
            str: MIME type
        """
        mime_map = {
            '.jpg': 'image/jpeg',
            '.jpeg': 'image/jpeg',
            '.png': 'image/png',
            '.gif': 'image/gif',
            '.webp': 'image/webp',
            '.svg': 'image/svg+xml',
            '.pdf': 'application/pdf',
            '.doc': 'application/msword',
            '.docx': 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
            '.xls': 'application/vnd.ms-excel',
            '.xlsx': 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
            '.txt': 'text/plain',
            '.csv': 'text/csv',
        }
        return mime_map.get(ext.lower(), 'application/octet-stream')


# Pre-configured validators for common file types
IMAGE_VALIDATOR = SecureFileValidator(
    allowed_types=ALLOWED_IMAGE_TYPES,
    max_size=MAX_IMAGE_SIZE,
    max_width=MAX_IMAGE_WIDTH,
    max_height=MAX_IMAGE_HEIGHT,
    min_width=MIN_IMAGE_WIDTH,
    min_height=MIN_IMAGE_HEIGHT,
)

PRODUCT_IMAGE_VALIDATOR = SecureFileValidator(
    allowed_types=ALLOWED_PRODUCT_IMAGE_TYPES,
    max_size=MAX_PRODUCT_IMAGE_SIZE,
    max_width=MAX_IMAGE_WIDTH,
    max_height=MAX_IMAGE_HEIGHT,
    min_width=MIN_IMAGE_WIDTH,
    min_height=MIN_IMAGE_HEIGHT,
)

AVATAR_VALIDATOR = SecureFileValidator(
    allowed_types=ALLOWED_AVATAR_TYPES,
    max_size=MAX_AVATAR_SIZE,
    max_width=512,
    max_height=512,
    min_width=64,
    min_height=64,
)

DOCUMENT_VALIDATOR = SecureFileValidator(
    allowed_types=ALLOWED_DOCUMENT_TYPES,
    max_size=MAX_DOCUMENT_SIZE,
)

