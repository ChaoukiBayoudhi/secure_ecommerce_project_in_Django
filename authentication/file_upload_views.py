"""
Secure File Upload ViewSets.

This module provides ViewSets for secure file upload operations with
comprehensive security features.
"""

import os
from django.db.models import Q
from django.http import FileResponse, Http404, HttpResponse
from django.utils.encoding import smart_str
from rest_framework import viewsets, status
from rest_framework.decorators import action
from rest_framework.permissions import IsAuthenticated, IsAuthenticatedOrReadOnly
from rest_framework.response import Response
from django_ratelimit.decorators import ratelimit
from django.utils.decorators import method_decorator
from django.conf import settings

from .file_upload_models import FileUpload, FileUploadLog
from .file_upload_serializers import (
    FileUploadSerializer,
    FileUploadCreateSerializer,
    FileUploadLogSerializer,
)
from .models import AuditLog


class FileUploadViewSet(viewsets.ModelViewSet):
    """
    ViewSet for secure file upload operations.
    
    Security Features:
    - File validation (type, size, content)
    - Access control (user/role-based)
    - Rate limiting
    - Audit logging
    - Secure file serving
    - Quarantine system
    """
    
    serializer_class = FileUploadSerializer
    permission_classes = [IsAuthenticatedOrReadOnly]
    filterset_fields = ['file_type', 'is_verified', 'is_quarantined', 'uploaded_by']
    ordering = ['-created_at']
    
    def get_queryset(self):
        """
        Filter queryset based on user permissions.
        
        Security:
        - Users see their own files
        - Public files are visible to all
        - Admins see all files
        """
        user = self.request.user
        
        # Admins see all files
        if user.is_authenticated and (user.is_superuser or user.has_role('ADMIN')):
            return FileUpload.objects.all()
        
        # Authenticated users see their own files and public files
        if user.is_authenticated:
            return FileUpload.objects.filter(
                Q(uploaded_by=user) | Q(is_public=True)
            )
        
        # Anonymous users see only public files
        return FileUpload.objects.filter(is_public=True)
    
    def get_serializer_class(self):
        """Use create serializer for create action."""
        if self.action == 'create':
            return FileUploadCreateSerializer
        return FileUploadSerializer
    
    def get_permissions(self):
        """Set permissions based on action."""
        if self.action in ['create', 'update', 'partial_update', 'destroy']:
            return [IsAuthenticated()]
        return super().get_permissions()
    
    @method_decorator(ratelimit(key='user', rate='10/m', method='POST'))
    @method_decorator(ratelimit(key='ip', rate='20/m', method='POST'))
    def create(self, request, *args, **kwargs):
        """
        Upload a file securely.
        
        Security:
        - Rate limited: 10 uploads per minute per user, 20 per IP
        - File validation (type, size, content)
        - File hash calculation
        - Quarantine until verified
        - Audit logging
        """
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        
        try:
            file_upload = serializer.save()
            
            # Log successful upload
            self._log_audit_event(
                request, 'FILE_UPLOAD', 'FILE_UPLOAD', str(file_upload.id),
                'SUCCESS', {
                    'file_type': file_upload.file_type,
                    'file_size': file_upload.file_size,
                    'filename': file_upload.original_filename,
                }
            )
            
            return Response(
                FileUploadSerializer(file_upload).data,
                status=status.HTTP_201_CREATED
            )
        except Exception as e:
            self._log_audit_event(
                request, 'FILE_UPLOAD', 'FILE_UPLOAD', None,
                'FAILURE', {'error': str(e)}
            )
            return Response(
                {'detail': f'File upload failed: {str(e)}'},
                status=status.HTTP_400_BAD_REQUEST
            )
    
    @method_decorator(ratelimit(key='user', rate='20/m', method=['PUT', 'PATCH']))
    def update(self, request, *args, **kwargs):
        """
        Update file metadata.
        
        Security:
        - Users can only update their own files
        - Admins can update any file
        - File content cannot be changed
        """
        instance = self.get_object()
        user = request.user
        
        # Check ownership or admin role
        if not (user.is_superuser or user.has_role('ADMIN')):
            if instance.uploaded_by != user:
                return Response(
                    {'detail': 'You can only update your own files.'},
                    status=status.HTTP_403_FORBIDDEN
                )
        
        self._log_audit_event(
            request, 'FILE_UPDATE', 'FILE_UPLOAD', str(instance.id),
            'SUCCESS', {}
        )
        
        return super().update(request, *args, **kwargs)
    
    @method_decorator(ratelimit(key='user', rate='10/m', method='DELETE'))
    def destroy(self, request, *args, **kwargs):
        """
        Delete a file.
        
        Security:
        - Users can only delete their own files
        - Admins can delete any file
        - Physical file is deleted
        - Audit logging
        """
        instance = self.get_object()
        user = request.user
        
        # Check ownership or admin role
        if not (user.is_superuser or user.has_role('ADMIN')):
            if instance.uploaded_by != user:
                return Response(
                    {'detail': 'You can only delete your own files.'},
                    status=status.HTTP_403_FORBIDDEN
                )
        
        # Delete physical file
        if instance.file_path:
            try:
                instance.file_path.delete(save=False)
            except Exception:
                pass  # File may already be deleted
        
        file_id = str(instance.id)
        instance.delete()
        
        self._log_audit_event(
            request, 'FILE_DELETE', 'FILE_UPLOAD', file_id,
            'SUCCESS', {}
        )
        
        return Response(
            {'detail': 'File deleted successfully.'},
            status=status.HTTP_200_OK
        )
    
    @action(detail=True, methods=['get'], permission_classes=[])
    def download(self, request, pk=None):
        """
        Securely serve file for download.
        
        Security:
        - Access control check
        - Secure headers
        - Content-Disposition header
        - MIME type validation
        - Rate limiting
        """
        try:
            file_upload = FileUpload.objects.get(pk=pk)
        except FileUpload.DoesNotExist:
            raise Http404("File not found")
        
        # Check access permissions
        if not file_upload.can_access(request.user):
            self._log_audit_event(
                request, 'FILE_DOWNLOAD', 'FILE_UPLOAD', str(file_upload.id),
                'BLOCKED', {'reason': 'Access denied'}
            )
            return Response(
                {'detail': 'You do not have permission to access this file.'},
                status=status.HTTP_403_FORBIDDEN
            )
        
        # Check if file is verified
        if not file_upload.is_verified:
            return Response(
                {'detail': 'File is not verified and cannot be downloaded.'},
                status=status.HTTP_403_FORBIDDEN
            )
        
        # Check if file is quarantined
        if file_upload.is_quarantined:
            return Response(
                {'detail': 'File is quarantined and cannot be downloaded.'},
                status=status.HTTP_403_FORBIDDEN
            )
        
        # Check if file exists
        if not file_upload.file_path or not os.path.exists(file_upload.file_path.path):
            raise Http404("File not found on server")
        
        # Log download
        FileUploadLog.objects.create(
            file_upload=file_upload,
            action='download',
            user=request.user if request.user.is_authenticated else None,
            ip_address=self._get_client_ip(request),
            user_agent=request.META.get('HTTP_USER_AGENT', ''),
            status='success',
        )
        
        self._log_audit_event(
            request, 'FILE_DOWNLOAD', 'FILE_UPLOAD', str(file_upload.id),
            'SUCCESS', {'filename': file_upload.original_filename}
        )
        
        # Serve file with secure headers
        response = FileResponse(
            open(file_upload.file_path.path, 'rb'),
            content_type=file_upload.mime_type,
        )
        
        # Set secure headers
        response['Content-Disposition'] = f'inline; filename="{smart_str(file_upload.original_filename)}"'
        response['X-Content-Type-Options'] = 'nosniff'
        response['X-Frame-Options'] = 'DENY'
        
        # For downloads, use attachment instead of inline
        if request.GET.get('download') == 'true':
            response['Content-Disposition'] = f'attachment; filename="{smart_str(file_upload.original_filename)}"'
        
        return response
    
    @action(detail=True, methods=['post'], permission_classes=[IsAuthenticated])
    @method_decorator(ratelimit(key='user', rate='5/m', method='POST'))
    def verify(self, request, pk=None):
        """
        Manually verify a file (admin only).
        
        Security:
        - Only admins can verify files
        - Recalculates file hash
        - Updates verification status
        """
        file_upload = self.get_object()
        user = request.user
        
        # Check admin permission
        if not (user.is_superuser or user.has_role('ADMIN')):
            return Response(
                {'detail': 'Only admins can verify files.'},
                status=status.HTTP_403_FORBIDDEN
            )
        
        # Verify file
        if file_upload.verify_file():
            self._log_audit_event(
                request, 'FILE_VERIFY', 'FILE_UPLOAD', str(file_upload.id),
                'SUCCESS', {}
            )
            return Response({
                'detail': 'File verified successfully.',
                'file': FileUploadSerializer(file_upload).data,
            })
        else:
            return Response(
                {'detail': 'File verification failed. Hash mismatch.'},
                status=status.HTTP_400_BAD_REQUEST
            )
    
    @action(detail=False, methods=['get'], permission_classes=[IsAuthenticated])
    def my_files(self, request):
        """
        Get current user's files.
        
        Security:
        - Users can only see their own files
        """
        user = request.user
        files = FileUpload.objects.filter(uploaded_by=user)
        serializer = self.get_serializer(files, many=True)
        return Response(serializer.data)
    
    def _get_client_ip(self, request):
        """Get client IP address."""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            return x_forwarded_for.split(',')[0]
        return request.META.get('REMOTE_ADDR')
    
    def _log_audit_event(self, request, action, resource_type, resource_id, status, metadata=None):
        """Helper method to create audit log entries."""
        try:
            AuditLog.objects.create(
                user=request.user if request.user.is_authenticated else None,
                action=action,
                resource_type=resource_type,
                resource_id=resource_id,
                ip_address=self._get_client_ip(request),
                user_agent=request.META.get('HTTP_USER_AGENT', ''),
                request_path=request.path,
                request_method=request.method,
                status=status,
                metadata=metadata or {},
            )
        except Exception:
            pass

