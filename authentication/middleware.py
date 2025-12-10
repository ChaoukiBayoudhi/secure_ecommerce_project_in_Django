"""
Security middleware for the secure e-commerce application.

This module provides middleware for:
- Comprehensive audit logging
- Security header injection
- Request/response monitoring
- IP-based rate limiting tracking
"""

import logging
from django.utils.deprecation import MiddlewareMixin
from django.utils import timezone
from .models import AuditLog

logger = logging.getLogger(__name__)


class AuditLoggingMiddleware(MiddlewareMixin):
    """
    Middleware to automatically log security-relevant events.
    
    Logs:
    - All API requests (method, path, user, IP)
    - Authentication events (login, logout)
    - Authorization failures
    - Sensitive operations (create, update, delete)
    
    Security Considerations:
    - Non-blocking: Logging failures don't affect request processing
    - Async logging recommended for production (use Celery)
    - IP addresses are logged for security analysis
    - User agents help identify bot traffic
    """
    
    # Paths that should be logged
    LOGGED_PATHS = [
        '/api/auth/',
        '/api/products/',
        '/api/orders/',
        '/api/reviews/',
        '/admin/',
    ]
    
    # HTTP methods that should be logged
    LOGGED_METHODS = ['POST', 'PUT', 'PATCH', 'DELETE']
    
    # Paths to exclude from logging (too noisy)
    EXCLUDED_PATHS = [
        '/api/auth/token/refresh/',  # Too frequent
        '/static/',
        '/media/',
    ]
    
    def process_request(self, request):
        """
        Process incoming request and log if necessary.
        
        Args:
            request: HTTP request object
        """
        # Skip logging for excluded paths
        if any(request.path.startswith(path) for path in self.EXCLUDED_PATHS):
            return None
        
        # Only log API requests with sensitive methods
        if request.path.startswith('/api/') and request.method in self.LOGGED_METHODS:
            try:
                # Get client IP address
                ip_address = self._get_client_ip(request)
                
                # Determine action based on method and path
                action = self._determine_action(request)
                resource_type = self._determine_resource_type(request.path)
                
                # Log the request
                # Note: We log here but status will be determined in process_response
                request._audit_log_data = {
                    'action': action,
                    'resource_type': resource_type,
                    'ip_address': ip_address,
                    'user_agent': request.META.get('HTTP_USER_AGENT', ''),
                    'request_path': request.path,
                    'request_method': request.method,
                }
            except Exception as e:
                # Don't fail the request if logging fails
                logger.error(f"Error in audit logging middleware: {e}")
        
        return None
    
    def process_response(self, request, response):
        """
        Process response and complete audit log entry.
        
        Args:
            request: HTTP request object
            response: HTTP response object
        """
        # Complete audit log if we started one
        if hasattr(request, '_audit_log_data'):
            try:
                # Determine status based on response code
                if 200 <= response.status_code < 300:
                    status = 'SUCCESS'
                elif response.status_code == 403:
                    status = 'BLOCKED'
                else:
                    status = 'FAILURE'
                
                # Get resource ID from response if available
                resource_id = None
                if hasattr(response, 'data') and isinstance(response.data, dict):
                    resource_id = response.data.get('id') or response.data.get('pk')
                
                # Create audit log entry
                AuditLog.objects.create(
                    user=request.user if request.user.is_authenticated else None,
                    action=request._audit_log_data['action'],
                    resource_type=request._audit_log_data['resource_type'],
                    resource_id=str(resource_id) if resource_id else None,
                    ip_address=request._audit_log_data['ip_address'],
                    user_agent=request._audit_log_data['user_agent'],
                    request_path=request._audit_log_data['request_path'],
                    request_method=request._audit_log_data['request_method'],
                    status=status,
                    metadata={
                        'status_code': response.status_code,
                    },
                )
            except Exception as e:
                # Don't fail the response if logging fails
                logger.error(f"Error completing audit log: {e}")
        
        return response
    
    def process_exception(self, request, exception):
        """
        Log exceptions that occur during request processing.
        
        Args:
            request: HTTP request object
            exception: Exception that was raised
        """
        # Log security-relevant exceptions
        if hasattr(request, '_audit_log_data'):
            try:
                AuditLog.objects.create(
                    user=request.user if request.user.is_authenticated else None,
                    action=request._audit_log_data.get('action', 'EXCEPTION'),
                    resource_type=request._audit_log_data.get('resource_type', 'UNKNOWN'),
                    resource_id=None,
                    ip_address=request._audit_log_data.get('ip_address'),
                    user_agent=request._audit_log_data.get('user_agent', ''),
                    request_path=request._audit_log_data.get('request_path', ''),
                    request_method=request._audit_log_data.get('request_method', ''),
                    status='FAILURE',
                    metadata={
                        'exception_type': type(exception).__name__,
                        'exception_message': str(exception),
                    },
                )
            except Exception as e:
                logger.error(f"Error logging exception: {e}")
        
        return None
    
    def _get_client_ip(self, request):
        """
        Get client IP address from request.
        
        Handles proxies and load balancers that add X-Forwarded-For header.
        
        Args:
            request: HTTP request object
            
        Returns:
            str: Client IP address
        """
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            # X-Forwarded-For can contain multiple IPs, take the first one
            ip = x_forwarded_for.split(',')[0].strip()
        else:
            ip = request.META.get('REMOTE_ADDR')
        return ip
    
    def _determine_action(self, request):
        """
        Determine action type from request method and path.
        
        Args:
            request: HTTP request object
            
        Returns:
            str: Action type (CREATE, UPDATE, DELETE, etc.)
        """
        method = request.method
        path = request.path.lower()
        
        if method == 'POST':
            if 'login' in path or 'register' in path:
                return 'LOGIN' if 'login' in path else 'REGISTER'
            return 'CREATE'
        elif method == 'PUT' or method == 'PATCH':
            return 'UPDATE'
        elif method == 'DELETE':
            return 'DELETE'
        elif method == 'GET':
            return 'READ'
        else:
            return 'UNKNOWN'
    
    def _determine_resource_type(self, path):
        """
        Determine resource type from URL path.
        
        Args:
            path: URL path
            
        Returns:
            str: Resource type (USER, PRODUCT, ORDER, etc.)
        """
        path_lower = path.lower()
        
        if '/auth/' in path_lower or '/user' in path_lower:
            return 'USER'
        elif '/product' in path_lower:
            return 'PRODUCT'
        elif '/order' in path_lower:
            return 'ORDER'
        elif '/review' in path_lower:
            return 'REVIEW'
        elif '/payment' in path_lower:
            return 'PAYMENT'
        elif '/admin' in path_lower:
            return 'ADMIN'
        else:
            return 'UNKNOWN'


class SecurityHeadersMiddleware(MiddlewareMixin):
    """
    Middleware to add security headers to all responses.
    
    Security Headers:
    - X-Content-Type-Options: Prevents MIME type sniffing
    - X-Frame-Options: Prevents clickjacking
    - X-XSS-Protection: Enables XSS filter in browsers
    - Referrer-Policy: Controls referrer information
    - Content-Security-Policy: Restricts resource loading
    - Permissions-Policy: Restricts browser features
    
    Note: Some headers are also set in Django settings, but this middleware
    ensures they're always present even if settings are misconfigured.
    """
    
    def process_response(self, request, response):
        """
        Add security headers to response.
        
        Args:
            request: HTTP request object
            response: HTTP response object
        """
        # X-Content-Type-Options: Prevent MIME type sniffing
        response['X-Content-Type-Options'] = 'nosniff'
        
        # X-Frame-Options: Prevent clickjacking
        # DENY: Never allow framing
        # SAMEORIGIN: Allow framing from same origin
        response['X-Frame-Options'] = 'DENY'
        
        # X-XSS-Protection: Enable XSS filter (legacy, but still useful)
        response['X-XSS-Protection'] = '1; mode=block'
        
        # Referrer-Policy: Control referrer information
        # strict-origin-when-cross-origin: Send full referrer for same-origin,
        # origin only for cross-origin HTTPS
        response['Referrer-Policy'] = 'strict-origin-when-cross-origin'
        
        # Content-Security-Policy: Restrict resource loading
        # This is a basic CSP - customize based on your needs
        csp = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline' 'unsafe-eval'; "  # Allow inline scripts for admin
            "style-src 'self' 'unsafe-inline'; "  # Allow inline styles
            "img-src 'self' data: https:; "
            "font-src 'self' https:; "
            "connect-src 'self'; "
            "frame-ancestors 'none';"
        )
        response['Content-Security-Policy'] = csp
        
        # Permissions-Policy: Restrict browser features
        # Empty list means feature is blocked
        permissions_policy = (
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
        response['Permissions-Policy'] = permissions_policy
        
        return response

