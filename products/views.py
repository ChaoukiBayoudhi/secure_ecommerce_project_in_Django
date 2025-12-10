"""
Product ViewSets for the secure e-commerce API.

This module provides ViewSets for Product model with comprehensive
security features including:
- Role-based access control (RBAC)
- Rate limiting
- Input validation
- Audit logging
- Proper permissions
"""

from django_filters.rest_framework import DjangoFilterBackend
from rest_framework import viewsets, filters, status
from rest_framework.decorators import action
from rest_framework.permissions import IsAuthenticated, IsAuthenticatedOrReadOnly
from rest_framework.response import Response
from django_ratelimit.decorators import ratelimit
from django.utils.decorators import method_decorator

from .models import Product
from .serializers import ProductSerializer, ProductListSerializer
from authentication.models import AuditLog


class ProductViewSet(viewsets.ModelViewSet):
    """
    ViewSet for Product model with comprehensive security.
    
    Security Features:
    - Authentication required for create/update/delete
    - Read access for authenticated and anonymous users
    - Seller can only modify their own products
    - Admins can modify any product
    - Rate limiting on write operations
    - Audit logging for all actions
    """
    
    queryset = Product.objects.filter(is_active=True)
    permission_classes = [IsAuthenticatedOrReadOnly]
    filter_backends = [DjangoFilterBackend, filters.SearchFilter, filters.OrderingFilter]
    filterset_fields = ['seller', 'is_featured', 'is_active']
    search_fields = ['name', 'description', 'sku']
    ordering_fields = ['name', 'price', 'created_at', 'stock_quantity']
    ordering = ['-created_at']  # Default ordering
    
    def get_serializer_class(self):
        """
        Use lightweight serializer for list view to improve performance.
        """
        if self.action == 'list':
            return ProductListSerializer
        return ProductSerializer
    
    def get_queryset(self):
        """
        Filter queryset based on user permissions.
        
        Security: Regular users only see active products.
        Sellers see their own products (including inactive).
        Admins see all products.
        """
        queryset = super().get_queryset()
        user = self.request.user
        
        # Admins can see all products
        if user.is_authenticated and (user.is_superuser or user.has_role('ADMIN')):
            return Product.objects.all()
        
        # Sellers can see their own products (including inactive)
        if user.is_authenticated and user.has_role('SELLER'):
            return Product.objects.filter(seller=user) | Product.objects.filter(is_active=True)
        
        # Regular users and anonymous users see only active products
        return queryset.filter(is_active=True)
    
    def get_permissions(self):
        """
        Set permissions based on action.
        
        Security: Write operations require authentication.
        Read operations are allowed for everyone.
        """
        if self.action in ['create', 'update', 'partial_update', 'destroy']:
            return [IsAuthenticated()]
        return super().get_permissions()
    
    @method_decorator(ratelimit(key='user', rate='10/m', method='POST'))
    @method_decorator(ratelimit(key='ip', rate='20/m', method='POST'))
    def create(self, request, *args, **kwargs):
        """
        Create a new product.
        
        Security:
        - Rate limited: 10 per minute per user, 20 per minute per IP
        - Only SELLER or ADMIN roles can create products
        - Seller is automatically set to request.user
        - Audit log is created
        """
        # Check role permission
        if not (request.user.has_role('SELLER', 'ADMIN') or request.user.is_superuser):
            return Response(
                {'detail': 'Only sellers and admins can create products.'},
                status=status.HTTP_403_FORBIDDEN
            )
        
        # Log the action
        self._log_action(request, 'CREATE', 'PRODUCT', None, 'SUCCESS')
        
        return super().create(request, *args, **kwargs)
    
    @method_decorator(ratelimit(key='user', rate='20/m', method=['PUT', 'PATCH']))
    def update(self, request, *args, **kwargs):
        """
        Update a product.
        
        Security:
        - Rate limited: 20 updates per minute per user
        - Sellers can only update their own products
        - Admins can update any product
        - Audit log is created
        """
        instance = self.get_object()
        
        # Check ownership or admin role
        if not (request.user.is_superuser or request.user.has_role('ADMIN')):
            if instance.seller != request.user:
                self._log_action(
                    request, 'UPDATE', 'PRODUCT', str(instance.id),
                    'FAILURE', {'reason': 'Permission denied: not owner'}
                )
                return Response(
                    {'detail': 'You can only update your own products.'},
                    status=status.HTTP_403_FORBIDDEN
                )
        
        self._log_action(request, 'UPDATE', 'PRODUCT', str(instance.id), 'SUCCESS')
        return super().update(request, *args, **kwargs)
    
    @method_decorator(ratelimit(key='user', rate='10/m', method='DELETE'))
    def destroy(self, request, *args, **kwargs):
        """
        Delete (soft delete) a product.
        
        Security:
        - Rate limited: 10 deletions per minute per user
        - Sellers can only delete their own products
        - Admins can delete any product
        - Soft delete (is_active=False) preserves data
        - Audit log is created
        """
        instance = self.get_object()
        
        # Check ownership or admin role
        if not (request.user.is_superuser or request.user.has_role('ADMIN')):
            if instance.seller != request.user:
                self._log_action(
                    request, 'DELETE', 'PRODUCT', str(instance.id),
                    'FAILURE', {'reason': 'Permission denied: not owner'}
                )
                return Response(
                    {'detail': 'You can only delete your own products.'},
                    status=status.HTTP_403_FORBIDDEN
                )
        
        # Soft delete: set is_active=False instead of actual deletion
        instance.is_active = False
        instance.save(update_fields=['is_active', 'updated_at'])
        
        self._log_action(request, 'DELETE', 'PRODUCT', str(instance.id), 'SUCCESS')
        
        return Response(
            {'detail': 'Product deactivated successfully.'},
            status=status.HTTP_200_OK
        )
    
    @action(detail=True, methods=['post'], permission_classes=[IsAuthenticated])
    @method_decorator(ratelimit(key='user', rate='5/m', method='POST'))
    def update_stock(self, request, pk=None):
        """
        Update product stock quantity.
        
        Security:
        - Only product owner or admin can update stock
        - Rate limited: 5 updates per minute per user
        - Audit log is created
        """
        product = self.get_object()
        
        # Check ownership or admin role
        if not (request.user.is_superuser or request.user.has_role('ADMIN')):
            if product.seller != request.user:
                return Response(
                    {'detail': 'You can only update stock for your own products.'},
                    status=status.HTTP_403_FORBIDDEN
                )
        
        quantity = request.data.get('quantity')
        if quantity is None:
            return Response(
                {'detail': 'Quantity is required.'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        try:
            quantity = int(quantity)
            if quantity < 0:
                return Response(
                    {'detail': 'Quantity cannot be negative.'},
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            product.stock_quantity = quantity
            product.save(update_fields=['stock_quantity', 'updated_at'])
            
            self._log_action(
                request, 'UPDATE_STOCK', 'PRODUCT', str(product.id),
                'SUCCESS', {'new_stock': quantity}
            )
            
            return Response({
                'detail': 'Stock updated successfully.',
                'stock_quantity': product.stock_quantity,
            })
        except ValueError:
            return Response(
                {'detail': 'Invalid quantity value.'},
                status=status.HTTP_400_BAD_REQUEST
            )
    
    def _log_action(self, request, action, resource_type, resource_id, status, metadata=None):
        """
        Helper method to create audit log entries.
        
        Args:
            request: HTTP request object
            action: Action type (CREATE, UPDATE, DELETE, etc.)
            resource_type: Type of resource (PRODUCT, ORDER, etc.)
            resource_id: ID of the resource
            status: Status of the action (SUCCESS, FAILURE, BLOCKED)
            metadata: Additional metadata to log
        """
        try:
            # Get client IP address
            x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
            if x_forwarded_for:
                ip_address = x_forwarded_for.split(',')[0]
            else:
                ip_address = request.META.get('REMOTE_ADDR')
            
            AuditLog.objects.create(
                user=request.user if request.user.is_authenticated else None,
                action=action,
                resource_type=resource_type,
                resource_id=resource_id,
                ip_address=ip_address,
                user_agent=request.META.get('HTTP_USER_AGENT', ''),
                request_path=request.path,
                request_method=request.method,
                status=status,
                metadata=metadata or {},
            )
        except Exception as e:
            # Don't fail the request if audit logging fails
            # In production, log this error to monitoring system
            pass
