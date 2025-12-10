"""
Review ViewSets for the secure e-commerce API.

This module provides ViewSets for Review model with comprehensive
security features including:
- Role-based access control (RBAC)
- One review per customer per product
- Approval workflow for reviews
- Rate limiting
- Audit logging
"""

from django.db.models import Q
from django_filters.rest_framework import DjangoFilterBackend
from rest_framework import viewsets, status
from rest_framework.decorators import action
from rest_framework.permissions import IsAuthenticated, IsAuthenticatedOrReadOnly
from rest_framework.response import Response
from django_ratelimit.decorators import ratelimit
from django.utils.decorators import method_decorator

from .models import Review
from .serializers import ReviewSerializer
from authentication.models import AuditLog


class ReviewViewSet(viewsets.ModelViewSet):
    """
    ViewSet for Review model with comprehensive security.
    
    Security Features:
    - Authentication required for create/update/delete
    - Read access for authenticated and anonymous users (approved reviews only)
    - Customers can only modify their own reviews
    - Admins can approve/reject reviews
    - Rate limiting on write operations
    - Audit logging for all actions
    """
    
    serializer_class = ReviewSerializer
    permission_classes = [IsAuthenticatedOrReadOnly]
    filter_backends = [DjangoFilterBackend]
    filterset_fields = ['product', 'customer', 'rating', 'is_approved']
    ordering = ['-created_at']
    
    def get_queryset(self):
        """
        Filter queryset based on user permissions.
        
        Security:
        - Anonymous users see only approved reviews
        - Authenticated users see their own reviews (even if not approved) + approved reviews
        - Admins see all reviews
        """
        user = self.request.user
        
        # Admins see all reviews
        if user.is_authenticated and (user.is_superuser or user.has_role('ADMIN')):
            return Review.objects.all()
        
        # Authenticated users see their own reviews + approved reviews
        if user.is_authenticated:
            return Review.objects.filter(
                Q(customer=user) | Q(is_approved=True)
            )
        
        # Anonymous users see only approved reviews
        return Review.objects.filter(is_approved=True)
    
    def get_permissions(self):
        """
        Set permissions based on action.
        """
        if self.action in ['create', 'update', 'partial_update', 'destroy']:
            return [IsAuthenticated()]
        return super().get_permissions()
    
    @method_decorator(ratelimit(key='user', rate='10/m', method='POST'))
    @method_decorator(ratelimit(key='ip', rate='20/m', method='POST'))
    def create(self, request, *args, **kwargs):
        """
        Create a new review.
        
        Security:
        - Rate limited: 10 reviews per minute per user, 20 per minute per IP
        - Customer is automatically set to request.user
        - One review per customer per product (enforced by model)
        - Verified purchase flag is set automatically
        - Review requires approval before being visible
        - Audit log is created
        """
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        
        try:
            review = serializer.save()
            
            self._log_action(
                request, 'CREATE', 'REVIEW', str(review.id),
                'SUCCESS', {
                    'product_id': str(review.product.id),
                    'rating': review.rating,
                    'is_verified_purchase': review.is_verified_purchase,
                }
            )
            
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        except Exception as e:
            self._log_action(
                request, 'CREATE', 'REVIEW', None,
                'FAILURE', {'error': str(e)}
            )
            return Response(
                {'detail': f'Failed to create review: {str(e)}'},
                status=status.HTTP_400_BAD_REQUEST
            )
    
    @method_decorator(ratelimit(key='user', rate='20/m', method=['PUT', 'PATCH']))
    def update(self, request, *args, **kwargs):
        """
        Update a review.
        
        Security:
        - Rate limited: 20 updates per minute per user
        - Customers can only update their own reviews
        - Admins can update any review
        - Rating and is_approved cannot be changed by customers
        - Audit log is created
        """
        instance = self.get_object()
        user = request.user
        
        # Check ownership or admin role
        if not (user.is_superuser or user.has_role('ADMIN')):
            if instance.customer != user:
                self._log_action(
                    request, 'UPDATE', 'REVIEW', str(instance.id),
                    'FAILURE', {'reason': 'Permission denied: not owner'}
                )
                return Response(
                    {'detail': 'You can only update your own reviews.'},
                    status=status.HTTP_403_FORBIDDEN
                )
            
            # Customers cannot change rating or approval status
            if 'rating' in request.data or 'is_approved' in request.data:
                return Response(
                    {'detail': 'You cannot change rating or approval status.'},
                    status=status.HTTP_403_FORBIDDEN
                )
        
        self._log_action(request, 'UPDATE', 'REVIEW', str(instance.id), 'SUCCESS')
        return super().update(request, *args, **kwargs)
    
    @method_decorator(ratelimit(key='user', rate='10/m', method='DELETE'))
    def destroy(self, request, *args, **kwargs):
        """
        Delete a review.
        
        Security:
        - Rate limited: 10 deletions per minute per user
        - Customers can only delete their own reviews
        - Admins can delete any review
        - Audit log is created
        """
        instance = self.get_object()
        user = request.user
        
        # Check ownership or admin role
        if not (user.is_superuser or user.has_role('ADMIN')):
            if instance.customer != user:
                self._log_action(
                    request, 'DELETE', 'REVIEW', str(instance.id),
                    'FAILURE', {'reason': 'Permission denied: not owner'}
                )
                return Response(
                    {'detail': 'You can only delete your own reviews.'},
                    status=status.HTTP_403_FORBIDDEN
                )
        
        self._log_action(request, 'DELETE', 'REVIEW', str(instance.id), 'SUCCESS')
        return super().destroy(request, *args, **kwargs)
    
    @action(detail=True, methods=['post'], permission_classes=[IsAuthenticated])
    @method_decorator(ratelimit(key='user', rate='5/m', method='POST'))
    def approve(self, request, pk=None):
        """
        Approve a review (admin only).
        
        Security:
        - Only admins can approve reviews
        - Rate limited: 5 approvals per minute per user
        - Audit log is created
        """
        review = self.get_object()
        user = request.user
        
        # Check admin permission
        if not (user.is_superuser or user.has_role('ADMIN')):
            return Response(
                {'detail': 'Only admins can approve reviews.'},
                status=status.HTTP_403_FORBIDDEN
            )
        
        review.is_approved = True
        review.save(update_fields=['is_approved', 'updated_at'])
        
        self._log_action(
            request, 'APPROVE', 'REVIEW', str(review.id),
            'SUCCESS', {'product_id': str(review.product.id)}
        )
        
        return Response({
            'detail': 'Review approved successfully.',
            'review': ReviewSerializer(review).data,
        })
    
    @action(detail=True, methods=['post'], permission_classes=[IsAuthenticated])
    @method_decorator(ratelimit(key='user', rate='5/m', method='POST'))
    def mark_helpful(self, request, pk=None):
        """
        Mark a review as helpful.
        
        Security:
        - Rate limited: 5 votes per minute per user
        - One vote per user per review (should be enforced in production)
        - Audit log is created
        """
        review = self.get_object()
        
        # In production, track which users marked it helpful to prevent duplicate votes
        review.mark_helpful()
        
        self._log_action(
            request, 'MARK_HELPFUL', 'REVIEW', str(review.id),
            'SUCCESS', {'helpful_count': review.helpful_count}
        )
        
        return Response({
            'detail': 'Review marked as helpful.',
            'helpful_count': review.helpful_count,
        })
    
    def _log_action(self, request, action, resource_type, resource_id, status, metadata=None):
        """
        Helper method to create audit log entries.
        """
        try:
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
        except Exception:
            pass
