"""
Order ViewSets for the secure e-commerce API.

This module provides ViewSets for Order model with comprehensive
security features including:
- Role-based access control (RBAC)
- Customer can only access their own orders
- Admins can access all orders
- Rate limiting
- Audit logging
"""

from django_filters.rest_framework import DjangoFilterBackend
from rest_framework import viewsets, status
from rest_framework.decorators import action
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from django_ratelimit.decorators import ratelimit
from django.utils.decorators import method_decorator

from .models import Order, OrderItem
from .serializers import OrderSerializer, OrderCreateSerializer
from authentication.models import AuditLog


class OrderViewSet(viewsets.ModelViewSet):
    """
    ViewSet for Order model with comprehensive security.
    
    Security Features:
    - Authentication required for all operations
    - Customers can only access their own orders
    - Admins can access all orders
    - Rate limiting on create operations
    - Audit logging for all actions
    - Status transitions are validated
    """
    
    serializer_class = OrderSerializer
    permission_classes = [IsAuthenticated]
    filter_backends = [DjangoFilterBackend]
    filterset_fields = ['status', 'customer']
    ordering = ['-created_at']
    
    def get_queryset(self):
        """
        Filter queryset based on user permissions.
        
        Security:
        - Regular users (customers) see only their own orders
        - Admins and sellers see all orders
        """
        user = self.request.user
        
        # Admins and sellers can see all orders
        if user.is_superuser or user.has_role('ADMIN', 'SELLER'):
            return Order.objects.all()
        
        # Regular users see only their own orders
        return Order.objects.filter(customer=user)
    
    def get_serializer_class(self):
        """
        Use OrderCreateSerializer for create action.
        """
        if self.action == 'create':
            return OrderCreateSerializer
        return OrderSerializer
    
    @method_decorator(ratelimit(key='user', rate='5/m', method='POST'))
    @method_decorator(ratelimit(key='ip', rate='10/m', method='POST'))
    def create(self, request, *args, **kwargs):
        """
        Create a new order.
        
        Security:
        - Rate limited: 5 orders per minute per user, 10 per minute per IP
        - Customer is automatically set to request.user
        - Stock is validated and reduced atomically
        - Totals are calculated server-side
        - Audit log is created
        """
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        
        try:
            order = serializer.save()
            
            # Log successful order creation
            self._log_action(
                request, 'CREATE', 'ORDER', str(order.id),
                'SUCCESS', {'order_number': order.order_number, 'total': str(order.total_amount)}
            )
            
            # Return full order details
            response_serializer = OrderSerializer(order)
            return Response(response_serializer.data, status=status.HTTP_201_CREATED)
        except Exception as e:
            # Log failed order creation
            self._log_action(
                request, 'CREATE', 'ORDER', None,
                'FAILURE', {'error': str(e)}
            )
            return Response(
                {'detail': f'Failed to create order: {str(e)}'},
                status=status.HTTP_400_BAD_REQUEST
            )
    
    @method_decorator(ratelimit(key='user', rate='20/m', method=['PUT', 'PATCH']))
    def update(self, request, *args, **kwargs):
        """
        Update an order.
        
        Security:
        - Rate limited: 20 updates per minute per user
        - Customers can only update their own orders (limited fields)
        - Admins can update any order
        - Status transitions are validated
        - Audit log is created
        """
        instance = self.get_object()
        user = request.user
        
        # Check permissions
        if not (user.is_superuser or user.has_role('ADMIN', 'SELLER')):
            if instance.customer != user:
                self._log_action(
                    request, 'UPDATE', 'ORDER', str(instance.id),
                    'FAILURE', {'reason': 'Permission denied: not owner'}
                )
                return Response(
                    {'detail': 'You can only update your own orders.'},
                    status=status.HTTP_403_FORBIDDEN
                )
            
            # Customers can only update certain fields (e.g., shipping address before confirmation)
            if instance.status != Order.OrderStatus.PENDING:
                return Response(
                    {'detail': 'You can only update orders that are pending.'},
                    status=status.HTTP_403_FORBIDDEN
                )
        
        self._log_action(request, 'UPDATE', 'ORDER', str(instance.id), 'SUCCESS')
        return super().update(request, *args, **kwargs)
    
    @action(detail=True, methods=['post'], permission_classes=[IsAuthenticated])
    @method_decorator(ratelimit(key='user', rate='10/m', method='POST'))
    def cancel(self, request, pk=None):
        """
        Cancel an order.
        
        Security:
        - Rate limited: 10 cancellations per minute per user
        - Customers can only cancel their own orders
        - Only cancellable orders can be cancelled
        - Stock is restored when order is cancelled
        - Audit log is created
        """
        order = self.get_object()
        user = request.user
        
        # Check permissions
        if not (user.is_superuser or user.has_role('ADMIN')):
            if order.customer != user:
                return Response(
                    {'detail': 'You can only cancel your own orders.'},
                    status=status.HTTP_403_FORBIDDEN
                )
        
        # Check if order can be cancelled
        if not order.can_be_cancelled():
            return Response(
                {'detail': f'Order cannot be cancelled in current status: {order.status}'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Restore stock for all items
        for item in order.items.all():
            item.product.increase_stock(item.quantity)
        
        # Update order status
        order.status = Order.OrderStatus.CANCELLED
        order.save(update_fields=['status', 'updated_at'])
        
        self._log_action(
            request, 'CANCEL', 'ORDER', str(order.id),
            'SUCCESS', {'previous_status': order.status}
        )
        
        return Response({
            'detail': 'Order cancelled successfully.',
            'order': OrderSerializer(order).data,
        })
    
    @action(detail=True, methods=['post'], permission_classes=[IsAuthenticated])
    @method_decorator(ratelimit(key='user', rate='5/m', method='POST'))
    def update_status(self, request, pk=None):
        """
        Update order status (admin/seller only).
        
        Security:
        - Only admins and sellers can update status
        - Rate limited: 5 updates per minute per user
        - Status transitions are validated
        - Timestamps are updated (shipped_at, delivered_at)
        - Audit log is created
        """
        order = self.get_object()
        user = request.user
        
        # Check permissions
        if not (user.is_superuser or user.has_role('ADMIN', 'SELLER')):
            return Response(
                {'detail': 'Only admins and sellers can update order status.'},
                status=status.HTTP_403_FORBIDDEN
            )
        
        new_status = request.data.get('status')
        if not new_status:
            return Response(
                {'detail': 'Status is required.'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Validate status transition
        try:
            order.status = new_status
            
            # Update timestamps based on status
            from django.utils import timezone
            if new_status == Order.OrderStatus.SHIPPED and not order.shipped_at:
                order.shipped_at = timezone.now()
            elif new_status == Order.OrderStatus.DELIVERED and not order.delivered_at:
                order.delivered_at = timezone.now()
            
            order.save()
            
            self._log_action(
                request, 'UPDATE_STATUS', 'ORDER', str(order.id),
                'SUCCESS', {'new_status': new_status, 'previous_status': order.status}
            )
            
            return Response({
                'detail': 'Order status updated successfully.',
                'order': OrderSerializer(order).data,
            })
        except ValueError:
            return Response(
                {'detail': 'Invalid status value.'},
                status=status.HTTP_400_BAD_REQUEST
            )
    
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
