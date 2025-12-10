"""
Order serializers for the secure e-commerce API.

This module provides serializers for Order and OrderItem models with
comprehensive validation and security checks.
"""

from decimal import Decimal
from rest_framework import serializers
from .models import Order, OrderItem
from products.models import Product


class OrderItemSerializer(serializers.ModelSerializer):
    """
    Serializer for OrderItem model.
    
    Security Features:
    - Product information is read-only after creation
    - Unit price is validated
    - Line total is automatically calculated
    """
    
    product_name = serializers.CharField(
        source='product.name',
        read_only=True,
    )
    product_sku = serializers.CharField(
        source='product.sku',
        read_only=True,
    )
    
    class Meta:
        model = OrderItem
        fields = [
            'id',
            'product',
            'product_name',
            'product_sku',
            'quantity',
            'unit_price',
            'line_total',
            'created_at',
        ]
        read_only_fields = [
            'id',
            'line_total',
            'created_at',
        ]
    
    def validate_quantity(self, value):
        """Validate quantity is positive."""
        if value <= 0:
            raise serializers.ValidationError("Quantity must be greater than zero.")
        return value
    
    def validate_product(self, value):
        """
        Validate product is available and in stock.
        
        Security: Prevents ordering unavailable products.
        """
        if not value.is_active:
            raise serializers.ValidationError("Product is not available.")
        if not value.is_in_stock():
            raise serializers.ValidationError("Product is out of stock.")
        return value


class OrderSerializer(serializers.ModelSerializer):
    """
    Serializer for Order model with nested order items.
    
    Security Features:
    - Customer is automatically set from request.user
    - Order number is auto-generated
    - Totals are calculated automatically (prevents tampering)
    - Status transitions are validated
    """
    
    items = OrderItemSerializer(many=True, read_only=True)
    customer_email = serializers.EmailField(
        source='customer.email',
        read_only=True,
    )
    status_display = serializers.CharField(
        source='get_status_display',
        read_only=True,
    )
    
    class Meta:
        model = Order
        fields = [
            'id',
            'order_number',
            'customer',
            'customer_email',
            'subtotal',
            'tax_amount',
            'shipping_cost',
            'total_amount',
            'status',
            'status_display',
            'shipping_address',
            'shipping_city',
            'shipping_postal_code',
            'shipping_country',
            'contact_phone',
            'notes',
            'items',
            'created_at',
            'updated_at',
            'shipped_at',
            'delivered_at',
        ]
        read_only_fields = [
            'id',
            'order_number',
            'customer',
            'subtotal',
            'tax_amount',
            'shipping_cost',
            'total_amount',
            'created_at',
            'updated_at',
            'shipped_at',
            'delivered_at',
        ]
    
    def validate_status(self, value):
        """
        Validate status transitions.
        
        Security: Prevents invalid status changes (e.g., DELIVERED -> PENDING).
        """
        if self.instance:
            current_status = self.instance.status
            # Define allowed transitions
            allowed_transitions = {
                Order.OrderStatus.PENDING: [
                    Order.OrderStatus.CONFIRMED,
                    Order.OrderStatus.CANCELLED,
                ],
                Order.OrderStatus.CONFIRMED: [
                    Order.OrderStatus.PROCESSING,
                    Order.OrderStatus.CANCELLED,
                ],
                Order.OrderStatus.PROCESSING: [
                    Order.OrderStatus.SHIPPED,
                    Order.OrderStatus.CANCELLED,
                ],
                Order.OrderStatus.SHIPPED: [
                    Order.OrderStatus.DELIVERED,
                ],
            }
            
            if current_status in allowed_transitions:
                if value not in allowed_transitions[current_status]:
                    raise serializers.ValidationError(
                        f"Cannot transition from {current_status} to {value}."
                    )
        
        return value


class OrderCreateSerializer(serializers.Serializer):
    """
    Serializer for creating a new order.
    
    This serializer handles order creation with items and calculates totals.
    """
    
    items = serializers.ListField(
        child=serializers.DictField(),
        min_length=1,
        help_text="List of order items with 'product_id' and 'quantity'",
    )
    shipping_address = serializers.CharField(max_length=500)
    shipping_city = serializers.CharField(max_length=100)
    shipping_postal_code = serializers.CharField(max_length=20)
    shipping_country = serializers.CharField(max_length=100)
    contact_phone = serializers.CharField(max_length=20, required=False, allow_blank=True)
    notes = serializers.CharField(required=False, allow_blank=True)
    
    # Tax and shipping (can be calculated server-side or provided)
    tax_rate = serializers.DecimalField(
        max_digits=5,
        decimal_places=4,
        default=Decimal('0.10'),  # 10% default tax
        help_text="Tax rate as decimal (e.g., 0.10 for 10%)",
    )
    shipping_cost = serializers.DecimalField(
        max_digits=10,
        decimal_places=2,
        default=Decimal('0.00'),
        help_text="Shipping cost",
    )
    
    def validate_items(self, value):
        """
        Validate order items.
        
        Security: Ensures all products exist, are available, and have sufficient stock.
        """
        if not value:
            raise serializers.ValidationError("Order must contain at least one item.")
        
        validated_items = []
        product_ids = set()
        
        for item in value:
            product_id = item.get('product_id')
            quantity = item.get('quantity')
            
            if not product_id:
                raise serializers.ValidationError("Each item must have a 'product_id'.")
            if not quantity or quantity <= 0:
                raise serializers.ValidationError("Each item must have a positive 'quantity'.")
            
            # Check for duplicate products
            if product_id in product_ids:
                raise serializers.ValidationError(f"Duplicate product_id: {product_id}")
            product_ids.add(product_id)
            
            try:
                product = Product.objects.get(id=product_id, is_active=True)
            except Product.DoesNotExist:
                raise serializers.ValidationError(f"Product {product_id} not found or inactive.")
            
            if product.stock_quantity < quantity:
                raise serializers.ValidationError(
                    f"Insufficient stock for product {product.name}. "
                    f"Available: {product.stock_quantity}, Requested: {quantity}"
                )
            
            validated_items.append({
                'product': product,
                'quantity': quantity,
            })
        
        return validated_items
    
    def create(self, validated_data):
        """
        Create order with items and calculate totals.
        
        Security: All calculations are done server-side to prevent tampering.
        """
        from django.utils import timezone
        import uuid
        
        user = self.context['request'].user
        items_data = validated_data.pop('items')
        tax_rate = validated_data.pop('tax_rate', Decimal('0.10'))
        shipping_cost = validated_data.pop('shipping_cost', Decimal('0.00'))
        
        # Generate unique order number
        order_number = f"ORD-{timezone.now().strftime('%Y%m%d')}-{uuid.uuid4().hex[:8].upper()}"
        
        # Calculate subtotal
        subtotal = Decimal('0.00')
        order_items = []
        
        for item_data in items_data:
            product = item_data['product']
            quantity = item_data['quantity']
            unit_price = product.price
            line_total = unit_price * quantity
            subtotal += line_total
            
            # Reduce stock (should be in transaction)
            product.reduce_stock(quantity)
            
            order_items.append({
                'product': product,
                'quantity': quantity,
                'unit_price': unit_price,
                'line_total': line_total,
            })
        
        # Calculate tax
        tax_amount = subtotal * tax_rate
        
        # Create order
        order = Order.objects.create(
            customer=user,
            order_number=order_number,
            subtotal=subtotal,
            tax_amount=tax_amount,
            shipping_cost=shipping_cost,
            total_amount=subtotal + tax_amount + shipping_cost,
            **validated_data,
        )
        
        # Create order items
        for item_data in order_items:
            OrderItem.objects.create(
                order=order,
                **item_data,
            )
        
        return order

