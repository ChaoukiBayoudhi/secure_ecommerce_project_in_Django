"""
Review serializers for the secure e-commerce API.

This module provides serializers for Review model with validation
and security checks.
"""

from rest_framework import serializers
from .models import Review
from products.models import Product


class ReviewSerializer(serializers.ModelSerializer):
    """
    Serializer for Review model.
    
    Security Features:
    - Customer is automatically set from request.user
    - One review per customer per product (enforced by model)
    - Rating is validated (1-5)
    - Approval required for visibility
    """
    
    customer_email = serializers.EmailField(
        source='customer.email',
        read_only=True,
    )
    product_name = serializers.CharField(
        source='product.name',
        read_only=True,
    )
    product_sku = serializers.CharField(
        source='product.sku',
        read_only=True,
    )
    
    class Meta:
        model = Review
        fields = [
            'id',
            'customer',
            'customer_email',
            'product',
            'product_name',
            'product_sku',
            'rating',
            'title',
            'comment',
            'is_approved',
            'is_verified_purchase',
            'helpful_count',
            'created_at',
            'updated_at',
        ]
        read_only_fields = [
            'id',
            'customer',
            'is_approved',
            'helpful_count',
            'created_at',
            'updated_at',
        ]
    
    def validate_rating(self, value):
        """Validate rating is between 1 and 5."""
        if not (1 <= value <= 5):
            raise serializers.ValidationError("Rating must be between 1 and 5.")
        return value
    
    def validate_product(self, value):
        """Validate product exists and is active."""
        if not value.is_active:
            raise serializers.ValidationError("Cannot review inactive products.")
        return value
    
    def create(self, validated_data):
        """
        Create a new review.
        
        Security: Automatically set customer to the authenticated user.
        Also check if customer has purchased the product for verified_purchase flag.
        """
        user = self.context['request'].user
        product = validated_data['product']
        
        # Check if customer has purchased this product
        from orders.models import Order, OrderItem
        has_purchased = OrderItem.objects.filter(
            order__customer=user,
            product=product,
            order__status__in=[
                Order.OrderStatus.CONFIRMED,
                Order.OrderStatus.PROCESSING,
                Order.OrderStatus.SHIPPED,
                Order.OrderStatus.DELIVERED,
            ]
        ).exists()
        
        validated_data['customer'] = user
        validated_data['is_verified_purchase'] = has_purchased
        
        return super().create(validated_data)

