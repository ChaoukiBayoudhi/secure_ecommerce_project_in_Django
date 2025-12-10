"""
Product serializers for the secure e-commerce API.

This module provides serializers for Product model with proper validation,
security checks, and data transformation for API responses.
"""

from rest_framework import serializers
from .models import Product


class ProductSerializer(serializers.ModelSerializer):
    """
    Serializer for Product model.
    
    Security Features:
    - Read-only fields prevent tampering with timestamps and IDs
    - Seller is automatically set from request.user
    - Price and stock validation prevent invalid data
    """
    
    # Computed fields
    is_in_stock = serializers.BooleanField(
        read_only=True,
        help_text="True if product has stock available",
    )
    
    # Seller information (read-only in response)
    seller_email = serializers.EmailField(
        source='seller.email',
        read_only=True,
        help_text="Email of the product seller",
    )
    
    class Meta:
        model = Product
        fields = [
            'id',
            'name',
            'description',
            'sku',
            'price',
            'stock_quantity',
            'is_active',
            'is_featured',
            'is_in_stock',
            'seller',
            'seller_email',
            'created_at',
            'updated_at',
        ]
        read_only_fields = [
            'id',
            'seller',
            'created_at',
            'updated_at',
            'is_in_stock',
        ]
    
    def validate_price(self, value):
        """
        Validate price is positive.
        
        Security: Prevents negative or zero prices from being set.
        """
        if value <= 0:
            raise serializers.ValidationError("Price must be greater than zero.")
        return value
    
    def validate_sku(self, value):
        """
        Validate SKU format.
        
        Security: Ensures SKU follows expected format (alphanumeric, hyphens, underscores).
        """
        if not value.replace('-', '').replace('_', '').isalnum():
            raise serializers.ValidationError(
                "SKU must contain only alphanumeric characters, hyphens, and underscores."
            )
        return value.upper()  # Normalize to uppercase
    
    def create(self, validated_data):
        """
        Create a new product.
        
        Security: Automatically set seller to the authenticated user.
        """
        # Set seller to the authenticated user making the request
        validated_data['seller'] = self.context['request'].user
        return super().create(validated_data)


class ProductListSerializer(serializers.ModelSerializer):
    """
    Lightweight serializer for product listings (reduces payload size).
    
    Use this for list views to improve performance.
    """
    
    seller_email = serializers.EmailField(source='seller.email', read_only=True)
    is_in_stock = serializers.BooleanField(read_only=True)
    
    class Meta:
        model = Product
        fields = [
            'id',
            'name',
            'sku',
            'price',
            'stock_quantity',
            'is_in_stock',
            'is_featured',
            'seller_email',
            'created_at',
        ]
        read_only_fields = fields

