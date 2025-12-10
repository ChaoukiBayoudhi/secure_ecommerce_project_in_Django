"""
Product models for the secure e-commerce application.

This module defines the Product model which represents items available for sale
in the e-commerce platform. Products include security features such as:
- Soft deletion for audit trails
- Timestamps for tracking creation and updates
- Proper indexing for performance
- Validation for data integrity
"""

from decimal import Decimal
from django.core.validators import MinValueValidator, MaxValueValidator
from django.db import models
from django.utils.translation import gettext_lazy as _


class Product(models.Model):
    """
    Represents a product/item available for sale in the e-commerce platform.
    
    Security Considerations:
    - All prices are stored as Decimal to prevent floating-point errors
    - Stock quantities are validated to be non-negative
    - Soft deletion (is_active) preserves audit trails
    - Timestamps track all changes for compliance
    """
    
    # Basic Information
    name = models.CharField(
        max_length=200,
        help_text=_("Product name (max 200 characters)"),
        db_index=True,  # Indexed for faster searches
    )
    description = models.TextField(
        help_text=_("Detailed product description"),
        blank=True,
    )
    sku = models.CharField(
        max_length=100,
        unique=True,
        help_text=_("Stock Keeping Unit - unique product identifier"),
        db_index=True,
    )
    
    # Pricing Information
    # Using DecimalField to avoid floating-point precision issues
    price = models.DecimalField(
        max_digits=10,
        decimal_places=2,
        validators=[MinValueValidator(Decimal('0.01'))],  # Price must be positive
        help_text=_("Product price in the base currency"),
    )
    
    # Inventory Management
    stock_quantity = models.PositiveIntegerField(
        default=0,
        help_text=_("Current stock quantity available"),
        validators=[MinValueValidator(0)],  # Cannot be negative
    )
    
    # Product Status
    is_active = models.BooleanField(
        default=True,
        help_text=_("If False, product is hidden from customers but preserved for audit"),
    )
    is_featured = models.BooleanField(
        default=False,
        help_text=_("Featured products appear prominently in listings"),
    )
    
    # Seller Information
    # Foreign key to User model (sellers can create products)
    seller = models.ForeignKey(
        'authentication.User',
        on_delete=models.CASCADE,
        related_name='products',
        help_text=_("User who created/owns this product"),
    )
    
    # Metadata
    created_at = models.DateTimeField(
        auto_now_add=True,
        help_text=_("Timestamp when product was created"),
    )
    updated_at = models.DateTimeField(
        auto_now=True,
        help_text=_("Timestamp when product was last updated"),
    )
    
    class Meta:
        ordering = ['-created_at']  # Newest products first
        indexes = [
            models.Index(fields=['name']),  # Fast name searches
            models.Index(fields=['sku']),   # Fast SKU lookups
            models.Index(fields=['is_active', 'is_featured']),  # Filtering
            models.Index(fields=['seller', 'created_at']),  # Seller's products
        ]
        verbose_name = _("Product")
        verbose_name_plural = _("Products")
    
    def __str__(self):
        return f"{self.name} (SKU: {self.sku})"
    
    def is_in_stock(self) -> bool:
        """
        Check if product is currently in stock.
        
        Returns:
            bool: True if stock_quantity > 0, False otherwise
        """
        return self.stock_quantity > 0
    
    def reduce_stock(self, quantity: int) -> bool:
        """
        Reduce stock quantity by specified amount.
        
        Args:
            quantity: Amount to reduce (must be positive)
            
        Returns:
            bool: True if reduction was successful, False if insufficient stock
            
        Security Note:
            This method should be called within a database transaction
            to prevent race conditions in concurrent order processing.
        """
        if quantity <= 0:
            raise ValueError("Quantity must be positive")
        
        if self.stock_quantity < quantity:
            return False
        
        self.stock_quantity -= quantity
        self.save(update_fields=['stock_quantity', 'updated_at'])
        return True
    
    def increase_stock(self, quantity: int) -> None:
        """
        Increase stock quantity by specified amount.
        
        Args:
            quantity: Amount to increase (must be positive)
        """
        if quantity <= 0:
            raise ValueError("Quantity must be positive")
        
        self.stock_quantity += quantity
        self.save(update_fields=['stock_quantity', 'updated_at'])
