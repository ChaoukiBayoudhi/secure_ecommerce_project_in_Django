"""
Order models for the secure e-commerce application.

This module defines Order and OrderItem models which represent customer
purchase transactions. Includes security features such as:
- Status tracking for order lifecycle
- Financial calculations with Decimal precision
- Foreign key relationships with CASCADE protection
- Timestamps for audit compliance
"""

from decimal import Decimal
from django.core.validators import MinValueValidator
from django.db import models
from django.utils.translation import gettext_lazy as _


class Order(models.Model):
    """
    Represents a customer purchase transaction.
    
    Security Considerations:
    - Total amounts use DecimalField to prevent floating-point errors
    - Status transitions should be validated in business logic
    - Customer information is linked via foreign key (data integrity)
    - All timestamps are automatically managed for audit trails
    """
    
    # Order Status Choices
    class OrderStatus(models.TextChoices):
        PENDING = 'PENDING', _('Pending')
        CONFIRMED = 'CONFIRMED', _('Confirmed')
        PROCESSING = 'PROCESSING', _('Processing')
        SHIPPED = 'SHIPPED', _('Shipped')
        DELIVERED = 'DELIVERED', _('Delivered')
        CANCELLED = 'CANCELLED', _('Cancelled')
        REFUNDED = 'REFUNDED', _('Refunded')
    
    # Customer Information
    customer = models.ForeignKey(
        'authentication.User',
        on_delete=models.PROTECT,  # Prevent deletion of users with orders
        related_name='orders',
        help_text=_("Customer who placed this order"),
    )
    
    # Order Identification
    order_number = models.CharField(
        max_length=50,
        unique=True,
        db_index=True,
        help_text=_("Unique order identifier for customer reference"),
    )
    
    # Financial Information
    # Subtotal before tax and shipping
    subtotal = models.DecimalField(
        max_digits=10,
        decimal_places=2,
        default=Decimal('0.00'),
        validators=[MinValueValidator(Decimal('0.00'))],
        help_text=_("Sum of all order items before tax and shipping"),
    )
    
    # Tax amount
    tax_amount = models.DecimalField(
        max_digits=10,
        decimal_places=2,
        default=Decimal('0.00'),
        validators=[MinValueValidator(Decimal('0.00'))],
        help_text=_("Tax amount calculated for this order"),
    )
    
    # Shipping cost
    shipping_cost = models.DecimalField(
        max_digits=10,
        decimal_places=2,
        default=Decimal('0.00'),
        validators=[MinValueValidator(Decimal('0.00'))],
        help_text=_("Shipping and handling cost"),
    )
    
    # Total amount (subtotal + tax + shipping)
    total_amount = models.DecimalField(
        max_digits=10,
        decimal_places=2,
        validators=[MinValueValidator(Decimal('0.01'))],  # Must be at least 0.01
        help_text=_("Total order amount including tax and shipping"),
    )
    
    # Order Status
    status = models.CharField(
        max_length=20,
        choices=OrderStatus.choices,
        default=OrderStatus.PENDING,
        db_index=True,
        help_text=_("Current status of the order"),
    )
    
    # Shipping Information
    shipping_address = models.TextField(
        help_text=_("Complete shipping address"),
    )
    shipping_city = models.CharField(
        max_length=100,
        help_text=_("Shipping city"),
    )
    shipping_postal_code = models.CharField(
        max_length=20,
        help_text=_("Shipping postal/zip code"),
    )
    shipping_country = models.CharField(
        max_length=100,
        help_text=_("Shipping country"),
    )
    
    # Contact Information
    contact_phone = models.CharField(
        max_length=20,
        blank=True,
        help_text=_("Contact phone number for shipping"),
    )
    
    # Notes
    notes = models.TextField(
        blank=True,
        help_text=_("Additional notes or special instructions"),
    )
    
    # Timestamps
    created_at = models.DateTimeField(
        auto_now_add=True,
        help_text=_("Timestamp when order was created"),
    )
    updated_at = models.DateTimeField(
        auto_now=True,
        help_text=_("Timestamp when order was last updated"),
    )
    shipped_at = models.DateTimeField(
        null=True,
        blank=True,
        help_text=_("Timestamp when order was shipped"),
    )
    delivered_at = models.DateTimeField(
        null=True,
        blank=True,
        help_text=_("Timestamp when order was delivered"),
    )
    
    class Meta:
        ordering = ['-created_at']  # Newest orders first
        indexes = [
            models.Index(fields=['order_number']),  # Fast order lookups
            models.Index(fields=['customer', 'created_at']),  # Customer's orders
            models.Index(fields=['status', 'created_at']),  # Status filtering
        ]
        verbose_name = _("Order")
        verbose_name_plural = _("Orders")
    
    def __str__(self):
        return f"Order {self.order_number} - {self.customer.email} - {self.total_amount}"
    
    def calculate_total(self) -> Decimal:
        """
        Calculate total amount (subtotal + tax + shipping).
        
        Returns:
            Decimal: Total order amount
            
        Note:
            This method calculates but does not save. Call save() after
            updating fields if you want to persist the calculation.
        """
        return self.subtotal + self.tax_amount + self.shipping_cost
    
    def save(self, *args, **kwargs):
        """
        Override save to automatically calculate total_amount.
        
        Security Note:
            Always recalculate total to prevent tampering with amounts.
        """
        # Ensure total is always calculated from components
        self.total_amount = self.calculate_total()
        super().save(*args, **kwargs)
    
    def can_be_cancelled(self) -> bool:
        """
        Check if order can be cancelled.
        
        Returns:
            bool: True if order can be cancelled, False otherwise
        """
        return self.status in [
            self.OrderStatus.PENDING,
            self.OrderStatus.CONFIRMED,
            self.OrderStatus.PROCESSING,
        ]


class OrderItem(models.Model):
    """
    Represents a single product within an order with quantity and price.
    
    Security Considerations:
    - Price is stored at time of order (prevents price changes affecting past orders)
    - Quantity is validated to be positive
    - Foreign keys use CASCADE for order deletion, PROTECT for product deletion
    """
    
    order = models.ForeignKey(
        Order,
        on_delete=models.CASCADE,  # Delete items when order is deleted
        related_name='items',
        help_text=_("Order this item belongs to"),
    )
    
    product = models.ForeignKey(
        'products.Product',
        on_delete=models.PROTECT,  # Prevent deletion of products with orders
        related_name='order_items',
        help_text=_("Product being ordered"),
    )
    
    # Quantity ordered
    quantity = models.PositiveIntegerField(
        validators=[MinValueValidator(1)],  # Must be at least 1
        help_text=_("Quantity of this product in the order"),
    )
    
    # Price at time of order (snapshot to prevent price changes affecting past orders)
    unit_price = models.DecimalField(
        max_digits=10,
        decimal_places=2,
        validators=[MinValueValidator(Decimal('0.01'))],
        help_text=_("Price per unit at time of order (snapshot)"),
    )
    
    # Calculated total for this line item
    line_total = models.DecimalField(
        max_digits=10,
        decimal_places=2,
        validators=[MinValueValidator(Decimal('0.01'))],
        help_text=_("Total for this line item (quantity × unit_price)"),
    )
    
    # Timestamps
    created_at = models.DateTimeField(
        auto_now_add=True,
        help_text=_("Timestamp when order item was created"),
    )
    
    class Meta:
        ordering = ['created_at']
        indexes = [
            models.Index(fields=['order', 'product']),  # Fast lookups
        ]
        verbose_name = _("Order Item")
        verbose_name_plural = _("Order Items")
        # Prevent duplicate products in same order (business rule)
        unique_together = ['order', 'product']
    
    def __str__(self):
        return f"{self.quantity}x {self.product.name} in Order {self.order.order_number}"
    
    def calculate_line_total(self) -> Decimal:
        """
        Calculate line total (quantity × unit_price).
        
        Returns:
            Decimal: Total for this line item
        """
        return Decimal(self.quantity) * self.unit_price
    
    def save(self, *args, **kwargs):
        """
        Override save to automatically calculate line_total.
        
        Security Note:
            Always recalculate to prevent tampering with line totals.
        """
        self.line_total = self.calculate_line_total()
        super().save(*args, **kwargs)
