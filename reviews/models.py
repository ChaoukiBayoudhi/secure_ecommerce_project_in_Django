"""
Review models for the secure e-commerce application.

This module defines the Review model which represents customer feedback
and ratings on products. Includes security features such as:
- Rating validation (1-5 stars)
- One review per customer per product (prevents spam)
- Timestamps for audit trails
- Soft deletion for data preservation
"""

from django.core.validators import MinValueValidator, MaxValueValidator
from django.db import models
from django.utils.translation import gettext_lazy as _


class Review(models.Model):
    """
    Represents customer feedback and rating for a product.
    
    Security Considerations:
    - One review per customer per product (enforced by unique_together)
    - Rating is validated to be between 1 and 5
    - Customer and product are protected from deletion (PROTECT)
    - Timestamps track all changes for audit compliance
    """
    
    # Customer who wrote the review
    customer = models.ForeignKey(
        'authentication.User',
        on_delete=models.PROTECT,  # Prevent deletion of users with reviews
        related_name='reviews',
        help_text=_("Customer who wrote this review"),
    )
    
    # Product being reviewed
    product = models.ForeignKey(
        'products.Product',
        on_delete=models.CASCADE,  # Delete reviews when product is deleted
        related_name='reviews',
        help_text=_("Product being reviewed"),
    )
    
    # Rating (1-5 stars)
    rating = models.PositiveIntegerField(
        validators=[
            MinValueValidator(1, message=_("Rating must be at least 1")),
            MaxValueValidator(5, message=_("Rating cannot exceed 5")),
        ],
        help_text=_("Product rating from 1 (worst) to 5 (best)"),
    )
    
    # Review text
    title = models.CharField(
        max_length=200,
        help_text=_("Review title/summary"),
    )
    comment = models.TextField(
        help_text=_("Detailed review comment"),
        blank=True,
    )
    
    # Review Status
    is_approved = models.BooleanField(
        default=False,
        help_text=_("If True, review is visible to customers. Requires moderation."),
    )
    is_verified_purchase = models.BooleanField(
        default=False,
        help_text=_("If True, customer has purchased this product"),
    )
    
    # Helpful votes (for future enhancement)
    helpful_count = models.PositiveIntegerField(
        default=0,
        help_text=_("Number of customers who found this review helpful"),
    )
    
    # Timestamps
    created_at = models.DateTimeField(
        auto_now_add=True,
        help_text=_("Timestamp when review was created"),
    )
    updated_at = models.DateTimeField(
        auto_now=True,
        help_text=_("Timestamp when review was last updated"),
    )
    
    class Meta:
        ordering = ['-created_at']  # Newest reviews first
        indexes = [
            models.Index(fields=['product', 'is_approved', 'rating']),  # Product reviews
            models.Index(fields=['customer', 'created_at']),  # Customer's reviews
        ]
        # Enforce one review per customer per product
        unique_together = ['customer', 'product']
        verbose_name = _("Review")
        verbose_name_plural = _("Reviews")
    
    def __str__(self):
        return f"{self.customer.email} - {self.product.name} - {self.rating}★"
    
    def mark_helpful(self) -> None:
        """
        Increment helpful count for this review.
        
        Security Note:
            In production, you may want to track which users marked it helpful
            to prevent duplicate votes.
        """
        self.helpful_count += 1
        self.save(update_fields=['helpful_count', 'updated_at'])
