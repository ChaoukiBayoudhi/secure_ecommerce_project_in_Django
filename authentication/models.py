from datetime import timedelta

from django.conf import settings
from django.contrib.auth.models import AbstractUser, UserManager
from django.core.validators import RegexValidator
from django.db import models
from django.utils import timezone


class Role(models.Model):
    """
    Represents an authorization role that can be attached to one or more users.
    Roles allow fine-grained control over which resources a user can access.
    """

    name = models.CharField(
        max_length=32,
        unique=True,
        help_text="Unique machine-friendly role identifier, e.g. ADMIN, SUPPORT_AGENT.",
        validators=[
            RegexValidator(
                regex=r"^[A-Z_]{3,32}$",
                message="Role names must be uppercase letters and underscores only (3-32 chars).",
            )
        ],
    )
    display_name = models.CharField(
        max_length=64,
        help_text="Human readable role label shown in UIs.",
    )
    description = models.TextField(
        blank=True,
        help_text="Context about what this role can do and when to grant it.",
    )
    is_active = models.BooleanField(
        default=True,
        help_text="Inactive roles remain for audit history but cannot be newly assigned.",
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ("name",)

    def __str__(self) -> str:
        return self.display_name or self.name


class User(AbstractUser):
    """
    Custom application user model.

    Uses email as the login identifier and layers additional security metadata
    for tracking verification state and login throttling.
    """

    username = models.CharField(
        max_length=50,
        unique=True,
        help_text="3-50 characters. Letters, numbers, underscores, periods and hyphens allowed.",
        validators=[
            RegexValidator(
                regex=r"^[A-Za-z0-9_.-]{3,50}$",
                message="Username must be 3-50 characters and may include letters, numbers, underscores, periods or hyphens.",
            )
        ],
    )
    email = models.EmailField(unique=True)
    phone_number = models.CharField(
        max_length=20,
        blank=True,
        help_text="International E.164 format recommended, e.g. +21612345678.",
        validators=[
            RegexValidator(
                regex=r"^\+?[1-9]\d{7,14}$",
                message="Enter a valid phone number in international format (8-15 digits, optional leading +).",
            )
        ],
    )
    is_verified = models.BooleanField(default=False)
    roles = models.ManyToManyField(
        Role,
        through="UserRole",
        related_name="users",
        blank=True,
        help_text="Collection of authorization roles granted to this account.",
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    failed_login_attempts = models.PositiveIntegerField(default=0)
    last_failed_login = models.DateTimeField(null=True, blank=True)
    account_locked_until = models.DateTimeField(null=True, blank=True)

    USERNAME_FIELD = "email"
    REQUIRED_FIELDS = ["username"]

    objects = UserManager()

    class Meta:
        ordering = ("-created_at",)
        indexes = [
            models.Index(fields=("email",)),
            models.Index(fields=("username",)),
        ]

    def __str__(self) -> str:
        return f"{self.email} ({self.get_full_name() or self.username})"

    @property
    def is_account_locked(self) -> bool:
        return bool(self.account_locked_until and timezone.now() < self.account_locked_until)

    def reset_failed_logins(self) -> None:
        self.failed_login_attempts = 0
        self.last_failed_login = None
        self.account_locked_until = None
        self.save(update_fields=["failed_login_attempts", "last_failed_login", "account_locked_until"])

    def lock_account(self, minutes: int = 15) -> None:
        self.account_locked_until = timezone.now() + timedelta(minutes=minutes)
        self.save(update_fields=["account_locked_until"])

    def has_role(self, *role_names: str) -> bool:
        """
        Quickly check whether the user possesses any of the supplied role names.
        Superusers always return True.
        """
        if self.is_superuser:
            return True
        return self.roles.filter(name__in=role_names, is_active=True).exists()


class UserRole(models.Model):
    """
    Through table that tracks who granted which role to a user and when.
    """

    user = models.ForeignKey(
        User,
        on_delete=models.CASCADE,
        related_name="role_memberships",
    )
    role = models.ForeignKey(
        Role,
        on_delete=models.CASCADE,
        related_name="role_memberships",
    )
    assigned_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="roles_granted",
        help_text="Administrator who granted this role.",
    )
    assigned_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        unique_together = ("user", "role")
        verbose_name = "User role assignment"
        verbose_name_plural = "User role assignments"
        ordering = ("-assigned_at",)

    def __str__(self) -> str:
        return f"{self.user.email} → {self.role.name}"