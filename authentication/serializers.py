from django.conf import settings
from django.contrib.auth import authenticate
from django.contrib.auth.password_validation import validate_password
from django.utils import timezone
from django.utils.translation import gettext_lazy as _
from rest_framework import serializers
from rest_framework.exceptions import AuthenticationFailed

from .models import Role, User, UserRole


class RoleSerializer(serializers.ModelSerializer):
    class Meta:
        model = Role
        fields = [
            "id",
            "name",
            "display_name",
            "description",
            "is_active",
            "created_at",
            "updated_at",
        ]
        read_only_fields = ("id", "created_at", "updated_at")


class UserSerializer(serializers.ModelSerializer):
    roles = RoleSerializer(many=True, read_only=True)

    class Meta:
        model = User
        fields = [
            "id",
            "email",
            "username",
            "first_name",
            "last_name",
            "phone_number",
            "is_active",
            "is_verified",
            "roles",
            "created_at",
            "updated_at",
        ]
        read_only_fields = ("id", "is_active", "created_at", "updated_at")


class UserRegistrationSerializer(serializers.ModelSerializer):
    password = serializers.CharField(
        write_only=True,
        style={"input_type": "password"},
        help_text="Strong password required; will be validated against Django's password validators.",
    )
    password_confirm = serializers.CharField(
        write_only=True,
        style={"input_type": "password"},
    )

    class Meta:
        model = User
        fields = [
            "email",
            "username",
            "first_name",
            "last_name",
            "phone_number",
            "password",
            "password_confirm",
        ]

    def validate_email(self, value: str) -> str:
        return value.lower()

    def validate(self, attrs):
        password = attrs.get("password")
        password_confirm = attrs.pop("password_confirm", None)
        if password != password_confirm:
            raise serializers.ValidationError({"password_confirm": _("Passwords do not match.")})

        validate_password(password)
        return attrs

    def create(self, validated_data):
        password = validated_data.pop("password")

        user = User.objects.create_user(password=password, **validated_data)

        assigning_user = None
        request = self.context.get("request") if self.context else None
        if request and getattr(request, "user", None) and request.user.is_authenticated:
            assigning_user = request.user

        # Assign the least-privileged baseline role so new users cannot self-provision
        # elevated permissions during signup. The name is configurable to make the
        # behavior explicit per environment (e.g., CUSTOMER vs. STUDENT).
        default_role_name = getattr(settings, "DEFAULT_CUSTOMER_ROLE", None)
        if default_role_name:
            try:
                default_role = Role.objects.get(name=default_role_name, is_active=True)
            except Role.DoesNotExist:
                raise serializers.ValidationError(
                    {
                        "non_field_errors": [
                            _(
                                "Default role '%(role)s' is not configured or inactive. "
                                "Ask an administrator to seed roles before registering."
                            )
                            % {"role": default_role_name}
                        ]
                    }
                )

            # Record who (if anyone) granted the default role for auditability.
            UserRole.objects.update_or_create(
                user=user,
                role=default_role,
                defaults={"assigned_by": assigning_user},
            )

        return user


class LoginSerializer(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField(write_only=True, style={"input_type": "password"})

    lockout_threshold = getattr(settings, "AUTH_LOCKOUT_THRESHOLD", 5)
    lockout_minutes = getattr(settings, "AUTH_LOCKOUT_MINUTES", 15)

    def validate(self, attrs):
        email = attrs.get("email").lower()
        password = attrs.get("password")
        request = self.context.get("request")

        try:
            user = User.objects.get(email__iexact=email)
        except User.DoesNotExist:
            raise AuthenticationFailed(_("Invalid credentials."), code="authorization")

        if user.is_account_locked:
            locked_until = timezone.localtime(user.account_locked_until)
            raise AuthenticationFailed(
                _("Account locked due to repeated failures. Try again at %(datetime)s.") % {"datetime": locked_until},
                code="account_locked",
            )

        authenticated_user = authenticate(request, username=email, password=password)
        if not authenticated_user:
            user.failed_login_attempts += 1
            user.last_failed_login = timezone.now()

            if user.failed_login_attempts >= self.lockout_threshold:
                user.lock_account(self.lockout_minutes)
            else:
                user.save(update_fields=["failed_login_attempts", "last_failed_login"])

            raise AuthenticationFailed(_("Invalid credentials."), code="authorization")

        if user.failed_login_attempts:
            user.reset_failed_logins()

        attrs["user"] = authenticated_user
        return attrs


class RoleAssignmentSerializer(serializers.Serializer):
    user_email = serializers.EmailField()
    roles = serializers.ListField(
        child=serializers.CharField(max_length=32),
        allow_empty=False,
        help_text="List of role names (e.g. ADMIN, CUSTOMER) to assign to the user.",
    )

    def validate(self, attrs):
        email = attrs["user_email"].lower()
        try:
            user = User.objects.get(email__iexact=email)
        except User.DoesNotExist:
            raise serializers.ValidationError({"user_email": _("No user found with that email address.")})

        role_names = {role_name.upper() for role_name in attrs["roles"]}
        roles = list(Role.objects.filter(name__in=role_names, is_active=True))
        if len(roles) != len(role_names):
            missing = role_names - {role.name for role in roles}
            raise serializers.ValidationError({"roles": _("Unknown or inactive roles: %(roles)s") % {"roles": ", ".join(sorted(missing))}})

        attrs["user"] = user
        attrs["role_instances"] = roles
        return attrs

    def save(self, **kwargs):
        user = self.validated_data["user"]
        roles = self.validated_data["role_instances"]
        assigning_user = None
        request = self.context.get("request") if self.context else None
        if request and getattr(request, "user", None) and request.user.is_authenticated:
            assigning_user = request.user

        current_role_ids = set(user.roles.values_list("id", flat=True))
        new_role_ids = {role.id for role in roles}

        # Remove roles no longer assigned.
        for role_id in current_role_ids - new_role_ids:
            UserRole.objects.filter(user=user, role_id=role_id).delete()

        # Add or update requested roles.
        for role in roles:
            UserRole.objects.update_or_create(
                user=user,
                role=role,
                defaults={"assigned_by": assigning_user},
            )

        return user
