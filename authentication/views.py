from functools import wraps

from django.contrib.auth import get_user_model
from django.utils.translation import gettext_lazy as _
from rest_framework import status
from rest_framework.decorators import api_view, permission_classes, throttle_classes
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework.exceptions import PermissionDenied
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.throttling import ScopedRateThrottle

from .models import Role
from .serializers import (
    LoginSerializer,
    RoleAssignmentSerializer,
    RoleSerializer,
    UserRegistrationSerializer,
    UserSerializer,
)

User = get_user_model()


def role_required(*role_names):
    """
    Decorator to enforce that a request.user owns at least one of the supplied roles.
    Superusers bypass the check automatically.
    """

    def decorator(func):
        @wraps(func)
        def wrapper(request, *args, **kwargs):
            user = request.user
            if not user or not user.is_authenticated:
                raise PermissionDenied(detail=_("Authentication credentials were not provided."))
            if not user.has_role(*role_names):
                raise PermissionDenied(detail=_("You do not have permission to perform this action."))
            return func(request, *args, **kwargs)

        return wrapper

    return decorator


def _issue_tokens_for_user(user: User) -> dict:
    refresh = RefreshToken.for_user(user)
    return {
        "refresh": str(refresh),
        "access": str(refresh.access_token),
    }


# Registration must stay open to unauthenticated users, so we pair AllowAny
# with ScopedRateThrottle to keep bots from hammering the endpoint.
@api_view(["POST"])
@permission_classes([AllowAny])
@throttle_classes([ScopedRateThrottle])
def register_user(request):
    serializer = UserRegistrationSerializer(data=request.data, context={"request": request})
    serializer.is_valid(raise_exception=True)
    user = serializer.save()
    data = {
        "message": _("Registration successful."),
        "user": UserSerializer(user).data,
        "tokens": _issue_tokens_for_user(user),
    }
    return Response(data, status=status.HTTP_201_CREATED)


# Login is another anonymous entry point; throttling slows down credential
# stuffing while still allowing legitimate users to authenticate.
@api_view(["POST"])
@permission_classes([AllowAny])
@throttle_classes([ScopedRateThrottle])
def login_user(request):
    serializer = LoginSerializer(data=request.data, context={"request": request})
    serializer.is_valid(raise_exception=True)
    user = serializer.validated_data["user"]
    data = {
        "message": _("Login successful."),
        "user": UserSerializer(user).data,
        "tokens": _issue_tokens_for_user(user),
    }
    return Response(data, status=status.HTTP_200_OK)


@api_view(["GET"])
@permission_classes([IsAuthenticated])
def me(request):
    serializer = UserSerializer(request.user)
    return Response(serializer.data, status=status.HTTP_200_OK)


@api_view(["GET"])
@permission_classes([IsAuthenticated])
@role_required("ADMIN")
def list_users(request):
    queryset = User.objects.all().order_by("-created_at")
    serializer = UserSerializer(queryset, many=True)
    return Response(serializer.data, status=status.HTTP_200_OK)


@api_view(["POST"])
@permission_classes([IsAuthenticated])
@role_required("ADMIN")
def assign_roles(request):
    serializer = RoleAssignmentSerializer(data=request.data, context={"request": request})
    serializer.is_valid(raise_exception=True)
    user = serializer.save()
    return Response(
        {
            "message": _("Roles updated successfully."),
            "user": UserSerializer(user).data,
        },
        status=status.HTTP_200_OK,
    )


@api_view(["GET", "POST"])
@permission_classes([IsAuthenticated])
@role_required("ADMIN")
def roles(request):
    if request.method == "GET":
        serializer = RoleSerializer(Role.objects.all(), many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)

    serializer = RoleSerializer(data=request.data)
    serializer.is_valid(raise_exception=True)
    role = serializer.save()
    return Response(RoleSerializer(role).data, status=status.HTTP_201_CREATED)


# Map each throttled view to the rate definitions declared in
# REST_FRAMEWORK['DEFAULT_THROTTLE_RATES']. Using explicit names keeps the
# relationship obvious when security teams review the code.
register_user.throttle_scope = "auth-register"
login_user.throttle_scope = "auth-login"