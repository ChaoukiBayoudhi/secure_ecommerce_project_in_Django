from functools import wraps

from django.contrib.auth import get_user_model
from django.utils.translation import gettext_lazy as _
from rest_framework import status
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework.exceptions import PermissionDenied
from rest_framework_simplejwt.tokens import RefreshToken

from .models import Role, AuditLog
from .serializers import (
    LoginSerializer,
    RoleAssignmentSerializer,
    RoleSerializer,
    UserRegistrationSerializer,
    UserSerializer,
)
from .totp_utils import setup_totp_for_user, verify_totp_code, generate_totp_secret
from .webauthn_service import WebAuthnService
from .webauthn_models import WebAuthnCredential

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


@api_view(["POST"])
@permission_classes([AllowAny])
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


@api_view(["POST"])
@permission_classes([AllowAny])
def login_user(request):
    serializer = LoginSerializer(data=request.data, context={"request": request})
    serializer.is_valid(raise_exception=True)
    user = serializer.validated_data["user"]
    totp_code = request.data.get('totp_code', '').strip()
    
    # Check if MFA is enabled for this user
    if user.mfa_enabled:
        # MFA is enabled - require TOTP code
        if not totp_code:
            return Response({
                "message": _("MFA verification required."),
                "mfa_required": True,
                "user": UserSerializer(user).data,
            }, status=status.HTTP_200_OK)
        
        # Verify TOTP code
        if not user.mfa_secret or not verify_totp_code(user.mfa_secret, totp_code):
            # Log failed MFA attempt
            _log_audit_event(
                request, 'LOGIN_MFA_VERIFY', 'USER', str(user.id),
                'FAILURE', {'reason': 'Invalid TOTP code'}
            )
            return Response(
                {"detail": _("Invalid TOTP code. Please try again.")},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # TOTP code verified - log success and issue tokens
        _log_audit_event(
            request, 'LOGIN_MFA_VERIFY', 'USER', str(user.id),
            'SUCCESS', {'mfa_verified': True}
        )
    
    # No MFA required or MFA verified - issue tokens
    data = {
        "message": _("Login successful."),
        "user": UserSerializer(user).data,
        "tokens": _issue_tokens_for_user(user),
        "mfa_required": False,
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


# ============================================================================
# TOTP/MFA ENDPOINTS
# ============================================================================

@api_view(["POST"])
@permission_classes([IsAuthenticated])
def totp_setup(request):
    """
    Set up TOTP (Time-based One-Time Password) for Multi-Factor Authentication.
    
    This endpoint:
    1. Generates a new TOTP secret for the user
    2. Creates a QR code for easy setup with authenticator apps
    3. Returns the secret and QR code (user should verify before enabling)
    
    Security:
    - User must be authenticated
    - Secret is generated server-side
    - User must verify the code before MFA is enabled
    """
    user = request.user
    
    # Check if MFA is already enabled
    if user.mfa_enabled:
        return Response(
            {"detail": _("MFA is already enabled. Disable it first to set up a new secret.")},
            status=status.HTTP_400_BAD_REQUEST
        )
    
    # Set up TOTP
    totp_data = setup_totp_for_user(user)
    
    # Store secret temporarily (user must verify before enabling)
    # In production, you might want to encrypt this
    user.mfa_secret = totp_data['secret']
    user.save(update_fields=['mfa_secret'])
    
    # Log the action
    _log_audit_event(
        request, 'TOTP_SETUP', 'USER', str(user.id),
        'SUCCESS', {'mfa_enabled': False}
    )
    
    return Response({
        "message": _("TOTP setup successful. Scan the QR code with your authenticator app and verify the code."),
        "secret": totp_data['secret'],  # In production, consider not returning this
        "qr_code": totp_data['qr_code'],
        "uri": totp_data['uri'],
        "instructions": _(
            "1. Scan the QR code with an authenticator app (Google Authenticator, Authy, etc.)\n"
            "2. Enter the 6-digit code from the app to verify and enable MFA"
        ),
    }, status=status.HTTP_200_OK)


@api_view(["POST"])
@permission_classes([IsAuthenticated])
def totp_verify(request):
    """
    Verify TOTP code and enable MFA for the user.
    
    This endpoint:
    1. Verifies the TOTP code provided by the user
    2. Enables MFA if verification is successful
    3. Requires the user to provide TOTP code on subsequent logins
    
    Security:
    - User must be authenticated
    - Code must be valid (within time window)
    - MFA is only enabled after successful verification
    """
    user = request.user
    code = request.data.get('code')
    
    if not code:
        return Response(
            {"detail": _("TOTP code is required.")},
            status=status.HTTP_400_BAD_REQUEST
        )
    
    if not user.mfa_secret:
        return Response(
            {"detail": _("TOTP secret not found. Please set up TOTP first.")},
            status=status.HTTP_400_BAD_REQUEST
        )
    
    # Verify the code
    if verify_totp_code(user.mfa_secret, code):
        # Enable MFA
        user.mfa_enabled = True
        user.save(update_fields=['mfa_enabled'])
        
        # Log successful verification
        _log_audit_event(
            request, 'TOTP_VERIFY', 'USER', str(user.id),
            'SUCCESS', {'mfa_enabled': True}
        )
        
        return Response({
            "message": _("MFA enabled successfully. You will need to provide a TOTP code on future logins."),
            "mfa_enabled": True,
        }, status=status.HTTP_200_OK)
    else:
        # Log failed verification
        _log_audit_event(
            request, 'TOTP_VERIFY', 'USER', str(user.id),
            'FAILURE', {'reason': 'Invalid code'}
        )
        
        return Response(
            {"detail": _("Invalid TOTP code. Please try again.")},
            status=status.HTTP_400_BAD_REQUEST
        )


@api_view(["POST"])
@permission_classes([IsAuthenticated])
def totp_disable(request):
    """
    Disable MFA for the user.
    
    This endpoint:
    1. Requires the user to provide their TOTP code for verification
    2. Disables MFA if verification is successful
    3. Clears the TOTP secret
    
    Security:
    - User must be authenticated
    - Requires TOTP code verification before disabling
    - This is a sensitive operation and should be logged
    """
    user = request.user
    
    if not user.mfa_enabled:
        return Response(
            {"detail": _("MFA is not enabled.")},
            status=status.HTTP_400_BAD_REQUEST
        )
    
    # Require TOTP code to disable MFA (security measure)
    code = request.data.get('code')
    if not code:
        return Response(
            {"detail": _("TOTP code is required to disable MFA.")},
            status=status.HTTP_400_BAD_REQUEST
        )
    
    # Verify the code
    if not verify_totp_code(user.mfa_secret, code):
        # Log failed attempt
        _log_audit_event(
            request, 'TOTP_DISABLE', 'USER', str(user.id),
            'FAILURE', {'reason': 'Invalid code'}
        )
        
        return Response(
            {"detail": _("Invalid TOTP code.")},
            status=status.HTTP_400_BAD_REQUEST
        )
    
    # Disable MFA and clear secret
    user.mfa_enabled = False
    user.mfa_secret = ''
    user.save(update_fields=['mfa_enabled', 'mfa_secret'])
    
    # Log successful disable
    _log_audit_event(
        request, 'TOTP_DISABLE', 'USER', str(user.id),
        'SUCCESS', {'mfa_enabled': False}
    )
    
    return Response({
        "message": _("MFA disabled successfully."),
        "mfa_enabled": False,
    }, status=status.HTTP_200_OK)


# ============================================================================
# WEBAUTHN/BIOMETRIC AUTHENTICATION ENDPOINTS
# ============================================================================

@api_view(["POST"])
@permission_classes([IsAuthenticated])
def webauthn_register_start(request):
    """
    Start WebAuthn registration process.
    
    This endpoint generates registration options that the frontend uses
    to call navigator.credentials.create() for biometric registration
    (Face ID, Touch ID, Windows Hello, etc.).
    
    Security:
    - User must be authenticated
    - Challenge is stored and time-limited
    - Returns options for frontend WebAuthn API
    """
    user = request.user
    webauthn_service = WebAuthnService()
    
    try:
        registration_data = webauthn_service.create_registration_options(user)
        
        _log_audit_event(
            request, 'WEBAUTHN_REGISTER_START', 'USER', str(user.id),
            'SUCCESS', {'challenge_id': registration_data['challenge_id']}
        )
        
        return Response({
            "message": _("WebAuthn registration started. Use the options to create a credential."),
            **registration_data,
        }, status=status.HTTP_200_OK)
    except Exception as e:
        _log_audit_event(
            request, 'WEBAUTHN_REGISTER_START', 'USER', str(user.id),
            'FAILURE', {'error': str(e)}
        )
        return Response(
            {"detail": f"Failed to start registration: {str(e)}"},
            status=status.HTTP_400_BAD_REQUEST
        )


@api_view(["POST"])
@permission_classes([IsAuthenticated])
def webauthn_register_complete(request):
    """
    Complete WebAuthn registration by verifying and storing the credential.
    
    This endpoint receives the credential data from the frontend after
    navigator.credentials.create() and stores it for future authentication.
    
    Security:
    - User must be authenticated
    - Challenge is verified
    - Credential is stored securely
    """
    user = request.user
    webauthn_service = WebAuthnService()
    
    challenge_id = request.data.get('challenge_id')
    credential_data = request.data.get('credential')
    
    if not challenge_id or not credential_data:
        return Response(
            {"detail": _("challenge_id and credential are required.")},
            status=status.HTTP_400_BAD_REQUEST
        )
    
    try:
        credential = webauthn_service.verify_registration(user, challenge_id, credential_data)
        
        _log_audit_event(
            request, 'WEBAUTHN_REGISTER_COMPLETE', 'WEBAUTHN_CREDENTIAL', str(credential.id),
            'SUCCESS', {
                'credential_id': credential.credential_id,
                'authenticator_type': credential.authenticator_type,
            }
        )
        
        return Response({
            "message": _("Biometric authentication registered successfully."),
            "credential": {
                "id": credential.id,
                "name": credential.name,
                "authenticator_type": credential.authenticator_type,
                "created_at": credential.created_at,
            },
        }, status=status.HTTP_201_CREATED)
    except ValueError as e:
        _log_audit_event(
            request, 'WEBAUTHN_REGISTER_COMPLETE', 'USER', str(user.id),
            'FAILURE', {'error': str(e)}
        )
        return Response(
            {"detail": str(e)},
            status=status.HTTP_400_BAD_REQUEST
        )


@api_view(["POST"])
@permission_classes([AllowAny])
def webauthn_authenticate_start(request):
    """
    Start WebAuthn authentication process.
    
    This endpoint generates authentication options for passwordless login
    using biometric authentication (Face ID, Touch ID, etc.).
    
    Security:
    - Public endpoint (AllowAny) for login
    - Challenge is stored and time-limited
    - Returns options for frontend WebAuthn API
    """
    webauthn_service = WebAuthnService()
    
    # Optional: user email for credential lookup
    email = request.data.get('email')
    user = None
    if email:
        try:
            user = User.objects.get(email__iexact=email)
        except User.DoesNotExist:
            pass
    
    try:
        auth_data = webauthn_service.create_authentication_options(user=user)
        
        _log_audit_event(
            request, 'WEBAUTHN_AUTH_START', 'USER', str(user.id) if user else None,
            'SUCCESS', {'challenge_id': auth_data['challenge_id']}
        )
        
        return Response({
            "message": _("WebAuthn authentication started. Use the options to authenticate."),
            **auth_data,
        }, status=status.HTTP_200_OK)
    except Exception as e:
        _log_audit_event(
            request, 'WEBAUTHN_AUTH_START', 'USER', str(user.id) if user else None,
            'FAILURE', {'error': str(e)}
        )
        return Response(
            {"detail": f"Failed to start authentication: {str(e)}"},
            status=status.HTTP_400_BAD_REQUEST
        )


@api_view(["POST"])
@permission_classes([AllowAny])
def webauthn_authenticate_complete(request):
    """
    Complete WebAuthn authentication by verifying the signature.
    
    This endpoint receives the authentication data from the frontend after
    navigator.credentials.get() and verifies it to log the user in.
    
    Security:
    - Public endpoint (AllowAny) for login
    - Challenge and signature are verified
    - JWT tokens are issued on success
    """
    webauthn_service = WebAuthnService()
    
    challenge_id = request.data.get('challenge_id')
    credential_id = request.data.get('credential_id')
    signature_data = request.data.get('signature')
    
    if not challenge_id or not credential_id or not signature_data:
        return Response(
            {"detail": _("challenge_id, credential_id, and signature are required.")},
            status=status.HTTP_400_BAD_REQUEST
        )
    
    try:
        credential = webauthn_service.verify_authentication(
            challenge_id=challenge_id,
            credential_id=credential_id,
            signature_data=signature_data,
        )
        
        user = credential.user
        
        # Issue JWT tokens
        tokens = _issue_tokens_for_user(user)
        
        _log_audit_event(
            request, 'WEBAUTHN_AUTH_COMPLETE', 'USER', str(user.id),
            'SUCCESS', {
                'credential_id': credential.credential_id,
                'authenticator_type': credential.authenticator_type,
            }
        )
        
        return Response({
            "message": _("Biometric authentication successful."),
            "user": UserSerializer(user).data,
            "tokens": tokens,
        }, status=status.HTTP_200_OK)
    except ValueError as e:
        _log_audit_event(
            request, 'WEBAUTHN_AUTH_COMPLETE', 'USER', None,
            'FAILURE', {'error': str(e)}
        )
        return Response(
            {"detail": str(e)},
            status=status.HTTP_401_UNAUTHORIZED
        )


@api_view(["GET"])
@permission_classes([IsAuthenticated])
def webauthn_credentials(request):
    """
    List all WebAuthn credentials for the authenticated user.
    
    Security:
    - User can only see their own credentials
    """
    user = request.user
    credentials = WebAuthnCredential.objects.filter(user=user, is_active=True)
    
    return Response({
        "credentials": [
            {
                "id": cred.id,
                "name": cred.name,
                "authenticator_type": cred.authenticator_type,
                "created_at": cred.created_at,
                "last_used": cred.last_used,
            }
            for cred in credentials
        ],
    }, status=status.HTTP_200_OK)


@api_view(["POST"])
@permission_classes([IsAuthenticated])
def webauthn_revoke(request):
    """
    Revoke a WebAuthn credential.
    
    Security:
    - User can only revoke their own credentials
    """
    user = request.user
    credential_id = request.data.get('credential_id')
    
    if not credential_id:
        return Response(
            {"detail": _("credential_id is required.")},
            status=status.HTTP_400_BAD_REQUEST
        )
    
    webauthn_service = WebAuthnService()
    
    try:
        webauthn_service.revoke_credential(user, credential_id)
        
        _log_audit_event(
            request, 'WEBAUTHN_REVOKE', 'WEBAUTHN_CREDENTIAL', credential_id,
            'SUCCESS', {}
        )
        
        return Response({
            "message": _("Credential revoked successfully."),
        }, status=status.HTTP_200_OK)
    except ValueError as e:
        _log_audit_event(
            request, 'WEBAUTHN_REVOKE', 'WEBAUTHN_CREDENTIAL', credential_id,
            'FAILURE', {'error': str(e)}
        )
        return Response(
            {"detail": str(e)},
            status=status.HTTP_400_BAD_REQUEST
        )


def _log_audit_event(request, action, resource_type, resource_id, status, metadata=None):
    """
    Helper function to log audit events.
    
    Args:
        request: HTTP request object
        action: Action type
        resource_type: Resource type
        resource_id: Resource ID
        status: Status (SUCCESS, FAILURE, BLOCKED)
        metadata: Additional metadata
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
            resource_id=str(resource_id) if resource_id else None,
            ip_address=ip_address,
            user_agent=request.META.get('HTTP_USER_AGENT', ''),
            request_path=request.path,
            request_method=request.method,
            status=status,
            metadata=metadata or {},
        )
    except Exception:
        pass