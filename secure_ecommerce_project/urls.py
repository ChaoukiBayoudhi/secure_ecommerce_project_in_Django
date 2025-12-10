"""
URL configuration for secure_ecommerce_project.

This module defines URL patterns for the secure e-commerce API including:
- Authentication endpoints
- Product ViewSet routes
- Order ViewSet routes
- Review ViewSet routes
- Admin interface
- JWT token endpoints
"""

from django.contrib import admin
from django.urls import path, include
from rest_framework.routers import DefaultRouter
from rest_framework_simplejwt.views import (
    TokenObtainPairView,
    TokenRefreshView,
    TokenVerifyView,
)

# Import ViewSets
from products.views import ProductViewSet
from orders.views import OrderViewSet
from reviews.views import ReviewViewSet
from authentication.file_upload_views import FileUploadViewSet
from authentication import views as auth_views
from monitoring import views as monitoring_views
from monitoring.views import (
    DashboardView,
    HealthMetricViewSet,
    AlertViewSet,
    IncidentViewSet,
    AIAgentActionViewSet,
    SystemHealthViewSet,
)

# Create router for ViewSets
router = DefaultRouter()
router.register(r'products', ProductViewSet, basename='product')
router.register(r'orders', OrderViewSet, basename='order')
router.register(r'reviews', ReviewViewSet, basename='review')
router.register(r'files', FileUploadViewSet, basename='file')
router.register(r'monitoring/metrics', HealthMetricViewSet, basename='health-metric')
router.register(r'monitoring/alerts', AlertViewSet, basename='alert')
router.register(r'monitoring/incidents', IncidentViewSet, basename='incident')
router.register(r'monitoring/ai-actions', AIAgentActionViewSet, basename='ai-action')
router.register(r'monitoring/health', SystemHealthViewSet, basename='system-health')

urlpatterns = [
    # Admin interface
    path('admin/', admin.site.urls),
    
    # API routes
    path('api/', include(router.urls)),
    
    # Authentication endpoints
    path('api/auth/register/', auth_views.register_user, name='register'),
    path('api/auth/login/', auth_views.login_user, name='login'),
    path('api/auth/me/', auth_views.me, name='me'),
    path('api/auth/users/', auth_views.list_users, name='list-users'),
    path('api/auth/roles/', auth_views.roles, name='roles'),
    path('api/auth/assign-roles/', auth_views.assign_roles, name='assign-roles'),
    
    # TOTP/MFA endpoints
    path('api/auth/totp/setup/', auth_views.totp_setup, name='totp-setup'),
    path('api/auth/totp/verify/', auth_views.totp_verify, name='totp-verify'),
    path('api/auth/totp/disable/', auth_views.totp_disable, name='totp-disable'),
    
    # WebAuthn/Biometric Authentication endpoints
    path('api/auth/webauthn/register/start/', auth_views.webauthn_register_start, name='webauthn-register-start'),
    path('api/auth/webauthn/register/complete/', auth_views.webauthn_register_complete, name='webauthn-register-complete'),
    path('api/auth/webauthn/authenticate/start/', auth_views.webauthn_authenticate_start, name='webauthn-authenticate-start'),
    path('api/auth/webauthn/authenticate/complete/', auth_views.webauthn_authenticate_complete, name='webauthn-authenticate-complete'),
    path('api/auth/webauthn/credentials/', auth_views.webauthn_credentials, name='webauthn-credentials'),
    path('api/auth/webauthn/revoke/', auth_views.webauthn_revoke, name='webauthn-revoke'),
    
    # JWT token endpoints
    path('api/auth/token/', TokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('api/auth/token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('api/auth/token/verify/', TokenVerifyView.as_view(), name='token_verify'),
    
    # Monitoring Dashboard
    path('api/monitoring/dashboard/', DashboardView.as_view(), name='dashboard'),
    path('monitoring/dashboard/', monitoring_views.dashboard_html, name='dashboard-html'),
]
