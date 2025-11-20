"""
Authentication app URL declarations.

Keeping this list centralized makes it easy to audit which endpoints are public
(`AllowAny`) versus protected and ensures the project-level router can include
all auth routes with a single `include()` statement.
"""

from django.urls import path

from . import views

urlpatterns = [
    # Public endpoints used during onboarding and login
    path("auth/register/", views.register_user, name="auth-register"),
    path("auth/login/", views.login_user, name="auth-login"),
    path("auth/me/", views.me, name="auth-me"),
    # Administrative operations guarded by the role_required decorator
    path("auth/users/", views.list_users, name="auth-users"),
    path("auth/roles/assign/", views.assign_roles, name="auth-assign-roles"),
    path("auth/roles/", views.roles, name="auth-roles"),
]

