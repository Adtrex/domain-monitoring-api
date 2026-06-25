"""Organisation-scoping helpers and permissions for multi-tenant isolation."""
from rest_framework import permissions
from rest_framework.exceptions import PermissionDenied

from .models import Membership, Organisation, PlatformAdmin


def get_user_membership(user):
    """Return the Membership for a user, or None if they have none."""
    if not user or not user.is_authenticated:
        return None
    return Membership.objects.select_related('organisation').filter(user=user).first()


def is_platform_admin(user):
    """True if the user is a platform-wide super administrator.

    Routed through this single helper so the underlying mechanism (currently a
    dedicated PlatformAdmin row) can change without touching call sites.
    """
    if not user or not getattr(user, 'is_authenticated', False):
        return False
    return PlatformAdmin.objects.filter(user=user).exists()


def requested_org_id(request):
    """Org id a platform admin is explicitly targeting (query param or header)."""
    if request is None:
        return None
    org_id = None
    params = getattr(request, 'query_params', None)
    if params is not None:
        org_id = params.get('organisation_id')
    if not org_id:
        org_id = request.GET.get('organisation_id') if hasattr(request, 'GET') else None
    if not org_id:
        org_id = request.META.get('HTTP_X_ORGANISATION_ID')
    return org_id or None


def get_user_organisation(request):
    """Return the concrete organisation the request should act within.

    - Normal users: their own organisation (403 if none).
    - Platform admins: the organisation named by `organisation_id` (query param or
      `X-Organisation-Id` header). Platform admins are not bound to one org, so a
      concrete target is required for org-scoped write/detail endpoints.
    """
    user = getattr(request, 'user', None)
    if is_platform_admin(user):
        org_id = requested_org_id(request)
        if org_id:
            try:
                return Organisation.objects.get(id=org_id)
            except (Organisation.DoesNotExist, ValueError, TypeError):
                raise PermissionDenied(f'Organisation {org_id} not found.')

        # No explicit target. A platform admin who is also a member of an org
        # (e.g. an owner running scans in their own org via the normal UI) acts
        # within that org by default, so they don't have to send organisation_id
        # on every request. Only require an explicit target when they belong to
        # no org at all.
        membership = get_user_membership(user)
        if membership is not None:
            return membership.organisation

        raise PermissionDenied(
            'Platform admin: specify organisation_id (query param or X-Organisation-Id '
            'header) to act within a specific organisation, or use the /api/admin/ endpoints.'
        )

    membership = get_user_membership(user)
    if membership is None:
        raise PermissionDenied(
            'Your account is not linked to an organisation. Contact your administrator.'
        )
    return membership.organisation


class IsOrgOwnerOrAdmin(permissions.BasePermission):
    """Allow organisation owners/admins (used for member management).

    Platform admins also pass — they have full access to every feature.
    """
    message = 'Only organisation owners or admins can manage members.'

    def has_permission(self, request, view):
        if is_platform_admin(getattr(request, 'user', None)):
            return True
        membership = get_user_membership(getattr(request, 'user', None))
        return bool(membership and membership.can_manage_members)


class IsPlatformAdmin(permissions.BasePermission):
    """Allow only platform-wide super administrators."""
    message = 'Platform administrator access required.'

    def has_permission(self, request, view):
        return is_platform_admin(getattr(request, 'user', None))


class OrganisationScopedMixin:
    """Mixin for ModelViewSets that scopes querysets to the caller's org and
    stamps new objects with that org on create.

    Platform admins are cross-org: they see every organisation's data (optionally
    narrowed with `organisation_id`), and must name a target org to create.
    Assumes the model has an `organisation` FK.
    """

    def get_organisation(self):
        # Concrete org for writes / detail / maintenance. Raises for platform
        # admins who didn't specify organisation_id.
        return get_user_organisation(self.request)

    def scope_queryset(self, queryset):
        user = self.request.user
        if is_platform_admin(user):
            org_id = requested_org_id(self.request)
            return queryset.filter(organisation_id=org_id) if org_id else queryset
        return queryset.filter(organisation=get_user_organisation(self.request))

    def get_queryset(self):
        return self.scope_queryset(super().get_queryset())

    def perform_create(self, serializer):
        serializer.save(organisation=self.get_organisation())
