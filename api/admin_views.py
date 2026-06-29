"""Platform-admin (super-admin) API: cross-org oversight, org/owner provisioning,
platform dashboard and the audit activity feed.

Every endpoint here requires a platform administrator (IsPlatformAdmin).
"""
from datetime import timedelta

from django.contrib.auth import get_user_model
from django.db.models import Count
from django.utils import timezone
from rest_framework import status
from rest_framework.pagination import PageNumberPagination
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from .models import (
    Organisation, Membership, Invitation, AuditLog,
    Domain, Asset, Scan, Finding,
)
from .permissions import IsPlatformAdmin
from .audit import log_action
from .auth_views import send_invitation_email
from .admin_serializers import (
    AdminOrganisationSerializer, AdminOrganisationCreateSerializer,
    AdminUserSerializer, AuditLogSerializer,
)

User = get_user_model()


class AdminPagination(PageNumberPagination):
    page_size = 25
    page_size_query_param = 'page_size'
    max_page_size = 200


class AdminOrganisationListCreateView(APIView):
    """GET all organisations (with rollup counts) / POST create one (+ invite owner)."""
    permission_classes = [IsAuthenticated, IsPlatformAdmin]

    def get(self, request):
        orgs = Organisation.objects.all().order_by('name')
        return Response(AdminOrganisationSerializer(orgs, many=True).data)

    def post(self, request):
        serializer = AdminOrganisationCreateSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        org = Organisation.objects.create(name=serializer.validated_data['name'])
        log_action('org.create', request=request, organisation=org, target=org.name)

        # Assign the primary domain first so the serialized result reflects it.
        primary_domain = (serializer.validated_data.get('primary_domain') or '').strip()
        domain_result = None
        if primary_domain:
            domain_result = _assign_primary_domain(request, org, primary_domain)

        result = AdminOrganisationSerializer(org).data
        if domain_result is not None:
            result['primary_domain_created'] = domain_result

        owner_email = (serializer.validated_data.get('owner_email') or '').strip()
        if owner_email:
            result['owner_invite'] = _invite_owner(request, org, owner_email)

        return Response(result, status=status.HTTP_201_CREATED)


class AdminOrganisationDetailView(APIView):
    """GET / PATCH (rename) / DELETE a single organisation."""
    permission_classes = [IsAuthenticated, IsPlatformAdmin]

    def _get(self, pk):
        return Organisation.objects.filter(pk=pk).first()

    def get(self, request, pk):
        org = self._get(pk)
        if not org:
            return Response({'error': 'Organisation not found'}, status=status.HTTP_404_NOT_FOUND)
        return Response(AdminOrganisationSerializer(org).data)

    def patch(self, request, pk):
        org = self._get(pk)
        if not org:
            return Response({'error': 'Organisation not found'}, status=status.HTTP_404_NOT_FOUND)
        name = (request.data.get('name') or '').strip()
        if name:
            if Organisation.objects.filter(name__iexact=name).exclude(pk=org.pk).exists():
                return Response({'error': 'An organisation with this name already exists.'},
                                status=status.HTTP_400_BAD_REQUEST)
            org.name = name
            org.save()
            log_action('org.rename', request=request, organisation=org, target=name)
        return Response(AdminOrganisationSerializer(org).data)

    def delete(self, request, pk):
        org = self._get(pk)
        if not org:
            return Response({'error': 'Organisation not found'}, status=status.HTTP_404_NOT_FOUND)
        name = org.name
        org.delete()  # cascades the org's data
        log_action('org.delete', request=request, target=name)
        return Response(status=status.HTTP_204_NO_CONTENT)


class AdminOrganisationOwnerView(APIView):
    """POST invite (or add) an owner for an organisation, by email."""
    permission_classes = [IsAuthenticated, IsPlatformAdmin]

    def post(self, request, pk):
        org = Organisation.objects.filter(pk=pk).first()
        if not org:
            return Response({'error': 'Organisation not found'}, status=status.HTTP_404_NOT_FOUND)
        email = (request.data.get('email') or '').strip()
        role = (request.data.get('role') or 'owner').strip()
        if not email:
            return Response({'error': 'email is required'}, status=status.HTTP_400_BAD_REQUEST)
        if role not in {choice[0] for choice in Membership.ROLE_CHOICES}:
            return Response({'error': 'invalid role'}, status=status.HTTP_400_BAD_REQUEST)
        if Membership.objects.filter(organisation=org, user__email__iexact=email).exists():
            return Response({'error': 'A member with this email already exists in this organisation.'},
                            status=status.HTTP_400_BAD_REQUEST)
        return Response(_invite_owner(request, org, email, role=role),
                        status=status.HTTP_201_CREATED)


def _normalize_root_domain(value):
    value = (value or '').strip().lower().rstrip('/')
    if '://' in value:
        value = value.split('://', 1)[1]
    return value.split('/', 1)[0].split(':', 1)[0]


def _assign_primary_domain(request, org, root_domain):
    """Create/assign `root_domain` as the org's primary domain + apex asset."""
    root_domain = _normalize_root_domain(root_domain)
    domain, created = Domain.objects.get_or_create(
        organisation=org, root_domain=root_domain, defaults={'is_primary': True},
    )
    # Ensure it's the single primary for this org.
    Domain.objects.filter(organisation=org, is_primary=True).exclude(pk=domain.pk).update(is_primary=False)
    if not domain.is_primary:
        domain.is_primary = True
        domain.save(update_fields=['is_primary'])
    # Apex asset so the domain is immediately scannable.
    Asset.objects.get_or_create(
        domain=domain, value=root_domain,
        defaults={'asset_type': 'root_domain', 'source': 'platform-admin'},
    )
    log_action('domain.create', request=request, organisation=org,
               target=root_domain, is_primary=True)
    return {'id': domain.id, 'root_domain': root_domain, 'is_primary': True, 'created': created}


def _invite_owner(request, org, email, role='owner'):
    """Create an invitation for `email` to join `org` as `role` and email the link."""
    invite = Invitation.objects.create(
        organisation=org, email=email, role=role, invited_by=request.user,
    )
    sent = send_invitation_email(invite)
    log_action('org.owner_invite', request=request, organisation=org,
               target=email, role=role, email_sent=sent)
    return {'email': email, 'role': role, 'email_sent': sent, 'invitation_id': invite.id}


class AdminUserListView(APIView):
    """GET all users across the platform (with org + role + platform-admin flag)."""
    permission_classes = [IsAuthenticated, IsPlatformAdmin]

    def get(self, request):
        users = User.objects.select_related('membership__organisation').order_by('-date_joined')
        search = (request.query_params.get('search') or '').strip()
        if search:
            from django.db.models import Q
            users = users.filter(Q(email__icontains=search) | Q(username__icontains=search))
        org_id = request.query_params.get('organisation_id')
        if org_id:
            users = users.filter(membership__organisation_id=org_id)

        paginator = AdminPagination()
        page = paginator.paginate_queryset(users, request)
        return paginator.get_paginated_response(AdminUserSerializer(page, many=True).data)


class AdminDashboardView(APIView):
    """GET platform-wide rollup metrics across every organisation."""
    permission_classes = [IsAuthenticated, IsPlatformAdmin]

    def get(self, request):
        week_ago = timezone.now() - timedelta(days=7)
        findings_by_risk = {
            row['risk_rating']: row['count']
            for row in Finding.objects.values('risk_rating').annotate(count=Count('id'))
        }
        top_orgs = [
            {
                'id': o.id,
                'organisation': o.name,
                'primary_domain': o.domains.count(),
                'findings': o.findings.count(),
                'scans': o.scans.count(),
            }
            for o in Organisation.objects.all()
        ]
        top_orgs.sort(key=lambda x: x['findings'], reverse=True)

        return Response({
            'organisations': Organisation.objects.count(),
            'users': User.objects.count(),
            'platform_admins': User.objects.filter(platform_admin__isnull=False).count(),
            'domains': Domain.objects.count(),
            'assets': Asset.objects.count(),
            'scans': {
                'total': Scan.objects.count(),
                'completed': Scan.objects.filter(status='completed').count(),
                'running': Scan.objects.filter(status='running').count(),
                'failed': Scan.objects.filter(status='failed').count(),
                'cancelled': Scan.objects.filter(status='cancelled').count(),
                'last_7_days': Scan.objects.filter(created_at__gte=week_ago).count(),
            },
            'findings': {
                'total': Finding.objects.count(),
                'by_risk': findings_by_risk,
            },
            'pending_invitations': Invitation.objects.filter(accepted=False).count(),
            'top_organisations': top_orgs[:10],
        })


class AdminActivityView(APIView):
    """GET the platform audit/activity feed (newest first)."""
    permission_classes = [IsAuthenticated, IsPlatformAdmin]

    def get(self, request):
        logs = AuditLog.objects.select_related('organisation').all()
        action = request.query_params.get('action')
        if action:
            logs = logs.filter(action=action)
        org_id = request.query_params.get('organisation_id')
        if org_id:
            logs = logs.filter(organisation_id=org_id)

        paginator = AdminPagination()
        page = paginator.paginate_queryset(logs, request)
        return paginator.get_paginated_response(AuditLogSerializer(page, many=True).data)
