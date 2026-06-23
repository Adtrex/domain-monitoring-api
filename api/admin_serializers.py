"""Serializers for the platform-admin (super-admin) API."""
from django.contrib.auth import get_user_model
from rest_framework import serializers

from .models import Organisation, Membership, AuditLog

User = get_user_model()


class AdminOrganisationSerializer(serializers.ModelSerializer):
    """Organisation with platform-level rollup counts."""
    members = serializers.SerializerMethodField()
    domains = serializers.SerializerMethodField()
    primary_domain = serializers.SerializerMethodField()
    scans = serializers.SerializerMethodField()
    findings = serializers.SerializerMethodField()
    owners = serializers.SerializerMethodField()

    class Meta:
        model = Organisation
        fields = ['id', 'name', 'slug', 'created_at', 'updated_at',
                  'members', 'owners', 'domains', 'primary_domain', 'scans', 'findings']
        read_only_fields = fields

    def get_primary_domain(self, obj):
        primary = obj.domains.filter(is_primary=True).first()
        return primary.root_domain if primary else None

    def get_members(self, obj):
        return obj.memberships.count()

    def get_owners(self, obj):
        return list(
            obj.memberships.filter(role='owner').values_list('user__email', flat=True)
        )

    def get_domains(self, obj):
        return obj.domains.count()

    def get_scans(self, obj):
        return obj.scans.count()

    def get_findings(self, obj):
        return obj.findings.count()


class AdminOrganisationCreateSerializer(serializers.Serializer):
    """Create an organisation, optionally invite its first owner, and optionally
    assign its primary domain — all in one call."""
    name = serializers.CharField(max_length=255)
    owner_email = serializers.EmailField(required=False, allow_blank=True)
    primary_domain = serializers.CharField(max_length=255, required=False, allow_blank=True)

    def validate_name(self, value):
        value = value.strip()
        if Organisation.objects.filter(name__iexact=value).exists():
            raise serializers.ValidationError('An organisation with this name already exists.')
        return value


class AdminUserSerializer(serializers.ModelSerializer):
    organisation = serializers.SerializerMethodField()
    role = serializers.SerializerMethodField()
    is_platform_admin = serializers.SerializerMethodField()

    class Meta:
        model = User
        fields = ['id', 'username', 'email', 'first_name', 'last_name', 'is_active',
                  'date_joined', 'last_login', 'organisation', 'role', 'is_platform_admin']
        read_only_fields = fields

    def _membership(self, obj):
        return getattr(obj, 'membership', None)

    def get_organisation(self, obj):
        m = self._membership(obj)
        return m.organisation.name if m else None

    def get_role(self, obj):
        m = self._membership(obj)
        return m.role if m else None

    def get_is_platform_admin(self, obj):
        return hasattr(obj, 'platform_admin')


class AuditLogSerializer(serializers.ModelSerializer):
    organisation = serializers.CharField(source='organisation.name', default=None, read_only=True)

    class Meta:
        model = AuditLog
        fields = ['id', 'action', 'actor_email', 'organisation', 'target',
                  'metadata', 'ip_address', 'created_at']
        read_only_fields = fields
