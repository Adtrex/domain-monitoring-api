"""Serializers for authentication, organisation, members and invitations."""
from django.contrib.auth import get_user_model
from django.contrib.auth.password_validation import validate_password
from django.db import transaction
from django.utils import timezone
from rest_framework import serializers
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer

from .models import Organisation, Membership, Invitation

User = get_user_model()


class OrganisationSerializer(serializers.ModelSerializer):
    class Meta:
        model = Organisation
        fields = ['id', 'name', 'slug', 'created_at', 'updated_at']
        read_only_fields = fields


class MemberSerializer(serializers.ModelSerializer):
    """Represents a Membership as a user record with role."""
    user_id = serializers.IntegerField(source='user.id', read_only=True)
    username = serializers.CharField(source='user.username', read_only=True)
    email = serializers.EmailField(source='user.email', read_only=True)
    first_name = serializers.CharField(source='user.first_name', read_only=True)
    last_name = serializers.CharField(source='user.last_name', read_only=True)
    is_active = serializers.BooleanField(source='user.is_active', read_only=True)

    class Meta:
        model = Membership
        fields = [
            'id', 'user_id', 'username', 'email', 'first_name', 'last_name',
            'role', 'is_active', 'created_at',
        ]
        read_only_fields = fields


class MeSerializer(serializers.Serializer):
    """Current authenticated user + their organisation context."""
    id = serializers.IntegerField()
    username = serializers.CharField()
    email = serializers.EmailField()
    first_name = serializers.CharField()
    last_name = serializers.CharField()
    role = serializers.SerializerMethodField()
    organisation = serializers.SerializerMethodField()
    is_platform_admin = serializers.SerializerMethodField()

    def get_is_platform_admin(self, obj):
        return hasattr(obj, 'platform_admin')

    def get_role(self, obj):
        membership = getattr(obj, 'membership', None)
        return membership.role if membership else None

    def get_organisation(self, obj):
        membership = getattr(obj, 'membership', None)
        if not membership:
            return None
        return OrganisationSerializer(membership.organisation).data


class EmailOrUsernameTokenObtainPairSerializer(TokenObtainPairSerializer):
    """Login with username OR email; embeds org/role claims and returns user context."""

    @classmethod
    def get_token(cls, user):
        token = super().get_token(user)
        membership = Membership.objects.select_related('organisation').filter(user=user).first()
        if membership:
            token['organisation_id'] = membership.organisation_id
            token['role'] = membership.role
        return token

    def validate(self, attrs):
        # Allow the username field to actually contain an email address.
        login = attrs.get(self.username_field)
        if login and '@' in login:
            match = User.objects.filter(email__iexact=login).first()
            if match:
                attrs[self.username_field] = match.get_username()
        data = super().validate(attrs)

        membership = Membership.objects.select_related('organisation').filter(user=self.user).first()
        data['user'] = {
            'id': self.user.id,
            'username': self.user.username,
            'email': self.user.email,
            'role': membership.role if membership else None,
            'is_platform_admin': hasattr(self.user, 'platform_admin'),
            'organisation': (
                OrganisationSerializer(membership.organisation).data if membership else None
            ),
        }
        return data


class InvitationSerializer(serializers.ModelSerializer):
    invited_by_username = serializers.CharField(source='invited_by.username', read_only=True)
    is_valid = serializers.BooleanField(read_only=True)

    class Meta:
        model = Invitation
        fields = [
            'id', 'email', 'role', 'accepted', 'is_valid',
            'invited_by_username', 'created_at', 'expires_at',
        ]
        read_only_fields = fields


class InvitationCreateSerializer(serializers.ModelSerializer):
    class Meta:
        model = Invitation
        fields = ['email', 'role']

    def validate_role(self, value):
        if value == 'owner':
            raise serializers.ValidationError("Cannot invite a user as 'owner'.")
        return value

    def validate_email(self, value):
        org = self.context['organisation']
        # Reject if a user with this email already belongs to this organisation.
        existing = Membership.objects.filter(
            organisation=org, user__email__iexact=value
        ).exists()
        if existing:
            raise serializers.ValidationError("A member with this email already exists in your organisation.")
        return value


class AcceptInvitationSerializer(serializers.Serializer):
    token = serializers.CharField()
    password = serializers.CharField(write_only=True)
    first_name = serializers.CharField(required=False, allow_blank=True, default='')
    last_name = serializers.CharField(required=False, allow_blank=True, default='')

    def validate_token(self, value):
        invite = Invitation.objects.select_related('organisation').filter(token=value).first()
        if invite is None:
            raise serializers.ValidationError("Invalid invitation token.")
        if not invite.is_valid:
            raise serializers.ValidationError("This invitation has expired or already been used.")
        self.context['invitation'] = invite
        return value

    def validate_password(self, value):
        validate_password(value)
        return value

    @transaction.atomic
    def save(self, **kwargs):
        invite = self.context['invitation']
        email = invite.email

        if User.objects.filter(email__iexact=email).exists() or \
                User.objects.filter(username=email).exists():
            raise serializers.ValidationError(
                {'email': 'An account with this email already exists. Please log in instead.'}
            )

        user = User.objects.create_user(
            username=email,
            email=email,
            password=self.validated_data['password'],
            first_name=self.validated_data.get('first_name', ''),
            last_name=self.validated_data.get('last_name', ''),
        )
        Membership.objects.create(
            user=user, organisation=invite.organisation, role=invite.role
        )
        invite.accepted = True
        invite.save(update_fields=['accepted'])
        return user
