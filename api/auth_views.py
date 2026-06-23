"""Authentication, organisation, member-management and invitation endpoints."""
import logging
from datetime import timedelta

from django.conf import settings
from django.core.mail import send_mail
from django.utils import timezone
from rest_framework import status
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.exceptions import TokenError
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.views import TokenObtainPairView

from .models import Membership, Invitation
from .permissions import get_user_organisation, IsOrgOwnerOrAdmin
from .audit import log_action
from .auth_serializers import (
    EmailOrUsernameTokenObtainPairSerializer, MeSerializer, OrganisationSerializer,
    MemberSerializer, InvitationSerializer, InvitationCreateSerializer,
    AcceptInvitationSerializer,
)

logger = logging.getLogger(__name__)


class LoginView(TokenObtainPairView):
    """POST username/email + password -> {access, refresh, user}."""
    permission_classes = [AllowAny]
    serializer_class = EmailOrUsernameTokenObtainPairSerializer

    def post(self, request, *args, **kwargs):
        response = super().post(request, *args, **kwargs)
        if response.status_code == 200:
            user_ctx = (response.data or {}).get('user') or {}
            org = user_ctx.get('organisation') or {}
            log_action(
                'auth.login', request=request,
                target=user_ctx.get('email') or request.data.get('username', ''),
                role=user_ctx.get('role'), organisation_name=org.get('name'),
            )
        return response


class LogoutView(APIView):
    """POST {refresh} -> blacklist the refresh token."""
    permission_classes = [IsAuthenticated]

    def post(self, request):
        refresh = request.data.get('refresh')
        if not refresh:
            return Response({'error': 'refresh token is required'},
                            status=status.HTTP_400_BAD_REQUEST)
        try:
            RefreshToken(refresh).blacklist()
        except TokenError:
            return Response({'error': 'Invalid or expired refresh token'},
                            status=status.HTTP_400_BAD_REQUEST)
        log_action('auth.logout', request=request,
                   target=request.user.email or request.user.username)
        return Response(status=status.HTTP_205_RESET_CONTENT)


class MeView(APIView):
    """GET current user + organisation + role."""
    permission_classes = [IsAuthenticated]

    def get(self, request):
        return Response(MeSerializer(request.user).data)


class OrganisationDetailView(APIView):
    """GET the caller's organisation."""
    permission_classes = [IsAuthenticated]

    def get(self, request):
        org = get_user_organisation(request)
        return Response(OrganisationSerializer(org).data)


class MemberListView(APIView):
    """GET list of members in the caller's organisation."""
    permission_classes = [IsAuthenticated, IsOrgOwnerOrAdmin]

    def get(self, request):
        org = get_user_organisation(request)
        members = Membership.objects.select_related('user', 'organisation').filter(organisation=org)
        return Response(MemberSerializer(members, many=True).data)


class MemberDetailView(APIView):
    """PATCH role / DELETE a member within the caller's organisation."""
    permission_classes = [IsAuthenticated, IsOrgOwnerOrAdmin]

    def _get_member(self, request, pk):
        org = get_user_organisation(request)
        return Membership.objects.select_related('user').filter(organisation=org, pk=pk).first()

    def patch(self, request, pk):
        member = self._get_member(request, pk)
        if member is None:
            return Response({'error': 'Member not found'}, status=status.HTTP_404_NOT_FOUND)

        new_role = request.data.get('role')
        valid_roles = {choice[0] for choice in Membership.ROLE_CHOICES}
        if new_role not in valid_roles:
            return Response({'error': f'role must be one of {sorted(valid_roles)}'},
                            status=status.HTTP_400_BAD_REQUEST)

        # Only an owner may grant/revoke the owner role.
        requester = request.user.membership
        if (new_role == 'owner' or member.role == 'owner') and requester.role != 'owner':
            return Response({'error': 'Only an owner can change ownership.'},
                            status=status.HTTP_403_FORBIDDEN)

        old_role = member.role
        member.role = new_role
        member.save(update_fields=['role'])
        log_action('member.role_change', request=request, organisation=member.organisation,
                   target=member.user.email or member.user.username,
                   old_role=old_role, new_role=new_role)
        return Response(MemberSerializer(member).data)

    def delete(self, request, pk):
        member = self._get_member(request, pk)
        if member is None:
            return Response({'error': 'Member not found'}, status=status.HTTP_404_NOT_FOUND)
        if member.user_id == request.user.id:
            return Response({'error': 'You cannot remove yourself.'},
                            status=status.HTTP_400_BAD_REQUEST)
        if member.role == 'owner' and request.user.membership.role != 'owner':
            return Response({'error': 'Only an owner can remove another owner.'},
                            status=status.HTTP_403_FORBIDDEN)
        # Never leave an organisation without an owner.
        if member.role == 'owner' and \
                Membership.objects.filter(organisation=member.organisation, role='owner').count() <= 1:
            return Response({'error': 'Cannot remove the last owner of the organisation.'},
                            status=status.HTTP_400_BAD_REQUEST)
        removed_email = member.user.email or member.user.username
        removed_org = member.organisation
        member.user.delete()  # cascades the membership
        log_action('member.remove', request=request, organisation=removed_org,
                   target=removed_email)
        return Response(status=status.HTTP_204_NO_CONTENT)


def send_invitation_email(invite):
    """Send (or re-send) the activation email for an invitation. Returns True on success."""
    link = f"{settings.FRONTEND_URL}{settings.INVITE_PATH}?token={invite.token}"
    subject = f"You've been invited to {invite.organisation.name} on DomainScan"
    body = (
        f"You have been invited to join {invite.organisation.name} as a {invite.role}.\n\n"
        f"Set your password and activate your account here:\n{link}\n\n"
        f"This invitation expires on {invite.expires_at:%Y-%m-%d %H:%M UTC}."
    )
    try:
        send_mail(
            subject, body, settings.DEFAULT_FROM_EMAIL, [invite.email],
            fail_silently=False,
        )
        return True
    except Exception as exc:  # don't fail the request if email delivery hiccups
        logger.error("Failed to send invitation email to %s: %s", invite.email, exc)
        return False


class InvitationListCreateView(APIView):
    """GET list invitations / POST create + email an invitation."""
    permission_classes = [IsAuthenticated, IsOrgOwnerOrAdmin]

    def get(self, request):
        org = get_user_organisation(request)
        invites = Invitation.objects.filter(organisation=org)
        return Response(InvitationSerializer(invites, many=True).data)

    def post(self, request):
        org = get_user_organisation(request)
        serializer = InvitationCreateSerializer(data=request.data, context={'organisation': org})
        serializer.is_valid(raise_exception=True)
        invite = serializer.save(organisation=org, invited_by=request.user)

        sent = send_invitation_email(invite)
        log_action('invitation.create', request=request, organisation=org,
                   target=invite.email, role=invite.role, email_sent=sent)
        data = InvitationSerializer(invite).data
        data['email_sent'] = sent
        return Response(data, status=status.HTTP_201_CREATED)


class InvitationResendView(APIView):
    """POST resend the activation email for an existing invitation (refreshes expiry)."""
    permission_classes = [IsAuthenticated, IsOrgOwnerOrAdmin]

    def post(self, request, pk):
        org = get_user_organisation(request)
        invite = Invitation.objects.filter(organisation=org, pk=pk).first()
        if invite is None:
            return Response({'error': 'Invitation not found'}, status=status.HTTP_404_NOT_FOUND)
        if invite.accepted:
            return Response(
                {'error': 'This invitation has already been accepted.'},
                status=status.HTTP_400_BAD_REQUEST,
            )

        # Refresh the validity window so the re-sent link is good for another 7 days.
        invite.expires_at = timezone.now() + timedelta(days=7)
        invite.save(update_fields=['expires_at'])

        sent = send_invitation_email(invite)
        data = InvitationSerializer(invite).data
        data['email_sent'] = sent
        return Response(data, status=status.HTTP_200_OK)


class AcceptInvitationView(APIView):
    """POST {token, password, first_name, last_name} -> create user + membership."""
    permission_classes = [AllowAny]

    def post(self, request):
        serializer = AcceptInvitationSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.save()
        membership = getattr(user, 'membership', None)
        log_action(
            'invitation.accept', request=request, actor=user,
            organisation=membership.organisation if membership else None,
            target=user.email, role=membership.role if membership else None,
        )
        return Response(
            {'message': 'Account created. You can now log in.', 'username': user.username},
            status=status.HTTP_201_CREATED,
        )
