"""Lightweight audit logging helper.

`log_action` is intentionally best-effort: it never raises into the caller, so
audit failures can't break the action being recorded.
"""
import logging

logger = logging.getLogger(__name__)


def _client_ip(request):
    if request is None:
        return None
    fwd = request.META.get('HTTP_X_FORWARDED_FOR', '')
    if fwd:
        return fwd.split(',')[0].strip() or None
    return request.META.get('REMOTE_ADDR') or None


def log_action(action, request=None, actor=None, organisation=None, target='', **metadata):
    """Record an AuditLog row. Safe to call from anywhere."""
    try:
        from .models import AuditLog

        if actor is None and request is not None:
            user = getattr(request, 'user', None)
            if user is not None and getattr(user, 'is_authenticated', False):
                actor = user

        actor_email = ''
        if actor is not None:
            actor_email = getattr(actor, 'email', '') or getattr(actor, 'username', '')

        AuditLog.objects.create(
            action=action,
            actor=actor,
            actor_email=actor_email,
            organisation=organisation,
            target=str(target)[:300],
            metadata=metadata or {},
            ip_address=_client_ip(request),
        )
    except Exception:  # pragma: no cover - auditing must never break the request
        logger.exception("Failed to write audit log for action=%s", action)
