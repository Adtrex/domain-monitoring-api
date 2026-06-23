"""Seed a default organisation + owner login and attach orphaned data to it.

Idempotent: safe to run multiple times. Gives an instant working login that
owns all pre-existing (backfilled) scan data.

    python manage.py seed_default_org
    python manage.py seed_default_org --reset-password   # also reset the owner's password

Credentials come from settings/env (DEFAULT_ADMIN_EMAIL / DEFAULT_ADMIN_PASSWORD)
with documented fallbacks. If no password is configured, a random one is
generated and printed once.
"""
import secrets

from django.conf import settings
from django.contrib.auth import get_user_model
from django.core.management.base import BaseCommand
from django.db import transaction
from django.utils.text import slugify

from api.models import (
    Organisation, Membership, PlatformAdmin, Domain, Asset, Scan, Finding,
    FrontendLibraryCheck, SSLTLSCheck, EmailSecurityCheck,
    SecurityHeaderCheck, DNSSecurityCheck, TechnologyCheck, ReportSummary,
)

SCOPED_MODELS = [
    Domain, Asset, Scan, Finding,
    FrontendLibraryCheck, SSLTLSCheck, EmailSecurityCheck,
    SecurityHeaderCheck, DNSSecurityCheck, TechnologyCheck, ReportSummary,
]


class Command(BaseCommand):
    help = "Create/ensure the default organisation + owner login and attach orphaned data to it."

    def add_arguments(self, parser):
        parser.add_argument(
            '--reset-password',
            action='store_true',
            help="Reset the default owner's password to the configured/generated value.",
        )

    def _unique_slug(self, name):
        base = slugify(name) or 'org'
        slug = base
        counter = 1
        while Organisation.objects.filter(slug=slug).exists():
            counter += 1
            slug = f"{base}-{counter}"
        return slug

    @transaction.atomic
    def handle(self, *args, **options):
        User = get_user_model()

        org_name = getattr(settings, 'DEFAULT_ORG_NAME', 'Default Organisation')
        email = getattr(settings, 'DEFAULT_ADMIN_EMAIL', 'admin@domainscan.local')
        password = getattr(settings, 'DEFAULT_ADMIN_PASSWORD', '') or ''
        username = email.split('@')[0] or 'admin'

        # 1. Ensure the default organisation exists.
        org, created = Organisation.objects.get_or_create(
            name=org_name,
            defaults={'slug': self._unique_slug(org_name)},
        )
        self.stdout.write(
            self.style.SUCCESS(f"{'Created' if created else 'Found'} organisation: {org.name}")
        )

        # 2. Safety net: attach any rows still missing an organisation.
        attached_total = 0
        for Model in SCOPED_MODELS:
            updated = Model.objects.filter(organisation__isnull=True).update(organisation=org)
            attached_total += updated
        if attached_total:
            self.stdout.write(
                self.style.WARNING(f"Attached {attached_total} orphaned row(s) to {org.name}.")
            )

        # 3. Ensure the default owner user + membership.
        generated_password = False
        if not password:
            password = secrets.token_urlsafe(12)
            generated_password = True

        user, user_created = User.objects.get_or_create(
            username=username,
            defaults={'email': email, 'is_staff': True},
        )
        if user_created:
            user.set_password(password)
            user.save()
            self.stdout.write(self.style.SUCCESS(f"Created owner user: {username}"))
        else:
            if options['reset_password']:
                user.set_password(password)
                user.save()
                self.stdout.write(self.style.WARNING(f"Reset password for existing user: {username}"))
            else:
                self.stdout.write(f"Owner user already exists: {username} (password unchanged)")

        # The default admin is also the initial platform super administrator.
        _pa, pa_created = PlatformAdmin.objects.get_or_create(
            user=user, defaults={'note': 'Seeded default platform administrator.'}
        )
        if pa_created:
            self.stdout.write(self.style.SUCCESS(f"Granted platform-admin to: {username}"))

        membership, m_created = Membership.objects.get_or_create(
            user=user,
            defaults={'organisation': org, 'role': 'owner'},
        )
        if not m_created and membership.organisation_id != org.id:
            self.stdout.write(
                self.style.WARNING(
                    f"User {username} already belongs to '{membership.organisation}'. Leaving as-is."
                )
            )
        elif not m_created and membership.role != 'owner':
            membership.role = 'owner'
            membership.save(update_fields=['role'])
            self.stdout.write(self.style.WARNING(f"Promoted {username} to owner."))

        # 4. Report the login.
        self.stdout.write("")
        self.stdout.write(self.style.MIGRATE_HEADING("=== Default login ==="))
        self.stdout.write(f"  Organisation: {org.name}")
        self.stdout.write(f"  Username:     {username}")
        self.stdout.write(f"  Email:        {email}")
        if user_created or options['reset_password']:
            if generated_password:
                self.stdout.write(self.style.WARNING(f"  Password:     {password}  (randomly generated)"))
                self.stdout.write(self.style.WARNING(
                    "  >>> Set DEFAULT_ADMIN_PASSWORD or change this password after first login."
                ))
            else:
                self.stdout.write("  Password:     (as configured in DEFAULT_ADMIN_PASSWORD)")
        else:
            self.stdout.write("  Password:     (unchanged; use --reset-password to reset)")
        self.stdout.write("")
