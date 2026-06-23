"""Backfill: assign every pre-existing row to a default organisation.

This is idempotent and uses the same default organisation name as the
`seed_default_org` management command, so running either first is fine.
"""
from django.conf import settings
from django.db import migrations
from django.utils.text import slugify


DEFAULT_ORG_NAME = getattr(settings, 'DEFAULT_ORG_NAME', 'Default Organisation')

# Models that carry a denormalized `organisation` FK and need backfilling.
SCOPED_MODELS = [
    'Domain', 'Asset', 'Scan', 'Finding',
    'FrontendLibraryCheck', 'SSLTLSCheck', 'EmailSecurityCheck',
    'SecurityHeaderCheck', 'DNSSecurityCheck', 'TechnologyCheck',
    'ReportSummary',
]


def _unique_slug(Organisation, name):
    base = slugify(name) or 'org'
    slug = base
    counter = 1
    while Organisation.objects.filter(slug=slug).exists():
        counter += 1
        slug = f"{base}-{counter}"
    return slug


def backfill(apps, schema_editor):
    Organisation = apps.get_model('api', 'Organisation')
    org, _created = Organisation.objects.get_or_create(
        name=DEFAULT_ORG_NAME,
        defaults={'slug': _unique_slug(Organisation, DEFAULT_ORG_NAME)},
    )

    for model_name in SCOPED_MODELS:
        Model = apps.get_model('api', model_name)
        Model.objects.filter(organisation__isnull=True).update(organisation=org)


def noop_reverse(apps, schema_editor):
    # Reverting only nulls out the FK; the default org row is left in place.
    for model_name in SCOPED_MODELS:
        Model = apps.get_model('api', model_name)
        Model.objects.update(organisation=None)


class Migration(migrations.Migration):

    dependencies = [
        ('api', '0010_organisation_alter_domain_root_domain_membership_and_more'),
    ]

    operations = [
        migrations.RunPython(backfill, noop_reverse),
    ]
