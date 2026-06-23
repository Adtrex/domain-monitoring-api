"""Make the denormalized `organisation` FK non-null on all scoped tables.

Safe because migration 0011 backfilled every existing row to the default
organisation, so no NULLs remain when Postgres applies SET NOT NULL.
"""
import django.db.models.deletion
from django.db import migrations, models


def _org_fk(related_name):
    return models.ForeignKey(
        on_delete=django.db.models.deletion.CASCADE,
        related_name=related_name,
        to='api.organisation',
    )


SCOPED_FIELDS = [
    ('domain', 'domains'),
    ('asset', 'assets'),
    ('scan', 'scans'),
    ('finding', 'findings'),
    ('frontendlibrarycheck', 'library_checks'),
    ('ssltlscheck', 'ssl_checks'),
    ('emailsecuritycheck', 'email_checks'),
    ('securityheadercheck', 'header_checks'),
    ('dnssecuritycheck', 'dns_checks'),
    ('technologycheck', 'technology_checks'),
    ('reportsummary', 'report_summaries'),
]


class Migration(migrations.Migration):

    dependencies = [
        ('api', '0011_backfill_default_organisation'),
    ]

    operations = [
        migrations.AlterField(
            model_name=model_name,
            name='organisation',
            field=_org_fk(related_name),
        )
        for model_name, related_name in SCOPED_FIELDS
    ]
