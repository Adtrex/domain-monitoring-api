from django.db import migrations, models
import django.db.models.deletion
import django.utils.timezone


class Migration(migrations.Migration):

    dependencies = [
        ('api', '0006_technologycheck_latest_version'),
    ]

    operations = [
        migrations.CreateModel(
            name='ReportSummary',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('organization_name', models.CharField(max_length=255)),
                ('generated_at', models.DateTimeField(default=django.utils.timezone.now)),
                ('executive_summary', models.TextField(blank=True)),
                ('scope_note', models.CharField(blank=True, max_length=500)),
                ('total_findings', models.IntegerField(default=0)),
                ('critical_risk', models.IntegerField(default=0)),
                ('high_risk', models.IntegerField(default=0)),
                ('medium_risk', models.IntegerField(default=0)),
                ('low_risk', models.IntegerField(default=0)),
                ('asset', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='report_summaries', to='api.asset')),
                ('domain', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='report_summaries', to='api.domain')),
            ],
            options={
                'db_table': 'report_summary',
                'ordering': ['-generated_at'],
            },
        ),
        migrations.CreateModel(
            name='ReportSummaryFinding',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('finding_type', models.CharField(max_length=80)),
                ('title', models.CharField(max_length=300)),
                ('severity', models.CharField(choices=[('Critical', 'Critical'), ('High', 'High'), ('Medium', 'Medium'), ('Low', 'Low')], max_length=20)),
                ('risk_summary', models.CharField(max_length=400)),
                ('external_reference', models.URLField()),
                ('affected_asset', models.CharField(max_length=500)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('summary', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='findings', to='api.reportsummary')),
            ],
            options={
                'db_table': 'report_summary_finding',
                'ordering': ['created_at'],
            },
        ),
    ]
