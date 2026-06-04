from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('api', '0007_report_summary_and_findings'),
    ]

    operations = [
        migrations.AddField(
            model_name='reportsummary',
            name='scan',
            field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='report_summaries', to='api.scan'),
        ),
    ]
