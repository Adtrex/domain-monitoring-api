from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('api', '0008_reportsummary_scan_fk'),
    ]

    operations = [
        migrations.AddField(
            model_name='scan',
            name='cancel_requested',
            field=models.BooleanField(default=False),
        ),
        migrations.AlterField(
            model_name='scan',
            name='status',
            field=models.CharField(
                choices=[
                    ('queued', 'Queued'),
                    ('running', 'Running'),
                    ('completed', 'Completed'),
                    ('failed', 'Failed'),
                    ('cancelled', 'Cancelled'),
                ],
                default='queued',
                max_length=20,
            ),
        ),
    ]
