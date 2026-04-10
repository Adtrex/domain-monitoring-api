from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('api', '0005_alter_securityheadercheck_cvss_score'),
    ]

    operations = [
        migrations.AddField(
            model_name='technologycheck',
            name='latest_version',
            field=models.CharField(blank=True, default='Unknown', max_length=100, null=True),
        ),
    ]
