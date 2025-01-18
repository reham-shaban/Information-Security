# Generated by Django 5.1.5 on 2025-01-18 18:14

import myapp.validators
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('myapp', '0003_document'),
    ]

    operations = [
        migrations.AddField(
            model_name='document',
            name='file_hash',
            field=models.CharField(blank=True, max_length=64, null=True),
        ),
        migrations.AlterField(
            model_name='document',
            name='file',
            field=models.FileField(upload_to='documents/', validators=[myapp.validators.validate_file_extension, myapp.validators.virus_scan, myapp.validators.validate_file_size, myapp.validators.check_suspicious_filename]),
        ),
    ]
