# Generated by Django 5.1.4 on 2024-12-31 12:28

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('myapp', '0001_initial'),
    ]

    operations = [
        migrations.AddField(
            model_name='customuser',
            name='role',
            field=models.CharField(choices=[('user', 'User'), ('employee', 'Employee')], default='user', max_length=10),
        ),
    ]
