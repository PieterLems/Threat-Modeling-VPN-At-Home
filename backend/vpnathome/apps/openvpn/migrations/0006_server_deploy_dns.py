# Generated by Django 2.1.2 on 2018-12-21 17:42

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('openvpn', '0005_server_deleted'),
    ]

    operations = [
        migrations.AddField(
            model_name='server',
            name='deploy_dns',
            field=models.BooleanField(default=False),
        ),
    ]
