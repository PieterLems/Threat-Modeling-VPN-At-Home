# Generated by Django 2.1.2 on 2018-12-15 15:10

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('openvpn', '0003_server_port'),
    ]

    operations = [
        migrations.AlterField(
            model_name='server',
            name='tls_auth_key',
            field=models.TextField(max_length=8192),
        ),
    ]
