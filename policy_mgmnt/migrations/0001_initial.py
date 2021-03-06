# -*- coding: utf-8 -*-
# Generated by Django 1.11.5 on 2017-10-10 20:03
from __future__ import unicode_literals

from django.db import migrations, models
import encrypted_fields.fields


class Migration(migrations.Migration):

    initial = True

    dependencies = [
    ]

    operations = [
        migrations.CreateModel(
            name='Firewall',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('firewall_name', models.CharField(max_length=50, verbose_name='Firewall Name')),
                ('firewall_active', models.BooleanField(default=True, verbose_name='Firewall Active?')),
                ('firewall_manageip', models.GenericIPAddressField(verbose_name='Management IP')),
                ('firewall_vpnip', models.GenericIPAddressField(verbose_name='VPN Interface IP')),
                ('firewall_user', models.CharField(blank=True, max_length=50, verbose_name='API User')),
                ('firewall_pass', encrypted_fields.fields.EncryptedCharField(blank=True, max_length=50, verbose_name='API Pass')),
                ('firewall_policies', models.TextField(blank=True, editable=False)),
            ],
        ),
        migrations.CreateModel(
            name='Policies',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('policy_name', models.CharField(max_length=10, verbose_name='Policy Code')),
                ('policy_source_address', models.CharField(max_length=10, verbose_name='Policy Code')),
                ('policy_destination_address', models.CharField(max_length=10, verbose_name='Policy Code')),
                ('policy_application', models.CharField(max_length=10, verbose_name='Policy Code')),
                ('policy_annotation', models.CharField(max_length=10, verbose_name='Policy Code')),
                ('policy_updated', models.BooleanField(default=False, verbose_name='Policy Present?')),
            ],
            options={
                'ordering': ['-policy_name'],
            },
        ),
    ]
