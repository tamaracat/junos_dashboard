# -*- coding: utf-8 -*-
# Generated by Django 1.11.5 on 2017-10-10 20:23
from __future__ import unicode_literals

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('policy_mgmnt', '0001_initial'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='firewall',
            name='firewall_vpnip',
        ),
    ]