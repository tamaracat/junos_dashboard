# -*- coding: utf-8 -*-
# Generated by Django 1.11.5 on 2018-01-19 20:38
from __future__ import unicode_literals

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('policy_mgmnt', '0029_engineer_engineer_fw_sig'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='engineer',
            name='engineer_netid',
        ),
    ]