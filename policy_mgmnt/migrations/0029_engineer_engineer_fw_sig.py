# -*- coding: utf-8 -*-
# Generated by Django 1.11.5 on 2018-01-19 20:34
from __future__ import unicode_literals

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('policy_mgmnt', '0028_auto_20180119_2032'),
    ]

    operations = [
        migrations.AddField(
            model_name='engineer',
            name='engineer_fw_sig',
            field=models.CharField(blank=True, max_length=50, verbose_name='Net ID'),
        ),
    ]
