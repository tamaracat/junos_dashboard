# -*- coding: utf-8 -*-
# Generated by Django 1.11.5 on 2018-01-05 19:27
from __future__ import unicode_literals

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('policy_mgmnt', '0020_policies_action'),
    ]

    operations = [
        migrations.AddField(
            model_name='policies',
            name='dst_zone',
            field=models.CharField(default=1, max_length=10, verbose_name='Source_Address'),
        ),
        migrations.AddField(
            model_name='policies',
            name='src_zone',
            field=models.CharField(default=1, max_length=10, verbose_name='Source_Address'),
        ),
    ]
