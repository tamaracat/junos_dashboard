# -*- coding: utf-8 -*-
# Generated by Django 1.11.5 on 2017-11-15 19:59
from __future__ import unicode_literals

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('policy_mgmnt', '0019_auto_20171026_1822'),
    ]

    operations = [
        migrations.AddField(
            model_name='policies',
            name='action',
            field=models.CharField(default=1, max_length=10, verbose_name='Action'),
        ),
    ]