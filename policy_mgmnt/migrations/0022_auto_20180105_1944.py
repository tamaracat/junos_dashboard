# -*- coding: utf-8 -*-
# Generated by Django 1.11.5 on 2018-01-05 19:44
from __future__ import unicode_literals

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('policy_mgmnt', '0021_auto_20180105_1927'),
    ]

    operations = [
        migrations.AlterField(
            model_name='policies',
            name='dst_zone',
            field=models.CharField(default=1, max_length=10, verbose_name='Dst_Zone'),
        ),
        migrations.AlterField(
            model_name='policies',
            name='src_zone',
            field=models.CharField(default=1, max_length=10, verbose_name='Src_Zone'),
        ),
    ]