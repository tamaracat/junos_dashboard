# -*- coding: utf-8 -*-
# Generated by Django 1.11.5 on 2017-10-24 18:06
from __future__ import unicode_literals

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('policy_mgmnt', '0016_auto_20171024_1546'),
    ]

    operations = [
        migrations.DeleteModel(
            name='POST_POLICY',
        ),
        migrations.AddField(
            model_name='post',
            name='policy_info',
            field=models.CharField(blank=True, max_length=50, verbose_name='policy_name'),
        ),
    ]
