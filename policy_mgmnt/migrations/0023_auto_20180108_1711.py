# -*- coding: utf-8 -*-
# Generated by Django 1.11.5 on 2018-01-08 17:11
from __future__ import unicode_literals

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('policy_mgmnt', '0022_auto_20180105_1944'),
    ]

    operations = [
        migrations.AddField(
            model_name='policies',
            name='address_set',
            field=models.CharField(default=1, max_length=10, verbose_name='Address_Set'),
        ),
        migrations.AddField(
            model_name='policies',
            name='defined_as',
            field=models.CharField(default=1, max_length=10, verbose_name='Defined_As'),
        ),
    ]