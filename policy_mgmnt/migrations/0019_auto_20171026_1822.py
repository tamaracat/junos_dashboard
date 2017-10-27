# -*- coding: utf-8 -*-
# Generated by Django 1.11.5 on 2017-10-26 18:22
from __future__ import unicode_literals

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('policy_mgmnt', '0018_post_pol'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='policies',
            name='updated',
        ),
        migrations.AddField(
            model_name='policies',
            name='firewall',
            field=models.CharField(blank=True, max_length=50, verbose_name='Firewall Name'),
        ),
    ]
