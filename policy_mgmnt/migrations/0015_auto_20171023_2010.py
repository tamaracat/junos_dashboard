# -*- coding: utf-8 -*-
# Generated by Django 1.11.5 on 2017-10-23 20:10
from __future__ import unicode_literals

from django.db import migrations
import django.db.models.manager


class Migration(migrations.Migration):

    dependencies = [
        ('policy_mgmnt', '0014_auto_20171018_2338'),
    ]

    operations = [
        migrations.AlterModelManagers(
            name='firewall',
            managers=[
                ('firewalls', django.db.models.manager.Manager()),
            ],
        ),
        migrations.AlterModelManagers(
            name='policies',
            managers=[
                ('policies', django.db.models.manager.Manager()),
            ],
        ),
    ]
