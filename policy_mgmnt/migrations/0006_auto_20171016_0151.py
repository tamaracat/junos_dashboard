# -*- coding: utf-8 -*-
# Generated by Django 1.11.5 on 2017-10-16 01:51
from __future__ import unicode_literals

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('policy_mgmnt', '0005_auto_20171016_0102'),
    ]

    operations = [
        migrations.AlterModelOptions(
            name='policies',
            options={'ordering': ['-name']},
        ),
        migrations.RenameField(
            model_name='application',
            old_name='policy_application',
            new_name='application',
        ),
        migrations.RenameField(
            model_name='destination_address',
            old_name='policy_destination_address',
            new_name='destination_address',
        ),
        migrations.RenameField(
            model_name='policies',
            old_name='policy_annotation',
            new_name='annotation',
        ),
        migrations.RenameField(
            model_name='policies',
            old_name='policy_application',
            new_name='application',
        ),
        migrations.RenameField(
            model_name='policies',
            old_name='policy_destination_address',
            new_name='destination_address',
        ),
        migrations.RenameField(
            model_name='policies',
            old_name='policy_name',
            new_name='name',
        ),
        migrations.RenameField(
            model_name='policies',
            old_name='policy_source_address',
            new_name='source_address',
        ),
        migrations.RenameField(
            model_name='policies',
            old_name='policy_updated',
            new_name='updated',
        ),
        migrations.RenameField(
            model_name='source_address',
            old_name='policy_source_address',
            new_name='source_address',
        ),
        migrations.RemoveField(
            model_name='firewall',
            name='firewall_policies',
        ),
    ]
