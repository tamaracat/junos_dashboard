# -*- coding: utf-8 -*-
# Generated by Django 1.11.5 on 2017-10-12 00:03
from __future__ import unicode_literals

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('policy_mgmnt', '0002_remove_firewall_firewall_vpnip'),
    ]

    operations = [
        migrations.AlterField(
            model_name='policies',
            name='policy_annotation',
            field=models.CharField(max_length=10, verbose_name='Annotation'),
        ),
        migrations.AlterField(
            model_name='policies',
            name='policy_application',
            field=models.CharField(max_length=10, verbose_name='Application'),
        ),
        migrations.AlterField(
            model_name='policies',
            name='policy_destination_address',
            field=models.CharField(max_length=10, verbose_name='Destination Address'),
        ),
        migrations.AlterField(
            model_name='policies',
            name='policy_name',
            field=models.CharField(max_length=10, verbose_name='Policy Name'),
        ),
        migrations.AlterField(
            model_name='policies',
            name='policy_source_address',
            field=models.CharField(max_length=10, verbose_name='Source Address'),
        ),
    ]