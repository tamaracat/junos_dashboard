# -*- coding: utf-8 -*-
# Generated by Django 1.11.5 on 2018-01-19 20:26
from __future__ import unicode_literals

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('policy_mgmnt', '0026_remove_policies_source_ip'),
    ]

    operations = [
        migrations.CreateModel(
            name='Engineer',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('engineer_name', models.CharField(max_length=50, verbose_name='Engineer Name')),
            ],
        ),
    ]
