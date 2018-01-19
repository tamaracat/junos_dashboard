# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.contrib import admin

from .models import Policies, Firewall, Engineer
# Register your models here.

admin.site.register(Firewall)
admin.site.register(Policies)
admin.site.register(Engineer)


