# -*- coding: utf-8 -*-
from __future__ import unicode_literals
from encrypted_fields import EncryptedCharField
from django.core.urlresolvers import reverse
from django.db import models

# Create your models here.

class POST(models.Model): 
    source_info = models.CharField('source', max_length=50)
    dest_info = models.CharField('dest', max_length=50)
    app_info = models.CharField('app', max_length=50)
    policy_info = models.CharField('policy_name', max_length=50, blank=True)
    
    def __str__(self):
        return self.source_info

class POST_POL(models.Model): 
    source_info = models.CharField('source', max_length=50)
    dest_info = models.CharField('dest', max_length=50)
    app_info = models.CharField('app', max_length=50)
    
    def __str__(self):
        return self.source_info


class FirewallManager(models.Manager):
    def create_firewall(self, firewall_name, firewall_manageip, firewall_user, firewall_pass):
      new_firewall = self.create(firewall_name=firewall_name, firewall_manageip=firewall_manageip, firewall_user=firewall_user, firewall_pass=firewall_pass)
      return new_firewall

class Firewall(models.Model): 
    firewall_name = models.CharField('Firewall Name', max_length=50)
    firewall_manageip = models.GenericIPAddressField('Management IP')
    firewall_user = models.CharField('API User', max_length=50, blank=True)
    firewall_pass = EncryptedCharField('API Pass', max_length=50, blank=True)
    firewalls = models.Manager()
    objects = FirewallManager()

    class Meta: 
        ordering = ["-firewall_name"]
    
    def __str__(self):
        return self.firewall_name
    
class Policies(models.Model):
    name = models.CharField('Policy Name', max_length=10)
    source_address = models.CharField('Source_Address', max_length=10, default=1)
    destination_address = models.CharField('Destination_Address', max_length=10, default=1)
    application = models.CharField('Application', max_length=10, default=1)
    annotation = models.CharField('Annotation', max_length=10, blank=True, default=1)
    updated = models.BooleanField('Policy Present?', default=False, blank=True)
    policies = models.Manager()
    # Metadata
    class Meta: 
        ordering = ["-name"]

    # Methods
    def get_absolute_url(self):
         """
         Returns the url to access a particular instance of MyModelName.
         """
         return reverse('model-detail-view', args=[str(self.id)])
    def __str__(self):
        return self.name


