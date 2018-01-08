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

class PolicyManager(models.Manager):
    def create_policy(self, src_zone, dst_zone, name, source_address, destination_address, application, action, source_ip, defined_as, address_set, annotation, firewall):
      new_policy = self.create(src_zone=src_zone, dst_zone=dst_zone, name=name, source_address=source_address, destination_address=destination_address, application=application, action=action, source_ip=source_ip, defined_as=defined_as, address_set=address_set, annotation=annotation, firewall=firewall)
      return new_policy
    
class Policies(models.Model):
    src_zone = models.CharField('Src_Zone', max_length=10, default=1)
    dst_zone = models.CharField('Dst_Zone', max_length=10, default=1)
    name = models.CharField('Policy Name', max_length=10)
    source_address = models.CharField('Source_Address', max_length=10, default=1)
    destination_address = models.CharField('Destination_Address', max_length=10, default=1)
    application = models.CharField('Application', max_length=10, default=1)
    action = models.CharField('Action', max_length=10, default=1)
    source_ip = models.CharField('Source_IP', max_length=10, default=1)
    defined_as = models.CharField('Defined_As', max_length=10, default=1)
    address_set = models.CharField('Address_Set', max_length=10, default=1)
    annotation = models.CharField('Annotation', max_length=10, blank=True, default=1)
    firewall =  models.CharField('Firewall Name', blank=True, max_length=50)
    policies = models.Manager()
    objects = PolicyManager()
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



