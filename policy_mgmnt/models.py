# -*- coding: utf-8 -*-
from __future__ import unicode_literals
from encrypted_fields import EncryptedCharField
from django.db import models

# Create your models here.

class Firewall(models.Model):  
    firewall_name = models.CharField('Firewall Name', max_length=50)
    firewall_active = models.BooleanField('Firewall Active?', default=True)
    firewall_manageip = models.GenericIPAddressField('Management IP')
    firewall_user = models.CharField('API User', max_length=50, blank=True)
    firewall_pass = EncryptedCharField('API Pass', max_length=50, blank=True)
    firewall_policies = models.TextField(editable=False, blank=True)
    
    def __str__(self):
        return self.firewall_name

class Policies(models.Model):
    policy_name = models.CharField('Policy Name', max_length=10)
    policy_source_address = models.CharField('Source Address', max_length=10)
    policy_destination_address = models.CharField('Destination Address', max_length=10)
    policy_application = models.CharField('Application', max_length=10)
    policy_annotation = models.CharField('Annotation', max_length=10)
    policy_updated = models.BooleanField('Policy Present?', default=False)
    # Metadata
    class Meta: 
        ordering = ["-policy_name"]

    # Methods
    def get_absolute_url(self):
         """
         Returns the url to access a particular instance of MyModelName.
         """
         return reverse('model-detail-view', args=[str(self.id)])
    def __str__(self):
        return self.policy_name
