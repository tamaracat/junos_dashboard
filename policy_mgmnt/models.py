# -*- coding: utf-8 -*-
from __future__ import unicode_literals
from encrypted_fields import EncryptedCharField
from django.core.urlresolvers import reverse
from django.db import models

# Create your models here.

class Firewall(models.Model): 
    firewall_name = models.CharField('Firewall Name', max_length=50)
    firewall_manageip = models.GenericIPAddressField('Management IP')
    firewall_user = models.CharField('API User', max_length=50, blank=True)
    firewall_pass = EncryptedCharField('API Pass', max_length=50, blank=True)
    
    def __str__(self):
        return self.firewall_name

class Policies(models.Model):
    name = models.CharField('Policy Name', max_length=10)
    source_address = models.CharField('Source_Address', max_length=10, default=1)
    destination_address = models.CharField('Destination_Address', max_length=10, default=1)
    application = models.CharField('Application', max_length=10, default=1)
    annotation = models.CharField('Annotation', max_length=10, blank=True, default=1)
    updated = models.BooleanField('Policy Present?', default=False, blank=True)

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
