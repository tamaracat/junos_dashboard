from django import forms
from django.forms import ModelForm, PasswordInput
from .models import Policies, Firewall, POST
from django.core.exceptions import ValidationError
from django.utils.translation import ugettext_lazy as _


# class FirewallForm(ModelForm):
    # firewall_pass = CharField(widget=forms.PasswordInput)
    # class Meta:
        # model = Firewall
        # fields = ['firewall_pass']

class ContactForm(forms.Form):
    
    source_info = forms.CharField(label='source_info', max_length=50)
    dest_info = forms.CharField(label='dest_info', max_length=50)
    app_info = forms.CharField(label='app_info', max_length=50)

   