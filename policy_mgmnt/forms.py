from django import forms
from django.forms import ModelForm, PasswordInput
from .models import Policies, Firewall, POST, FirewallManager
from django.core.exceptions import ValidationError
from django.utils.translation import ugettext_lazy as _




class ContactForm(forms.Form):  
    Firewalls = forms.ModelChoiceField(empty_label="Select Firewall", queryset=Firewall.objects.all())
    source_info = forms.CharField(label='Source Address', max_length=50)
    dest_info = forms.CharField(label='Destination Address', max_length=50)
    app_info = forms.CharField(label='Application', max_length=50)

class ModifyPolicyForm(forms.Form): 
    Firewalls = forms.ModelChoiceField(empty_label="Select Firewall", queryset=Firewall.objects.all())
    policy_info = forms.CharField(label='Policy Name', max_length=50)

class FirewallForm(forms.Form):
    firewall_pass = forms.CharField(widget=forms.PasswordInput)
    class Meta:
        model = Firewall
        fields = ['firewall_pass']

class enterNewPolicyValues(forms.Form):
    source_info = forms.CharField(label='Source Address', max_length=50)
    dest_info = forms.CharField(label='Destination Address', max_length=50)
    app_info = forms.CharField(label='Application', max_length=50)