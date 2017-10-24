from __future__ import unicode_literals
import subprocess
from django.shortcuts import render
from django.http import HttpResponse
from django.core.urlresolvers import reverse
from models import Firewall, Policies, FirewallManager
from django.views.decorators.csrf import ensure_csrf_cookie
from scripts.xmlPython import *
from .forms import ContactForm, ModifyPolicyForm
from django.template import loader
# import sys, ast

def policy_mgmnt(request):
   
    return render(request, "policy_mgmnt.html", {})

@ensure_csrf_cookie
def submit(request):
  # info=request.POST['info']
  form = ContactForm(request.POST)
  if form.is_valid():
    print form.cleaned_data["Firewalls"]
    # TODO get creds from db
    # modify python code to take args and create new function
    # call function and pass parameters to log in to fw

    if (form.cleaned_data["dest_info"] == 'any'):
      policies = get_host_access_info(form.cleaned_data["source_info"])
      # newPolicies = get_policy_info(policies)
      print policies
    else:
      policies = get_host_info(form.cleaned_data["source_info"], form.cleaned_data["dest_info"], form.cleaned_data["app_info"])
      print policies

  return render(request, "submit.html", {"policies": policies})
  # return render(request, "submit.html", {'policies': sorted(policies.items())})
 
def home(request):
    
    form = ContactForm()
 
    return render(request, "home.html", {'form':form})
 
    
@ensure_csrf_cookie
def get_firewall(request):
  info=request.POST['list_info']
  
  template = loader.get_template('home.html')

  context = {
        'policies': "test",
  }  

  return HttpResponse(template.render(context,request))



@ensure_csrf_cookie
def modify_policy(request):
      
  form = ModifyPolicyForm()
 
  return render(request, "modify_policy.html", {'form':form})
      

@ensure_csrf_cookie
def modify_policy_result(request):
           
  form = ModifyPolicyForm(request.POST)
  # policies = get_policy_info("15544")
  if form.is_valid():

    policies = get_policy_info(form.cleaned_data["policy_info"])
    print policies

    return render(request, "modify_policy_result.html", {"policies": policies})
  else:
    print "Policy not selected"
    return render(request, "modify_policy_result.html", {"policies": "Policy not selected"})