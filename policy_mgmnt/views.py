from __future__ import unicode_literals
import subprocess
from django.shortcuts import render
from django.http import HttpResponse
from django.core.urlresolvers import reverse
from models import Firewall, Policies
from django.views.decorators.csrf import ensure_csrf_cookie
from scripts.noConnJuniper import *
from .forms import ContactForm
from django.template import loader
# import sys, ast

def policy_mgmnt(request):
   
    return render(request, "policy_mgmnt.html", {})

@ensure_csrf_cookie
def submit(request):
  # info=request.POST['info']
  form = ContactForm(request.POST)
  if form.is_valid():
    policies = get_host_info(form.cleaned_data["source_info"], form.cleaned_data["dest_info"], form.cleaned_data["app_info"])
    print policies

  return render(request, "submit.html", {"policies": policies})
 
def home(request):

    form = ContactForm()
 
    return render(request, "home.html", {'form':form})
 
    
@ensure_csrf_cookie
def get_firewall(request):
  info=request.POST['list_info']
  
  a_fw = Firewall(firewall_name="new_firewall")
  a_fw = Firewall(firewall_manageip="3.3.3.3")
  a_fw.save()
  print (a_fw.firewall_name)

  template = loader.get_template('home.html')

  context = {
        'policies': a_fw.firewall_name,
  }  

  return HttpResponse(template.render(context,request))