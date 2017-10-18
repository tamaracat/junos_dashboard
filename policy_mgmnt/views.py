from __future__ import unicode_literals
import subprocess
from django.shortcuts import render
from django.http import HttpResponse
from django.core.urlresolvers import reverse
from models import Firewall, Policies
from django.views.decorators.csrf import ensure_csrf_cookie
from scripts.noConnJuniper import *
# Create your views here.
# Import stuff
from django.template import loader
# import sys, ast


def policy_mgmnt(request):
    # html = "<h1> BOUND </h1>" OLD
    return render(request, "policy_mgmnt.html", {})

@ensure_csrf_cookie
def submit(request):
  # info=request.POST['info']

  a_fw = Firewall(firewall_name="new_firewall")
  a_fw = Firewall(firewall_manageip="3.3.3.3")
  a_fw.save()
  print (a_fw.firewall_name)

  a_pol = Policies(name='newPol10', source_address='new_dest', destination_address='new_dest', application='new_app', annotation='ttangney')
  a_pol.save()
  print Policies(a_pol.name)
  class PolicyObject:
        def __init__(self, Policy, Source_Address, Destination_Address, Application):
          self.Policy = Policy,
          self.Source_Address = Source_Address,
          self.Destination_Address = Destination_Address,
          self.Application = Application
      # do something with info
#   p=subprocess.Popen(["python", "scripts/pyEZJuniper.py"], close_fds=True, stdout=subprocess.PIPE) 
#   p=subprocess.Popen(["python", "scripts/xmlPython.py"], close_fds=True, stdout=subprocess.PIPE) 
  # p=subprocess.Popen(["python", "scripts/noConnJuniper.py"], close_fds=True, stdout=subprocess.PIPE) 

  # p=subprocess.call(['scripts/noConnJuniper.py', '13317', 'str'])
  testVar = get_host_info("any", "any", "any")
  print testVar
  

  template = loader.get_template('submit.html')

  context = {
        'policies': testVar,
  }  

  return HttpResponse(template.render(context,request))
def home(request):
    # info=request.POST['info']
    
    firewall_list = ''
    policies_list = ''

    template = loader.get_template('home.html')

    context = {
        'policies_list': policies_list,
        'firewall_list': firewall_list,
    }

    # return HttpResponse(template.render(context,request))
    return render(request, "home.html", {})
    # return HttpResponse("This page will eventually be a magical dashboard!")
    
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