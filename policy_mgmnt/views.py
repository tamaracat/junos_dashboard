# -*- coding: utf-8 -*-
from __future__ import unicode_literals
import subprocess
from django.shortcuts import render
from django.http import HttpResponse
from django.core.urlresolvers import reverse



from django.views.decorators.csrf import ensure_csrf_cookie

# Create your views here.
# Import stuff
from django.template import loader
# import sys, ast


def policy_mgmnt(request):
    # html = "<h1> BOUND </h1>" OLD
    return render(request, "policy_mgmnt.html", {})

@ensure_csrf_cookie
def submit(request):
  info=request.POST['info']


  class PolicyObject:
        def __init__(self, Policy, Source_Address, Destination_Address, Application):
          self.Policy = Policy,
          self.Source_Address = Source_Address,
          self.Destination_Address = Destination_Address,
          self.Application = Application
      # do something with info
#   p=subprocess.Popen(["python", "scripts/pyEZJuniper.py"], close_fds=True, stdout=subprocess.PIPE) 
  p=subprocess.Popen(["python", "scripts/xmlPython.py"], close_fds=True, stdout=subprocess.PIPE) 
  

  data = p.communicate()

  
  print data[0]
#   print data[0]
#   return HttpResponse(p)
#   return render(request, "submit.html", {data})
  template = loader.get_template('submit.html')

#   tupToString =  ''.join(data)
#   mytext = "<br />".join(''.join(data).split("\n"))

  context = {
        'policies': data[0],
  }  

  return HttpResponse(template.render(context,request))
    

# This is our index page
# @ensure_csrf_cookie
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
    
# This is our function to build the HTML table
