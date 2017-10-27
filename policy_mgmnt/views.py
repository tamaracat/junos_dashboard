from __future__ import unicode_literals
import subprocess
from django.views import generic
from django.shortcuts import render
from django.http import HttpResponse
from django.core.urlresolvers import reverse
from models import Firewall, Policies, FirewallManager
from django.views.decorators.csrf import ensure_csrf_cookie
from scripts.xmlPython import *
from .forms import ContactForm, ModifyPolicyForm, enterNewPolicyValues
from django.template import loader
import json
# import sys, ast


@ensure_csrf_cookie
def submit(request):
  # info=request.POST['info']
  form = ContactForm(request.POST)
  if form.is_valid():
    print form.cleaned_data["Firewalls"]
    firewall = form.cleaned_data["Firewalls"]
    # get creds from db
    querySet = Firewall.objects.all().filter(firewall_name=firewall)

    print [p.firewall_name for p in querySet]
   
    FWName = p.firewall_name
    hostname = p.firewall_manageip
    username = p.firewall_user
    password = p.firewall_pass
   
    # modify python code to take args and create new function
    if(connect_to_firewall(hostname, username, password)):
    # call function and pass parameters to log in to fw

      if (form.cleaned_data["dest_info"] == 'any'):
        policies = get_host_access_info(form.cleaned_data["source_info"])
        # newPolicies = get_policy_info(policies)
        print policies
      else:
        policies = get_host_info(form.cleaned_data["source_info"], form.cleaned_data["dest_info"], form.cleaned_data["app_info"])

        print policies

      context = { 
        'title':FWName,
        'policies':policies,
      }

      return render(request, "submit.html", context)
  
    else:
      errorStr = "Could not establish a connection to "
      errorStr += FWName
      return render(request, "submit.html", {"policies": errorStr}) 

def home(request):
    
    form = ContactForm()
 
    return render(request, "home.html", {'form':form})
 
@ensure_csrf_cookie
def modify_policy(request):
  if request.method == 'POST':
         
    form = ModifyPolicyForm(request.POST)
    # form = enterNewPolicyValues(request.POST)
 
    if form.is_valid():
      print form.cleaned_data["Firewalls"]
      firewall = form.cleaned_data["Firewalls"]
      # get creds from db
      querySet = Firewall.objects.all().filter(firewall_name=firewall)

      print [p.firewall_name for p in querySet]
    
      FWName = p.firewall_name
      hostname = p.firewall_manageip
      username = p.firewall_user
      password = p.firewall_pass
   
      # modify python code to take args and create new function
      if(connect_to_firewall(hostname, username, password)):
        policies = get_policy_info(form.cleaned_data["policy_info"])
        print 'Returned value from get_policy_info {}'.format(policies)
        policy_entry_check = Policies.policies.all()
        
        new_policy_entry = Policies(name=policies[0].get('Policy'), source_address=policies[0].get('Source'), destination_address=policies[0].get('Dest'), application=policies[0].get('Port'), firewall=FWName)
        policy_check = policy_entry_check.filter(name=policies[0].get('Policy'))
  
        if(policy_entry_check.filter(name=policies[0].get('Policy'))):
          print "Policy already exists in database."
          # policy_entry_check.delete()
        else:
          new_policy_entry.save(force_insert=True)
          # policy_entry_check.delete()
        
        context = { 
        'title':FWName,
        'policies':policies,
        }

        return render(request, "modify_policy_result.html", context)

      else:
        print "Policy not selected"
       
      context = { 
        'title':FWName,
        'policies':"Policy not selected",
        }

      return render(request, "modify_policy_result.html", context)

  else:
    print " GET in def modify_policy(request):"
    form = ModifyPolicyForm()
  
    return render(request, "modify_policy.html", {'form':form})

@ensure_csrf_cookie
def policyUpdate(request):
  if request.method == 'POST':
    policy_entry_check = Policies.policies.all()
# TODI: FIX THIS FUNCTION
    print "in modify_policy_result"
    context = { 
        'title':"firewall",
        'policies':policy_entry_check.filter(name='15544')
        }
    return render(request, "policyUpdate.html", context)
  else:
    form = enterNewPolicyValues()
 
    return render(request, "policyUpdate.html", {'form':form})

@ensure_csrf_cookie
def modify_policy_chosen(request):
      
  print "in modify_policy_chosen"
        
  form = enterNewPolicyValues()
 
  return render(request, "modify_policy_chosen.html", {'form':form})

class modify_policy_chosenView(generic.ListView):
      

  print "in modify_policy_chosenView"
      
  model = Policies

  context_object_name = 'policy_list'   # your own name for the list as a template variable
  queryset = Policies.policies.all() # Get all policies
  template_name = 'modify_policy_chosen.html'  # Specify your own template name/location

  def get_context_data(self, **kwargs):
    context = super(modify_policy_chosenView, self).get_context_data(**kwargs)
    context['some_data'] = 'This is just some data'
    return context
      
    

