from __future__ import unicode_literals
import subprocess
from django.views import generic
from django.views.generic.detail import DetailView
from django.views.generic.edit import FormView
from django.utils import timezone
from django.shortcuts import render
from django.http import HttpResponse
from django.core.urlresolvers import reverse
from models import Firewall, Policies, FirewallManager, PolicyManager
from django.views.decorators.csrf import ensure_csrf_cookie
from scripts.pyEZJuniper import *
from .forms import ContactForm, ModifyPolicyForm, enterNewPolicyValues, FirewallFactsForm
from django.template import loader
import re
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
    dev = connect_to_firewall(hostname, username, password)
    if(dev):
    # call function and pass parameters to log in to fw

      if (form.cleaned_data["dest_info"] == 'all' and form.cleaned_data["app_info"] == 'all'):
        # global_policies = get_host_access_info(dev, 'CISCO-VOIP-PUBLIC.GLOBAL')
        policies = get_host_to_all_info(hostname, dev, form.cleaned_data["source_info"])
 
      elif (form.cleaned_data["dest_info"] == 'all'):
        policies = get_host_access_info_app(dev,form.cleaned_data["source_info"], form.cleaned_data["app_info"])
        # print policies
      else:
        policies = get_host_info(dev, form.cleaned_data["source_info"], form.cleaned_data["dest_info"], form.cleaned_data["app_info"])
        # get_zone_host_info(dev, form.cleaned_data["source_info"], form.cleaned_data["dest_info"], form.cleaned_data["app_info"])

   
      dev.close()  
    
      policy_table_clear = Policies.objects.all()
      policy_table_clear.delete()
      # print policies
      for item in policies:
          Src_Zone = str(item.get('Src_Zone'))
          print Src_Zone
          Dst_Zone = str(item.get('Dst_Zone'))
          policy = re.sub(r'[^\w]', " ",str(item.get('Policy')))
          print policy
          source = str(item.get('Source'))
          # source = re.sub(r'[^\w]', " ",str(item.get('Source')))
          dest = str(item.get('Dest'))
          # dest = re.sub(r'[^\w]', " ",str(item.get('Dest')))
          port = str(item.get('Port'))
          source_ip = str(item.get('Source_IP'))
          defined_as = str(item.get('Defined_As'))
          address_set = str(item.get('Address_Set'))
          # port = re.sub(r'[^\w]', " ",str(item.get('Port')))
          action = re.sub(r'[^\w]', " ",str(item.get('Action')))
        
          
          new_policy = Policies.objects.create_policy(src_zone=Src_Zone, dst_zone=Dst_Zone,name=policy, source_address=source, destination_address=str(item.get('Dest')), application=port, action=action, source_ip=source_ip, defined_as=defined_as, address_set=address_set, annotation='ttangney', firewall=FWName)
          new_policy.save()

          displayPolicy = Policies.objects.all()
          displayObjectVars = Policies.objects.all()[:1]

      if policies:  
        context = { 
          'title':FWName,
          'source_databaseEntry':displayPolicy,
          'displayObjectVars' :displayObjectVars,
          }

        return render(request, "submit.html", context)
      else:
        context = { 
          'title':"No Policies Present for Data Entered",
          }

        return render(request, "submit.html", context)
            
    else:
      print "Could not establish a connection to "
      errorStr = "Could not establish a connection to "
      errorStr += FWName
      context = { 
        'title':errorStr
      }
      return render(request, "submit.html", context) 

def home(request):
    
    form = ContactForm()
 
    return render(request, "home.html", {'form':form})
 
@ensure_csrf_cookie
def modify_policy(request):

  if request.method == 'POST':

    form = ModifyPolicyForm(request.POST)
 
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
      dev = connect_to_firewall(hostname, username, password)
      if(dev):
        # python function get policy from  selected firewall
        policies = get_policy_info(dev, form.cleaned_data["policy_info"])

        print policies
                
        print 'Returned value from get_policy_info {}'.format(policies)
      
        policy_table_clear = Policies.objects.all()
        policy_table_clear.delete()

        for item in policies:
          policy = re.sub(r'[^\w]', " ",str(item.get('Policy')))
          source = re.sub(r'[^\w]', " ",str(item.get('Source')))
          print policy
          dest = re.sub(r'[^\w]', " ",str(item.get('Dest')))
          port = re.sub(r'[^\w]', " ",str(item.get('Port')))
          action = re.sub(r'[^\w]', " ",str(item.get('Action')))
        
        new_policy = Policies.objects.create_policy(name=policy, source_address=source, destination_address=dest, application=port, action=action,annotation='ttangney', firewall=FWName)
        new_policy.save()

        # displayPolicy = Policies.objects.all()

        dev.close()
        
        context = { 
        'title':FWName,
        'databaseEntry':new_policy,
        }

        return render(request, "policyUpdate.html", context)

      else:
        print "Policy not selected"
       
      context = { 
        'title':FWName,
        'policies':"Policy not selected",
        }

      return render(request, "modify_policy.html", context)

  else:
    print " GET in def modify_policy(request):"
    form = ModifyPolicyForm()
  
    return render(request, "modify_policy.html", {'form':form})

@ensure_csrf_cookie
def policyUpdate(request):
     
  form = enterNewPolicyValues(request.GET or None)
  policy_entry_check = Policies.policies.all().get()
  
   
  context = { 
        'title':policy_entry_check.firewall,
        'databaseEntry':policy_entry_check,
        'form': form
        }

  return render(request, "policyUpdate.html", context)

@ensure_csrf_cookie
def DisplayPolicyToUpdate(request):
        
  form = enterNewPolicyValues(request.POST)
  if form.is_valid():
      source =  form.cleaned_data["source_info"]
      dest = form.cleaned_data["dest_info"]
      app = form.cleaned_data["app_info"]
        
      # new_policy_entry = Policies(name=policies[0].get('Policy'), source_address=','.join(policies[0].get('Source')), destination_address=','.join(policies[0].get('Dest')), application=','.join(policies[0].get('Port')), action=','.join(policies[0].get('Action')),firewall=FWName)
      
      policy_entry_check = Policies.policies.all().get()
   
      context = { 
          'title':policy_entry_check.firewall,
          'databaseEntry':policy_entry_check,
        }

      return render(request, "DisplayPolicyToUpdate.html", context)
def get_facts(request):
      
  if request.method == 'GET':
    form = FirewallFactsForm(request.GET or None)
    return render(request, "get_facts.html", {'form':form})

  elif request.method == 'POST':
        
    form = FirewallFactsForm(request.POST)

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
      dev = connect_to_firewall(hostname, username, password)
      if(dev):
        Facts = GetDeviceFacts(dev)

        titleStr = "Facts for " + FWName
        context = { 
          'title': titleStr,
          'facts':Facts,
          'form': form
          }
        dev.close()  

        return render(request, "submit.html", context)
      else:
        
        errorStr = "Could not establish a connection to "
        errorStr += FWName
      
        context = { 
          'title': errorStr,
          'form': form
          } 

        return render(request, "get_facts.html", context)
          
    

      
    

