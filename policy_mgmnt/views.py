from __future__ import unicode_literals
import subprocess
from django.views import generic
from django.views.generic.detail import DetailView
from django.views.generic.edit import FormView
from django.http import Http404
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
globalFWName=''

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
    # dev = connect_to_firewall(hostname, username, password)
    # get_device_configuration(hostname, dev)
    run=True
    if(run):
      sourceDatabaseEntry=False
      destDatabaseEntry=False
    # call function and pass parameters to log in to fw
      if (form.cleaned_data["dest_info"] == 'all' and form.cleaned_data["app_info"] == 'all'):
        # global_policies = get_host_access_info(dev, 'CISCO-VOIP-PUBLIC.GLOBAL')
        policies = get_host_to_all_info(hostname, form.cleaned_data["source_info"], form.cleaned_data["dest_info"])
        sourceDatabaseEntry=True
        sourceIP = form.cleaned_data["source_info"]
      elif (form.cleaned_data["source_info"] == 'all' and form.cleaned_data["app_info"] == 'all'):
        policies = get_host_to_all_info(hostname, form.cleaned_data["source_info"], form.cleaned_data["dest_info"])
        destDatabaseEntry=True
        destIP = form.cleaned_data["dest_info"]
      else:
        policies = get_source_dest_app_policy_info(form.cleaned_data["source_info"], form.cleaned_data["dest_info"], form.cleaned_data["app_info"])
        # get_zone_host_info(dev, form.cleaned_data["source_info"], form.cleaned_data["dest_info"], form.cleaned_data["app_info"])

      # dev.close()  
    
      policy_table_clear = Policies.objects.all()
      policy_table_clear.delete()
      # print policies
      for item in policies:
          policy = re.sub(r'[^\w]', " ",str(item.get('Policy')))
          source = str(item.get('Source'))
          # source = re.sub(r'[^\w]', " ",str(item.get('Source')))
          dest = str(item.get('Dest'))
          port = str(item.get('Port'))
          defined_as = str(item.get('Defined_As'))
          address_set = str(item.get('Address_Set'))
          action = re.sub(r'[^\w]', " ",str(item.get('Action')))
        
          
          new_policy = Policies.objects.create_policy(name=policy, source_address=source, destination_address=dest, application=port, action=action, defined_as=defined_as, address_set=address_set, annotation='ttangney', firewall=FWName)
          new_policy.save()

          displayPolicy = Policies.objects.all()
          displayObjectVars = Policies.objects.all()[:1]

      if policies: 
        if sourceDatabaseEntry: 
          context = { 
            'title':FWName,
            'sourceIP': sourceIP,
            'source_databaseEntry':displayPolicy,
            'displayObjectVars' :displayObjectVars,
            }
        elif destDatabaseEntry:
          context = { 
            'title':FWName,
            'destIP': destIP,
            'dest_databaseEntry':displayPolicy,
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
    print " POST in def modify_policy(request):"
    form = ModifyPolicyForm(request.POST)
 
    if form.is_valid():
      print form.cleaned_data["Firewalls"]
      firewall = form.cleaned_data["Firewalls"]
      # get creds from db
      querySet = Firewall.objects.all().filter(firewall_name=firewall)

      print [p.firewall_name for p in querySet]
      globalFWName = p.firewall_name
      FWName = p.firewall_name
      hostname = p.firewall_manageip
      username = p.firewall_user
      password = p.firewall_pass
      # modify python code to take args and create new function
      # dev = connect_to_firewall(hostname, username, password) 
      run=True
      if(run):
        # python function get policy from  selected firewall for policy name
        policies = get_policy_info(hostname, form.cleaned_data["policy_info"])   
        print policies              
        print 'Returned value from get_policy_info {}'.format(policies)
      
        policy_table_clear = Policies.objects.all()
        policy_table_clear.delete()
        
        if isinstance(policies, list):
          for item in policies:
            policy = str(item.get('Policy'))
            source = str(item.get('Source'))
            dest = str(item.get('Dest'))
            port = str(item.get('Port'))
            action = str(item.get('Action'))
        
            new_policy = Policies.objects.create_policy(name=policy, source_address=source, destination_address=str(item.get('Dest')), application=port, action=action, defined_as="empty", address_set="none", annotation='ttangney', firewall=FWName)
            new_policy.save()

            displayPolicy = Policies.objects.all()
            
            if Policies:
              context = { 
              'title':FWName,
              'source_databaseEntry':displayPolicy,
              }
      
              return render(request, "modify_policy.html", context)
        else:
          print "Policy not selected"
       
          context = { 
            'title':FWName,
            'policy_not_present':"Policy not selected",
            }

          return render(request, "modify_policy.html", context)
  
  else:
    print " GET in def modify_policy(request):"
    form = ModifyPolicyForm()
  
    return render(request, "modify_policy.html", {'form':form})

@ensure_csrf_cookie
def policyUpdate(request):
      
  pol_dict = {'Policy': '', 'Source': [], 'Dest': [], 'Port': [], 'Action': []}

  if request.method == 'POST':  
    form = enterNewPolicyValues(request.POST or None)
   
    displayPolicy = Policies.objects.all()
    print displayPolicy
                      
    context = {
       'source_databaseEntry':displayPolicy,
       'form': form
      }
    
    return render(request, "policyUpdate.html", context)
  
  elif request.method == 'GET':
    print " GET in def policyUpdate(request):"
    print ("firewall is: {}").format(globalFWName) 
    form = enterNewPolicyValues(request.GET)
    if form.is_valid():
      policy_info = form.cleaned_data["policy_info"]
      print("id: {}").format(policy_info)
      source_info = form.cleaned_data["source_info"]
      # if isinstance (source_info, str):
      if source_info != '':
        print("source: {}").format(source_info)
      dest_info = form.cleaned_data["dest_info"]
      # if isinstance (dest_info, str):
      if dest_info != '':
        print("dest: {}").format(dest_info)
      app_info = form.cleaned_data["app_info"]
      # if isinstance (app_info, str):
      if app_info != '':
        print("service: {}").format(app_info)
      
      #find and display policy stored in database
      try:
        querySet = Policies.objects.all().filter(name=policy_info).get()
        name = querySet.name
        print querySet.name
        print querySet.source_address
        print querySet.destination_address
        print querySet.firewall
      except Policies.DoesNotExist:
            raise Http404("No Policies matches the given query.")
      else:
      
          message_string = "Policy " + querySet.name

          context = { 
          'title':querySet.firewall,
          'message':message_string,
          'proposed_mod': 'yes',
          'form': form
            }  
          return render(request, "policyUpdate.html", context)
     

@ensure_csrf_cookie
def DisplayPolicyToUpdate(request):
      
  if request.method == 'GET':     
    form = enterNewPolicyValues(request.GET or None)
    if form.is_valid():
      source =  form.cleaned_data["source_info"]
      dest = form.cleaned_data["dest_info"]
      app = form.cleaned_data["app_info"]
         
      policy_entry_check = Policies.policies.all().get()
   
      context = { 
          'title':policy_entry_check.firewall,
          'databaseEntry':policy_entry_check,
        }

      return render(request, "DisplayPolicyToUpdate.html", context)

def get_facts(request):
      
  if request.method == 'GET':
    form = FirewallFactsForm(request.GET)
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
      # dev = connect_to_firewall(hostname, username, password)
      run=True
      if(run):
        Facts = GetDeviceFacts(hostname)

        titleStr = "Facts for " + FWName
        context = { 
          'title': titleStr,
          'facts':Facts,
          'form': form
          }
        # dev.close()  

        return render(request, "submit.html", context)
      else:
        
        errorStr = "Could not establish a connection to "
        errorStr += FWName
      
        context = { 
          'title': errorStr,
          'form': form
          } 

        return render(request, "get_facts.html", context)
          
    

      
    

