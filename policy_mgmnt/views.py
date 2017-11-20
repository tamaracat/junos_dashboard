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
from .forms import ContactForm, ModifyPolicyForm, enterNewPolicyValues
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
        policies = get_host_access_info(dev, form.cleaned_data["source_info"])
        print policies
      elif (form.cleaned_data["dest_info"] == 'all'):
        policies = get_host_access_info_app(dev,form.cleaned_data["source_info"], form.cleaned_data["app_info"])
        print policies
      else:
        policies = get_host_info(dev, form.cleaned_data["source_info"], form.cleaned_data["dest_info"], form.cleaned_data["app_info"])
        # get_zone_host_info(dev, form.cleaned_data["source_info"], form.cleaned_data["dest_info"], form.cleaned_data["app_info"])
        print policies

        # print ','.join(policies[0].get('Source'))
        # print ','.join(policies[0].get('Dest'))

      dev.close()

      context = { 
        'title':FWName,
        'policies':policies,
      }

      return render(request, "submit.html", context)
  
    else:
      
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
        
    class MyDict(dict):
      def __repr__(self):
        s = "{"
        for key in self:
            s += "{0}:{1}, ".format(key, self[key])
        if len(s) > 1:
            s = s[0: -2]
        s += "}"
        return s
         
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
                
        print 'Returned value from get_policy_info {}'.format(policies)

        formatted_policy = MyDict(policies[0])
       

        print 'Formatted Policy {}'.format(formatted_policy)

        # chars_to_remove = ['[', ']', "'"]
        # new_src = str(formatted_policy.get('Source')).translate(None, ''.join(chars_to_remove))

        print formatted_policy

        # source=map(str.strip(str(policies[0].get('Source')))
        source = re.sub(r'[^\w]', '',str(formatted_policy.get('Source')))
        dest = re.sub(r'[^\w]', '',str(formatted_policy.get('Dest')))
        port = re.sub(r'[^\w]', '',str(formatted_policy.get('Port')))
        # print policies
        
        new_policy = Policies.objects.create_policy(name=policies[0].get('Policy'), source_address=source, destination_address=dest, application=port, action=policies[0].get('Action'),annotation='ttangney', firewall=FWName)
        new_policy.save()

        '''
        print [p.name for p in new_policy]
    
        Name = p.objects.name
        hostname = p.firewall_manageip
        source = p.destination_address
        app = p.application
        act = p.action
        firewall = p.objects.firewall
        '''
    
        # formatSrc =  ','.join(policies[0].get('Source'))

        # new_policy.delete()
      
        # p.objects.save(force_insert=True)

        dev.close()
        
        context = { 
        'title':FWName,
        'policies':policies,
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
  policy_entry_check = Policies.policies.all()[:1].get()
  # policy_entry_check = Policies.policies.all().get()
  
   
  context = { 
        'title':policy_entry_check.firewall,
        'databaseEntry':policy_entry_check,
        'form': form
        }

  return render(request, "policyUpdate.html", context)

@ensure_csrf_cookie
def DisplayPolicyToUpdate(request):
      
  if request.method == 'POST':
        
    pol_dict = {'Policy': '', 'Source': [], 'Dest': [], 'Port': [], 'Action': []}

    form = enterNewPolicyValues(request.POST)
    if form.is_valid():
      source =  form.cleaned_data["source_info"]
      dest = form.cleaned_data["dest_info"]
      app = form.cleaned_data["app_info"]
        
      # new_policy_entry = Policies(name=policies[0].get('Policy'), source_address=','.join(policies[0].get('Source')), destination_address=','.join(policies[0].get('Dest')), application=','.join(policies[0].get('Port')), action=','.join(policies[0].get('Action')),firewall=FWName)
      
      policy_entry_check = Policies.policies.all()[:1].get()
      # policy_entry_check = Policies.policies.all().get()

      print policy_entry_check.name

      # pol_dict['Policy'].append(str(policy_entry_check.name))
      # pol_dict['Source'].append(policy_entry_check.object.source_address)
      # pol_dict['Dest'].append(policy_entry_check.object.destination_address)
      # pol_dict['Port'].append(policy_entry_check.object.application)
      # pol_dict['Action'].append(policy_entry_check.object.action)
   
    context = { 
          'title':policy_entry_check.firewall,
          'databaseEntry':policy_entry_check,
        }

    return render(request, "DisplayPolicyToUpdate.html", context)

  else:
    print 'GET DisplayPolicyToUpdate'
    context = { 
          'title':"GET",
        }
    return render(request, "DisplayPolicyToUpdate.html", context)
        
'''

class ApplyChanges(generic.ListView):
      

  print "in modify_policy_chosenView"
      
  model = Policies

  context_object_name = 'policy_list'   # your own name for the list as a template variable
  queryset = Policies.policies.all() # Get all policies
  template_name = 'policyUpdate.html'  # Specify your own template name/location
  
  policy_entry_check = Policies.policies.all()[:1].get()
    
  context = { 
        'title':policy_entry_check.firewall,
        'databaseEntry':policy_entry_check
        }
  print policy_entry_check.firewall
  def get_context_data(self, **kwargs):
    context = super(ApplyChanges, self).get_context_data(**kwargs)
    # context['some_data'] = 'This is just some data'
    return context
'''

      
    

