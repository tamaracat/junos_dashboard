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
from models import Firewall, Policies, FirewallManager, PolicyManager, Engineer
from django.views.decorators.csrf import ensure_csrf_cookie
from scripts.pyEZJuniper import *
from .forms import ContactForm, ModifyPolicyForm, enterNewPolicyValues, FirewallFactsForm
from django.template import loader
from datetime import datetime, timedelta
import datetime
from pytz import timezone
import pytz
import re, json

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
    #dev = connect_to_firewall(hostname, username, password)
    #get_device_configuration(hostname, dev)
    run=True
    if(run):
      sourceDatabaseEntry=False
      destDatabaseEntry=False
      source_dest_databaseEntry=False
      all_destDatabaseEntry=False
    # call function and pass parameters to log in to fw
      if (form.cleaned_data["dest_info"] == '' and form.cleaned_data["app_info"] == ''):
        policies = get_host_to_all_info(hostname, form.cleaned_data["source_info"], form.cleaned_data["dest_info"])
        sourceDatabaseEntry=True
        sourceIP = form.cleaned_data["source_info"]
      elif (form.cleaned_data["source_info"] == '' and form.cleaned_data["app_info"] == ''):
        policies = get_host_to_all_info(hostname, form.cleaned_data["source_info"], form.cleaned_data["dest_info"])
        destDatabaseEntry=True
        destIP = form.cleaned_data["dest_info"]
        # print policies
      elif (form.cleaned_data["source_info"] != '' and form.cleaned_data["dest_info"] != '' and form.cleaned_data["app_info"] == ''):
        policies = get_source_and_dest_info(hostname, form.cleaned_data["source_info"], form.cleaned_data["dest_info"])
        source_dest_databaseEntry=True
        sourceIP = form.cleaned_data["source_info"]
        destIP = form.cleaned_data["dest_info"] 
      elif (form.cleaned_data["source_info"] != '' and form.cleaned_data["dest_info"] != '' and form.cleaned_data["app_info"] != ''):
        policies = get_source_dest_app_policy_info(hostname, form.cleaned_data["source_info"], form.cleaned_data["dest_info"], form.cleaned_data["app_info"])
        source_dest_databaseEntry=True
        sourceIP = form.cleaned_data["source_info"]
        destIP = form.cleaned_data["dest_info"] 
        Service = form.cleaned_data["app_info"]  
      elif (form.cleaned_data["source_info"] != '' and form.cleaned_data["dest_info"] == '' and form.cleaned_data["app_info"] != ''):
        policies = get_source_dest_app_policy_info(hostname, form.cleaned_data["source_info"], form.cleaned_data["dest_info"], form.cleaned_data["app_info"])
        source_dest_databaseEntry=True
        sourceIP = form.cleaned_data["source_info"]
        destIP = form.cleaned_data["dest_info"] 
        Service = form.cleaned_data["app_info"]      
      elif (form.cleaned_data["source_info"] == '' and form.cleaned_data["dest_info"] != '' and form.cleaned_data["app_info"] != ''):
        policies = get_source_dest_app_policy_info(hostname, form.cleaned_data["source_info"], form.cleaned_data["dest_info"], form.cleaned_data["app_info"])
        source_dest_databaseEntry=True
        sourceIP = form.cleaned_data["source_info"]
        destIP = form.cleaned_data["dest_info"] 
        Service = form.cleaned_data["app_info"]          
      # dev.close()  
    
      policy_table_clear = Policies.objects.all()
      policy_table_clear.delete()
      print policies
      for item in policies:
          policy = re.sub(r'[^\w]', " ",str(item.get('Policy')))
          source = str(item.get('Source'))
          source_ip = str(item.get('Source_IP'))
          dest_ip = str(item.get('Dest_IP'))
          # source = re.sub(r'[^\w]', " ",str(item.get('Source')))
          dest = str(item.get('Dest'))
          port = str(item.get('Port'))
          defined_as = str(item.get('Defined_As'))
          dest_defined_as = str(item.get('DstDefined_As'))
          address_set = str(item.get('Address_Set'))
          dst_address_set = str(item.get('Dst_Address_Set'))
          action = re.sub(r'[^\w]', " ",str(item.get('Action')))
           
          new_policy = Policies.objects.create_policy(name=policy, source_address=source, source_ip=source_ip, destination_address=dest, dest_ip=dest_ip, application=port, action=action, defined_as=defined_as, dest_defined_as=dest_defined_as, address_set=address_set, dst_address_set=dst_address_set,annotation='ttangney', firewall=FWName)
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
        elif source_dest_databaseEntry:
            context = { 
              'title':FWName,
              'sourceIP': sourceIP,
              'destIP': destIP,
              'source_dest_databaseEntry':displayPolicy,
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
        # print policies              
        print 'Returned value from get_policy_info {}'.format(policies)
      
        policy_table_clear = Policies.objects.all()
        policy_table_clear.delete()
        
        if policies:
          for item in policies:
            policy = str(item.get('Policy'))
            source = str(item.get('Source'))
            dest = str(item.get('Dest'))
            port = str(item.get('Port'))
            action = str(item.get('Action'))

            new_policy = Policies.objects.create_policy(name=policy, source_address=source, source_ip="empty", destination_address=str(item.get('Dest')), dest_ip="empty", application=port, action=action, defined_as="empty", dest_defined_as="empty", address_set="none", dst_address_set="none", annotation='ttangney', firewall=FWName)
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

def next_weekday(d, weekday):
  days_ahead = weekday - d.weekday()
  if days_ahead <= 0: # Target day already happened this week
      days_ahead += 7
  return d + datetime.timedelta(days_ahead)

@ensure_csrf_cookie
def policyUpdate(request):
      
  utc_now = pytz.utc.localize(datetime.datetime.utcnow())
  cst_now = utc_now.astimezone(pytz.timezone("America/Chicago"))
  print cst_now
  print cst_now.month
  print cst_now.day
  print cst_now.year

  # date_str = cst_now.month + '/' + cst_now.day + '/' + cst_now.year
  
  pol_dict = {'Policy': '', 'Source': [], 'Dest': [], 'App': [], 'Engineer': '', 'Ticket': '', 'Date': '', 'EngDate': ''}
  create_address_obj_dict = {'Address': [], 'Object': []}
  address_obj_list=[]
  
  if request.method == 'POST':  
    form = enterNewPolicyValues(request.POST or None)
   
    displayPolicy = Policies.objects.all()
    # print displayPolicy
                      
    context = {
       'source_databaseEntry':displayPolicy,
       'form': form
      }
    
    return render(request, "policyUpdate.html", context)
  
  elif request.method == 'GET':
 
    form = enterNewPolicyValues(request.GET)
    if form.is_valid():     
      source_info = form.cleaned_data["source_info"]
      dest_info = form.cleaned_data["dest_info"]
      app_info = form.cleaned_data["app_info"]

      engineer = form.cleaned_data["eng_name"]
      if engineer != '':
        #  print("Engineer: {}").format(engineer)      
         querySet = Engineer.objects.all().filter(engineer_name=engineer)
         print [p.engineer_name for p in querySet]
         EngineerWName = p.engineer_fw_sig
         pol_dict['Engineer'] = EngineerWName

      fp_ticket = form.cleaned_data["fp_ticket"]
      if app_info != '':
        print("Ticket: {}").format(fp_ticket)
        pol_dict['Ticket'] = fp_ticket

      patch_day = form.cleaned_data["patch_day"]
      if patch_day != '':
        print("Patch Day: {}").format(patch_day)
        
      if patch_day == 'Tuesday':
        d = datetime.datetime.now().date()
        day = next_weekday(d, 1) # 0 = Monday, 1=Tuesday, 2=Wednesday...
        print('next_tuesday: {}').format(day)
        year = str(day.year).lstrip('20')
        month = str(day.month).zfill(2)
        day = str(day.day).zfill(2)
        patch_day_str = month + day + year
        eng_patch_day_str = month + '/' + day + '/' + year
        pol_dict['Date'] = patch_day_str 
        pol_dict['EngDate'] = eng_patch_day_str 
          
      elif patch_day == 'Friday':
        d = datetime.datetime.now().date()
        day = next_weekday(d, 4) # 0 = Monday, 1=Tuesday, 2=Wednesday...
        print('next_friday: {}').format(day)
        year = str(day.year).lstrip('20')
        month = str(day.month).zfill(2)
        day = str(day.day).zfill(2)
        patch_day_str = month + day + year
        eng_patch_day_str = month + '/' + day + '/' + year

        pol_dict['Date'] = patch_day_str 
        pol_dict['EngDate'] = eng_patch_day_str 
         
      #find and display policy stored in database
      try:
        database_entry = Policies.objects.all()[:1]
        querySet = Policies.objects.all().get()
 
        name = querySet.name
        print querySet.name
        print querySet.source_address
        print querySet.destination_address
        print querySet.firewall
      except Policies.DoesNotExist:
            raise Http404("No Policies matches the given query.")
      else:
           try:
            Firewall_IP = Firewall.objects.all().get(firewall_name=querySet.firewall)
           except Policies.DoesNotExist:
            raise Http404("No Policies matches the given query.")
           else:
            address_obj_create = False
            add_source=False
            add_dest=False
            if source_info != '':
              add_source=True
              address_obj = find_obj_defn(Firewall_IP.firewall_manageip, source_info)
              if address_obj:
                pol_dict['Source'] = address_obj[0]
              else:
                created_address_obj = create_address_object(source_info)
                pol_dict['Source'] = created_address_obj
                create_address_obj_dict['Address'] = source_info
                create_address_obj_dict['Object'] = created_address_obj
                address_obj_list.append(create_address_obj_dict)
                address_obj_create=True
                print ('create_address_obj_dict {}').format(create_address_obj_dict)
            if dest_info != '':
              add_dest=True
              address_obj = find_obj_defn(Firewall_IP.firewall_manageip, dest_info)
              if address_obj:
                pol_dict['Dest'] = address_obj[0]
              else:
                created_address_obj = create_address_object(dest_info)
                pol_dict['Dest'] = created_address_obj
                create_address_obj_dict['Address'] = dest_info
                create_address_obj_dict['Object'] = created_address_obj
                address_obj_list.append(create_address_obj_dict)
                address_obj_create=True
                print ('create_address_obj_dict {}').format(create_address_obj_dict)
                
            if app_info != '':
              pol_dict['App'] = app_info
              
            message_string = "Policy " + querySet.name

            pol_dict['Policy'] = querySet.name
            print pol_dict.get('Date')

            if address_obj_create and add_source and add_dest:
              context = { 
              'firewall':querySet.firewall,
              'create_address_obj': address_obj_list,
              'source_database_entry': database_entry,
              'policies': pol_dict,
              'form': form
              }    
            elif address_obj_create and add_source == False and add_dest:
               context = { 
              'no_source': 'no_source',
              'firewall':querySet.firewall,
              'create_address_obj': address_obj_list,
              'source_database_entry': database_entry,
              'policies': pol_dict,
              'form': form
              }  
            elif address_obj_create and add_source and add_dest == False:
              context = { 
              'no_dest': 'no_dest',
              'firewall':querySet.firewall,
              'create_address_obj': address_obj_list,
              'source_database_entry': database_entry,
              'policies': pol_dict,
              'form': form
              }  
            elif address_obj_create==False and add_source and add_dest:
               context = { 
              'firewall':querySet.firewall,
              'source_database_entry': database_entry,
              'policies': pol_dict,
              'form': form
              } 
            elif address_obj_create==False and add_source == False and add_dest: 
              context = { 
              'no_source': 'no_source',
              'firewall':querySet.firewall,
              'source_database_entry': database_entry,
              'policies': pol_dict,
              'form': form
              }
            elif address_obj_create==False and add_source and add_dest==False:    
              context = { 
              'no_dest': 'no_dest',
              'firewall':querySet.firewall,
              'source_database_entry': database_entry,
              'policies': pol_dict,
              'form': form
              }            
            return render(request, "policyUpdate.html", context)
     

@ensure_csrf_cookie
def DisplayPolicyToUpdate(request):     
  return True

def products_view(request):
    price_lte = request.GET['price_lte']
    #Code to filter products whose price is less than price_lte i.e. 5000

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
          
    

      
    

