#!/usr/bin/env python
__author__ = 'Tamara Tangney'
__email__ = 'tangney@northwestern.edu'
import paramiko
from paramiko import SSHClient, SSHConfig
import netmiko
from netmiko import ConnectHandler
import StringIO
from lxml import etree
import sys
from jnpr.junos.exception import ConnectError
from jnpr.junos.exception import CommitError


modnum = 0
'''
# Netmiko Device Login
juniper_ex2200 = {
    'device_type': 'juniper',
    'ip': '165.124.17.133',
    'username': 'srxadmin',
    'password': 'l1b2bstssrx',
    'secret': '',
    'use_keys': False,
    'alt_host_keys': True,
    'alt_key_file': '/Users/tamaratangney/.ssh/id_rsa',
    'verbose': False,
}


SSHClass = netmiko.ssh_dispatcher(device_type=juniper_ex2200['device_type'])
device_conn = SSHClass(**juniper_ex2200)
output = device_conn.send_command('show chassis hardware | display xml')
PolOutput = device_conn.send_command('show security policies global | display xml')
AddrOutput = device_conn.send_command('show security address-book | display xml')


fd = open('junos-chassis.xml', 'w')
# fd.write(output.strip())
fd.write(PolOutput.strip())
# print output
fd.close()

#  END of # Netmiko Device Login
'''
  # zone_vrs = PolicyContextTable(path=junos_config_path)
  # zone_context = zone_vrs.get() 
'''
  for zone in zone_context:
        # Connects to firewall
     
      policies = PolicyRuleTable(path=junos_config_path).get(policy=[zone.from_zone,zone.to_zone], options=table_options)
      print policies
      
      print policies 
      for addr_obj in list_of_objects:   
          for item in policies:
            
            src_match=False  
            if(addr_obj == item.match_src ):
              src_match = True
              pol_dict['Src_Zone'] = zone.from_zone
              pol_dict['Dst_Zone'] = zone.to_zone
              pol_dict['Source'] = item.match_src
              pol_dict['Dest'] = item.match_dst
              pol_dict["Port"] = item.match_app
              pol_dict['Action'] = item.action 
              pol_dict['Policy'] = item.name 
   
            if(src_match):
              policies_list.append(pol_dict.copy())
  '''  
  # num_zone_policies = PolicyRuleTable(path=junos_config_path).get(policy=['any','any'], options=table_options)   
  # print num_zone_policies


def connect_to_firewall(hostname, username, password):
  connect = False
  port = 22

  try:
    client = paramiko.SSHClient()
    client.load_system_host_keys()
    client.set_missing_host_key_policy(paramiko.WarningPolicy)
    
    client.connect(hostname, port=port, username=username, password=password)
    # stdin, stdout, stderr = client.exec_command('show security address-book global | display xml')
  
    stdin, stdout, stderr = client.exec_command('show security policies global | display xml')
    # stdin, stdout, stderr = client.exec_command('show security policies | display xml')
    output = stdout.read()

    fd = open('junos-chassis.xml', 'w')
    # fd.write(output.strip())
    fd.write(output)
    # print output
    fd.close()

    connect = True

  except:
    print "ERROR -- Failed to connect to {}".format(hostname)
    connect = False

  finally:
      client.close()
      
  return connect



def get_host_info(source, dest, port):

  xmldoc = etree.parse('junos-chassis.xml')
  docroot = xmldoc.getroot()
  
  policies_list = []
  i=0
  for ele in docroot.iter('{*}policy-information'):
    src_match=False
    dest_match=False
    app_match=False
    i=i+1
    pol_dict = {'Policy': '', 'Source': [], 'Dest': [], 'Port': [], 'Action': []}
        
    for sourceAddr in ele.iter('{*}source-address'):
      
      if(source == sourceAddr.find('{*}address-name').text ):
        src_match = True
        pol_dict['Source'].append(sourceAddr.find('{*}address-name').text)
        # print("Source Address: {}".format(sourceAddr.find('{*}address-name').text))
    
    for destAddr in ele.iter('{*}destination-address'):  
      if(dest == destAddr.find('{*}address-name').text):
          dest_match = True
          pol_dict['Dest'].append(destAddr.find('{*}address-name').text)
        # print("Destination Address: {}".format(destAddr.find('{*}address-name').text))
    
    for app in ele.iter('{*}application'):
      if(port == app.find('{*}application-name').text):
          app_match = True
          pol_dict["Port"].append(app.find('{*}application-name').text)
        # print("Application: {}".format(app.find('{*}application-name').text))
    
    for action in ele.iter('{*}policy-action'):
      pol_dict["Action"].append(action.find('{*}action-type').text)
        # print("Policy: {}".format(policy_to_match))  
      pol_dict['Policy'] = ele.find('{*}policy-name').text 
      # print("Policy: {}".format(ele.find('{*}policy-name').text))
      if(src_match & dest_match & app_match):
        policies_list.append(pol_dict)
      print i
  return policies_list  

def get_host_access_info(source):
    
  xmldoc = etree.parse('junos-chassis.xml')
  docroot = xmldoc.getroot()
  
  policies_list = []
  i=0
  for ele in docroot.iter('{*}policy-information'):
    pol_dict = {'Policy': '', 'Source': [], 'Dest': [], 'Port': [], 'Action': []}
    is_match=False
    for sourceAddr in ele.iter('{*}source-address'):
      is_match=False
      if(source == sourceAddr.find('{*}address-name').text ):
        pol_dict['Source'].append(sourceAddr.find('{*}address-name').text)
        is_match = True
        pol_dict['Policy'] = ele.find('{*}policy-name').text 
    for destAddr in ele.iter('{*}destination-address'): 
      pol_dict['Dest'].append(destAddr.find('{*}address-name').text)
    for app in ele.iter('{*}application'):
      pol_dict["Port"].append(app.find('{*}application-name').text)
    for action in ele.iter('{*}policy-action'):
      pol_dict["Action"].append(action.find('{*}action-type').text)
    if is_match:    
      policies_list.append(pol_dict)

  return policies_list 


def get_policy_info(pol_name):
 
  print pol_name   
  policies_list = []
    
  xmldoc = etree.parse('junos-chassis.xml')
  docroot = xmldoc.getroot()
  
        
  for ele in docroot.iter('{*}policy-information'):
    pol_dict = {'Policy': '', 'Source': [], 'Dest': [], 'Port': [], 'Action': []}
    is_match=False
    # print "policy name passed in {}".format(pol_name)
    if(pol_name == ele.find('{*}policy-name').text):
      is_match = True
      pol_dict['Policy'] = ele.find('{*}policy-name').text 
      for sourceAddr in ele.iter('{*}source-address'):
        pol_dict['Source'].append(sourceAddr.find('{*}address-name').text)
      for destAddr in ele.iter('{*}destination-address'): 
        pol_dict['Dest'].append(destAddr.find('{*}address-name').text)
      for app in ele.iter('{*}application'):
        pol_dict["Port"].append(app.find('{*}application-name').text)
      for action in ele.iter('{*}policy-action'):
          pol_dict["Action"].append(action.find('{*}action-type').text)
      if is_match: 
        policies_list.append(pol_dict)

        # print policies_list

  return policies_list  

def clone_ruleset(old_host):

  '''
  show configuration | display set | match old_host

  '''