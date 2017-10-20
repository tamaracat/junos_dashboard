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

hostname = '165.124.17.133'
password = 'l1b2bstssrx'

username = "srxadmin"
port = 22

try:
  client = paramiko.SSHClient()
  client.load_system_host_keys()
  client.set_missing_host_key_policy(paramiko.WarningPolicy)
    
  client.connect(hostname, port=port, username=username, password=password)

  stdin, stdout, stderr = client.exec_command('show security policies global | display xml')
  print stdout.read()

  fd = open('junos-chassis.xml', 'w')
  # fd.write(output.strip())
  fd.write('any')
  # print output
  fd.close()

finally:
    client.close()

def get_host_info(source, dest, port):

  xmldoc = etree.parse('junos-chassis.xml')
  docroot = xmldoc.getroot()
  
  policies_list = []
  i=0
  for ele in docroot.iter('{*}policy-information'):
    is_match=False
    dest_match=False
    app_match=False
    i=i+1
    pol_dict = {'Policy': '', 'Source': [], 'Dest': [], 'Port': []}
        
    for sourceAddr in ele.iter('{*}source-address'):
      if(source == sourceAddr.find('{*}address-name').text ):
        is_match = True
        pol_dict['Source'].append(sourceAddr.find('{*}address-name').text)
        # print("Source Address: {}".format(sourceAddr.find('{*}address-name').text))
    
    for destAddr in ele.iter('{*}destination-address'):  
      if(dest == destAddr.find('{*}address-name').text):
          is_match = True
          pol_dict['Dest'].append(destAddr.find('{*}address-name').text)
        # print("Destination Address: {}".format(destAddr.find('{*}address-name').text))
    
    for app in ele.iter('{*}application'):
      if(port == app.find('{*}application-name').text):
          is_match = True
          pol_dict["Port"].append(app.find('{*}application-name').text)
        # print("Application: {}".format(app.find('{*}application-name').text))

        # print("Policy: {}".format(policy_to_match))  
      pol_dict['Policy'] = ele.find('{*}policy-name').text 
      # print("Policy: {}".format(ele.find('{*}policy-name').text))
      if(is_match):
        policies_list.append(pol_dict)
      print i
  return policies_list  