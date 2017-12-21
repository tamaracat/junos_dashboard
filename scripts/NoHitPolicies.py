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



def connect_to_firewall(hostname, username, password):
  connect = False
  port = 22

  try:
    client = paramiko.SSHClient()
    client.load_system_host_keys()
    client.set_missing_host_key_policy(paramiko.WarningPolicy)
    
    client.connect(hostname, port=port, username=username, password=password)

    # stdin, stdout, stderr = client.exec_command('show security policies global | display xml')
    stdin, stdout, stderr = client.exec_command('show security policies hit-count ascending | display xml')
    output = stdout.read()

    fd = open('no_hit_policies.xml', 'w')
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


def get_policy_hit_info():
  
  policies_list = []
    
  xmldoc = etree.parse('no_hit_policies.xml')
  docroot = xmldoc.getroot()
  
        
#   for ele in docroot.iter('{*}policy-information'):
    # pol_dict = {'Index': '', 'From_zone': [], 'To_zone': [], 'Name': [], 'Policy_count': []}
    
   

        # print policies_list

  return xmldoc  


