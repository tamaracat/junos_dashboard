#!/usr/bin/env python
__author__ = 'Tamara Tangney'
__email__ = 'tangney@northwestern.edu'

import netmiko
from lxml import etree
import sys
# from ..policy_mgmnt/models import Firewall, Policies
# from policy_mgmnt import models
# sys.path.append('policy_mgmnt/models')
from policy_mgmnt.models import Policies

# logging.basicConfig(level=logging.NOTSET)


modnum = 0

# Netmiko Device Login
juniper_ex2200 = {
    'device_type': 'juniper',
    'ip': '165.124.17.133',
    'username': 'srxadmin',
    'password': 'l1b2bstssrx',
    'secret': '',
    'verbose': False,
}


SSHClass = netmiko.ssh_dispatcher(device_type=juniper_ex2200['device_type'])
device_conn = SSHClass(**juniper_ex2200)
# output = device_conn.send_command('show chassis hardware | display xml')
PolOutput = device_conn.send_command('show security policies global | display xml')


fd = open('junos-chassis.xml', 'w')
fd.write(PolOutput.strip())
# print PolOutput
fd.close()

#  END of # Netmiko Device Login

xmldoc = etree.parse('junos-chassis.xml')
docroot = xmldoc.getroot()

def main():

  class PolicyObject:
    def __init__(self, Policy, Source_Address, Destination_Address, Application):
      self.Policy = Policy,
      self.Source_Address = Source_Address,
      self.Destination_Address = Destination_Address,
      self.Application = Application
   
# Iterate through and print out policies
  for ele in docroot.iter('{*}policy-information'):
      print("Policy: {}".format(ele.find('{*}policy-name').text))

  for sourceAddr in ele.iter('{*}source-address'):
    print("Source Address: {}".format(sourceAddr.find('{*}address-name').text))


  for destAddr in ele.iter('{*}destination-address'):
    print("Destination Address: {}".format(destAddr.find('{*}address-name').text))
    # new_policy.Destination_Address = destAddr.find('{*}address-name').text

  for app in ele.iter('{*}application'):
    print("Application: {}".format(app.find('{*}application-name').text))
    # new_policy.Application = app.find('{*}application-name').text
    
  
if __name__ == '__main__':
      main()
  # print '\n'
