#!/usr/bin/env python

__author__ = 'Tamara Tangney'
__email__ = 'tangney@northwestern.edu'

import netmiko
from lxml import etree
import sys
from jnpr.junos.exception import ConnectError
from jnpr.junos.exception import CommitError


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
try:
  device_conn = SSHClass(**juniper_ex2200)
except ConnectError as err:
  print ("Cannot connect to device: {0}".format(err))

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
    policy_name = ele.find('policy-name').text
    print policy_name
    # Policies.policy_name = policy_name
    # Policies.save(update_fields=["policy_name"])
  # print("Policy: {}".format(ele.find('{*}policy-name').text))
  
    for sourceAddr in ele.iter('{*}source-address'):
      source_address = sourceAddr.find('address-name').text
      print source_address
    # print("{}".format(sourceAddr.find('{*}address-name').text))
  
    for destAddr in ele.iter('{*}destination-address'):
      dest_address = destAddr.find('address-name').text
      print dest_address
    # print("{}".format(destAddr.find('{*}address-name').text))
    # new_policy.Destination_Address = destAddr.find('{*}address-name').text

    for app in ele.iter('{*}application'):
      # print("{}".format(app.find('{*}application-name').text))
      app_name = app.find('application-name').text
      print app_name
    # new_policy.Application = app.find('{*}application-name').text
    # policies = PolicyObject(policy_name, source_address, dest_address, app_name) 

  # return policies
  
if __name__ == '__main__':
      main()
  # print '\n'
