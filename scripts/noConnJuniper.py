#!/usr/bin/env python
__author__ = 'Tamara Tangney'
__email__ = 'tangney@northwestern.edu'

import netmiko
from lxml import etree
import sys



      
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
  
  
    
  # print '\n'
