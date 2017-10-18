#!/usr/bin/env python
__author__ = 'Tamara Tangney'
__email__ = 'tangney@northwestern.edu'

import netmiko
from lxml import etree
import sys


#  END of # Netmiko Device Login

xmldoc = etree.parse('junos-chassis.xml')
docroot = xmldoc.getroot()

def main():
      
  
# Iterate through and print out policies
  for ele in docroot.iter('{*}policy-information'):
   
    print("Policy: {}".format(ele.find('{*}policy-name').text))
   
    for sourceAddr in ele.iter('{*}source-address'):
    
      print("Source Address: {}".format(sourceAddr.find('{*}address-name').text))
    
    for destAddr in ele.iter('{*}destination-address'):
     
      print("Destination Address: {}".format(destAddr.find('{*}address-name').text))
    
    for app in ele.iter('{*}application'):
      # final_app_name = app.find('application-name').text
      # print final_app_name
      print("Application: {}".format(app.find('{*}application-name').text))
     
  
if __name__ == '__main__':
      main()
  # print '\n'
