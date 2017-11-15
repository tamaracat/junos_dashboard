#!/usr/bin/env python

__author__ = 'Tamara Tangney'
__email__ = 'tangney@northwestern.edu'

from lxml import etree


# fd = open('junos-chassis.xml', 'r')
# fd.write(PolOutput.strip())
# print PolOutput
# fd.close()


xmldoc = etree.parse('junos-chassis.xml')
docroot = xmldoc.getroot()



for ele in docroot.iter('{*}policy-information'):
  
  print("Policy: {}".format(ele.find('policy-name').text))

  for sourceAddr in ele.iter('{*}source-address'):
    print("Source Address: {}".format(sourceAddr.find('{*}address-name').text))
    # src_address.append(sourceAddr.find('address-name').text)
    
  for destAddr in ele.iter('{*}destination-address'):
    print("Destination Address: {}".format(destAddr.find('{*}address-name').text))
    # dest_address.append(destAddr.find('address-name').text)

  for app in ele.iter('{*}application'):
    print("Application: {}".format(app.find('{*}application-name').text))
   
  # print '\n'
  
