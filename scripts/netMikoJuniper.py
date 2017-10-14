#!/usr/bin/env python

__author__ = 'Tamara Tangney'
__email__ = 'tangney@northwestern.edu'

import netmiko
import logging
from lxml import etree

logging.basicConfig(level=logging.NOTSET)

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
output = device_conn.send_command('show chassis hardware | display xml')
PolOutput = device_conn.send_command('show security policies global | display xml')


fd = open('junos-chassis.xml', 'w')
# fd.write(output.strip())
fd.write(PolOutput.strip())
# print output
fd.close()

#  END of # Netmiko Device Login

xmldoc = etree.parse('junos-chassis.xml')
docroot = xmldoc.getroot()

rootchildren = docroot.iter()
for child in rootchildren:
    print("Tag: {}, Text: {}".format(child.tag, child.text))

# Code to parse Junos
# for ele in docroot.iter('{*}policies'):
    # print ele
    # print("Policy: {}".format(ele.find('{*}policy-information').text))

# Iterate through and print out policies
for ele in docroot.iter('{*}policy-information'):
    print("Policy: {}".format(ele.find('{*}policy-name').text))
    

    for ele in docroot.iter('{*}source-addresses'):
        for ele in docroot.iter('{*}source-address'):
          print("Source Address: {}".format(ele.find('{*}address-name').text))

    print '\n'


     
    
    

    


    
