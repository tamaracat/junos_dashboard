from jnpr.junos import Device
from jnpr.junos.factory.factory_loader import FactoryLoader
from jnpr.junos.exception import ConnectError
from jnpr.junos.exception import LockError
from jnpr.junos.exception import UnlockError
from jnpr.junos.exception import ConfigLoadError
from jnpr.junos.exception import CommitError
import yaml
import json
from pprint import pprint
from lxml import etree
from jnpr.junos.factory import loadyaml
from os.path import splitext
from jnpr.junos.utils.config import Config
from jnpr.junos.op.arp import ArpTable

myYAML = """
---
UserTable:
  get: system/login/user
  view: UserView
UserView:
  fields:
    username: name
    userclass: class
### ---------------------------------------------------------------------------
### SRX zone-to-zone security policy
### ---------------------------------------------------------------------------

PolicyContextTable:
  get: security/policies/policy
  key:
    - from-zone-name
    - to-zone-name  
  view: policyContextView

policyContextView:
  fields:
    from_zone: from-zone-name
    to_zone: to-zone-name

### ---------------------------------------------------------------------------
### SRX zone-to-zone security policy rules
### ---------------------------------------------------------------------------

PolicyRuleTableOrig:
  get: security/policies/policy/policy 
  required_keys:
    policy:
      - from-zone-name
      - to-zone-name
  view: policyRuleViewOrig

policyRuleViewOrig:
  groups:
    match: match
    then: then
  fields_match:
    match_src: source-address
    match_dst: destination-address
    match_app: application
  fields_then:
    log_init : { log/session-init: flag }
    action : deny | permit 

### ---------------------------------------------------------------------------
### SRX zone-to-zone security policy rules
### ---------------------------------------------------------------------------

PolicyRuleTable:
  get: security/policies/policy 
  policy_name: '[afgx]e*' 
  view: policyRuleView

policyRuleView:
  groups:
    match: match
    then: then
  fields_match:
    match_src: source-address
    match_dst: destination-address
    match_app: application
  fields_then:
    log_init : { log/session-init: flag }
    action : deny | permit 
 

### ---------------------------------------------------------------------------
### SRX global address set
### ---------------------------------------------------------------------------

GlobalAddressBook:
  get: security/address-book/global
  interface_name: '[afgx]e*'
  view: GlobalAddressView
GlobalAddressView:
  fields:
    address: address

### ---------------------------------------------------------------------------
### SRX global policies match
### ---------------------------------------------------------------------------

GlobalPoliciesMatch:
  get: security/policies/global/policy
  policy_name: '[afgx]e*'
  view: GlobalAddressViewMatch
GlobalAddressViewMatch:
  groups:
    match: match
    then: then
  fields_match:
    match_src: source-address
    match_dst: destination-address
    match_app: application
  fields_then:
    log_init : { log/session-init: flag }
    action : deny | permit  


### ---------------------------------------------------------------------------
### SRX Ethernet EthPortTable
### ---------------------------------------------------------------------------

EthPortTable:
  rpc: get-interface-information
  args:
    media: True
    interface_name: '[afgx]e*'
  args_key: interface_name
  item: physical-interface
  view: EthPortView

EthPortView:
  groups:
    mac_stats: ethernet-mac-statistics
    flags: if-device-flags
  fields:
    oper: oper-status
    admin: admin-status
    description: description
    mtu: { mtu : int }
    link_mode: link-mode
    macaddr: current-physical-address
  fields_mac_stats:
    rx_bytes: input-bytes
    rx_packets: input-packets
    tx_bytes: output-bytes
    tx_packets: output-packets
  fields_flags:
    running: { ifdf-running: flag }
    present: { ifdf-present: flag }

### ---------------------------------------------------------------------------
### ARP Table
### ---------------------------------------------------------------------------

ArpTable:
  rpc: get-arp-table-information
  item: arp-table-entry
  key: mac-address
  view: ArpView
ArpView:
  fields:
    mac_address: mac-address
    ip_address: ip-address
    interface_name: interface-name
    host: hostname

"""
table_options = {'inherit':'inherit', 'groups':'groups', 'database':'committed'}

globals().update(FactoryLoader().load(yaml.load(myYAML)))

def get_zone_host_info(a_device, source):
  
  allPolicies = PolicyContextTable(a_device).get()
  for item in allPolicies:
    print item.from_zone
    print item.to_zone
  policies = PolicyRuleTableOrig(a_device).get(policy=['trust','Untrust'])
  
  print policies
  policies_list = []
  i=0
       
  for item in policies:
    src_match=False
    
    i=i+1
    pol_dict = {'Policy': '', 'Source': [], 'Dest': [], 'Port': [], 'Action': []}
    
    if(source == item.match_src ):
        src_match = True
        pol_dict['Source'].append(item.match_src)
        print("Source Address: {}".format(item.match_src))
  
        pol_dict['Dest'].append(item.match_dst)
        # print("Destination Address: {}".format(item.match_dst))
    
        pol_dict["Port"].append(item.match_app)
        # print("Service: {}".format(item.match_app))

        pol_dict['Action'] = item.action 
        # print("Action: {}".format(item.action))
    
        pol_dict['Policy'] = item.name 
        # print("Policy: {}".format(item.name))

    if(src_match):
      policies_list.append(pol_dict)
     
      
  return policies_list 

def get_host_info(a_device, source, dest, port):
    
  policies = GlobalPoliciesMatch(a_device).get(options=table_options)
 
 
  policies_list = []
  i=0

  for item in policies:
    print (item.name)
    print (item.match_src)
    print (item.match_dst)
    print (item.match_app)
    print (item.action) 
      
  for item in policies:
    src_match=False
    dest_match=False
    app_match=False
    i=i+1
    pol_dict = {'Policy': '', 'Source': [], 'Dest': [], 'Port': [], 'Action': []}
        
    if(source == item.match_src ):
        src_match = True
        pol_dict['Source'].append(item.match_src)
        print("Source Address: {}".format(item.match_src))
    
    if(dest == item.match_dst):
        dest_match = True
        pol_dict['Dest'].append(item.match_dst)
        print("Destination Address: {}".format(item.match_dst))
    
    if(port == item.match_app):
        app_match = True
        pol_dict["Port"].append(item.match_app)
        print("Service: {}".format(item.match_app))

        pol_dict['Action'] = item.action 
        print("Action: {}".format(item.action))
    
        pol_dict['Policy'] = item.name 
        print("Policy: {}".format(item.name))

    if(src_match & dest_match & app_match):
      policies_list.append(pol_dict)
      print i

  
  return policies_list    

def get_host_access_info(a_device, source):

  policies = GlobalPoliciesMatch(a_device).get(options=table_options) 

  policies_list = []
  i=0
       
  for item in policies:
    src_match=False
  
    i=i+1
    pol_dict = {'Policy': '', 'Source': [], 'Dest': [], 'Port': [], 'Action': []}
        
    if(source == item.match_src ):
        src_match = True
        pol_dict['Source'].append(item.match_src)
        # print("Source Address: {}".format(item.match_src))
  
        pol_dict['Dest'].append(item.match_dst)
        # print("Destination Address: {}".format(item.match_dst))
    
        pol_dict["Port"].append(item.match_app)
        # print("Service: {}".format(item.match_app))

        pol_dict['Action'] = item.action 
        # print("Action: {}".format(item.action))
    
        pol_dict['Policy'] = item.name 
        # print("Policy: {}".format(item.name))

    if(src_match):
      policies_list.append(pol_dict)
     
      
  return policies_list 

def get_policy_info(a_device, pol_name):
 
  policies = GlobalPoliciesMatch(a_device).get() 
  policies_list = []
  i=0
       
  for item in policies:
    print (item.name)
    print (item.match_src)
    print (item.match_dst)
    print (item.match_app)
    print (item.action) 
    src_match=False
  
    i=i+1
    pol_dict = {'Policy': '', 'Source': [], 'Dest': [], 'Port': [], 'Action': []}
        
    if(pol_name == item.name ):
        print pol_name
        print item.name
        src_match = True
        pol_dict['Policy']=item.name
        # print("Policy: {}".format(item.name))
      
        pol_dict['Source'] = item.match_src 
        # print("Source: {}".format(item.match_src))   
  
        pol_dict['Dest'].append(item.match_dst)
        # print("Destination Address: {}".format(item.match_dst))
    
        pol_dict["Port"].append(item.match_app)
        # print("Service: {}".format(item.match_app))

        pol_dict['Action'] = item.action 
        # print("Action: {}".format(item.action))
    
       
    if(src_match):
      policies_list.append(pol_dict)
      print i
      
  return policies_list   

def GetArpEntry():

  arps = ArpTable(a_device)
  arps.get()
  for arp in arps:  
        print 'mac_address: ', arp.mac_address
        print 'ip_address: ', arp.ip_address
        print 'interface_name:', arp.interface_name
        print 'hostname:', arp.host
        print

# JSON format
# data = a_device.rpc.get_config(options={'format':'json'})
# pprint (data)

    # Junos XML elements
# data = a_device.rpc.get_config(filter_xml='<system><services/></system>')
# print(etree.tostring(data, encoding='unicode'))
 
# users = UserTable(a_device)
# users.get()

# arp = ArpTable(a_device)
# arp.get()

# policies = GlobalPolicies(a_device)
# policies.get()

# output_json = json.loads(policies.to_json())
# print json.dumps(output_json, indent=4)

# print policies

# for account in users:
    # print("Username is {}\nUser class is {}".format(account.username, account.userclass))

# pprint(a_device.facts)

# output_json = json.loads(arp.to_json())
# print json.dumps(output_json, indent=4)

# rsp = a_device.rpc.get_interface_information(interface_name='ge-0/0/0.0', terse=True)
# pprint  (rsp.xpath(".// \
    # address-family[normalize-space(address-family-name)='inet']/ \
    # interface-address/ifa-local")[0].text)
def GetDeviceFacts(a_device):

  return a_device.facts      

def connect_to_firewall(hostname, username, password):

  a_device = Device(host=hostname, user=username, password=password, port='22')
  try:
    a_device.open(normalize=True)
  except ConnectError as err:
    print ("Cannot connect to device: {0}".format(err))
    return 0
  pprint( a_device.facts )

  return a_device

# def main():

# data = a_device.rpc.get_config(options={'database' : 'committed'})
# print(etree.tostring(data, encoding='unicode'))

  

    # Text format
# data = a_device.rpc.get_config(options={'format':'text'})
# print(etree.tostring(data))

    # Junos OS set format
# data = a_device.rpc.get_config(options={'format':'set'})
# print (etree.tostring(data))

# sp = a_device.rpc.get_global_firewall_policies(policy_name='1', dev_timeout=55)
# print sp

  # eths = EthPortTable(a_device).get()

  # for item in eths:
    # print (item.name)

  # dev = connect_to_firewall()

  # policies = get_host_info(dev, 'sorc_obj', 'dest_obj','ser_obj')
    
  # policies = get_host_access_info(dev, 'sorc_obj')

  # address = GlobalAddressBook(a_device).get()

  # for item in address:
    # print (item)
    
    
  # dev.close()

# if __name__ == "__main__":
 # main()

