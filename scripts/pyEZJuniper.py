from jnpr.junos import Device
from jnpr.junos.factory.factory_loader import FactoryLoader
from jnpr.junos.exception import ConnectError
from jnpr.junos.exception import LockError
from jnpr.junos.exception import UnlockError
from jnpr.junos.exception import ConfigLoadError
from jnpr.junos.exception import CommitError
import yaml, json, csv, os
from pprint import pprint
from lxml import etree
from jnpr.junos.factory import loadyaml
from os.path import splitext
from jnpr.junos.utils.config import Config
from jnpr.junos.op.arp import ArpTable
import jxmlease



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
### SRX device facts
### ---------------------------------------------------------------------------
DeviceFacts:
  rpc: get-software-information
  item: hostname
  view: DeviceFactsView
DeviceFactsView:
  fields:
    hostname: hostname

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
PolicyRuleTable:
  get: security/policies/policy/policy 
  required_keys:
    policy:
      - from-zone-name
      - to-zone-name
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
### SRX global address 
### ---------------------------------------------------------------------------
GlobalAddressBook:
  get: security/address-book/address
  view: GlobalAddressView
GlobalAddressView:
  
  fields:
    name: name
    address: ip-prefix

### ---------------------------------------------------------------------------
### SRX global address set
### ---------------------------------------------------------------------------
GlobalAddressSet:
  get: security/address-book/address-set
  key-field:
    address_name
  view: GlobalAddressSetView
GlobalAddressSetView:
  
  fields:
    set_name: name
    address: address/name

### ---------------------------------------------------------------------------
### SRX zone-to-zone security policy
### ---------------------------------------------------------------------------
SecurityPolicyTable:
  rpc: get-firewall-policies
  key:
    - from-zone-name
    - to-zone-name  
  view: SecurityPolicyContextView
SecurityPolicyContextView:
  groups:
    security_context: security-context
    match: match
    then: then
  fields_security_context:
    source_zone_name: source-zone-name
    to_zone_name: to-zone-name
  fields_match:
    match_src: source-address
    match_dst: destination-address
    match_app: application
  fields_then:
    log_init : { log/session-init: flag }
    action : deny | permit 

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



def get_device_configuration(hostname, a_device):

  conf_file = 'junos-config_' + hostname + '.xml'

  data = a_device.rpc.get_config(options={'database':'committed'})   
  fd = open(conf_file, 'w')
  fd.write(etree.tostring(data, encoding='unicode'))
  fd.close()


def get_host_to_all_info(hostname, source, dest):
      
  pol_dict = {'Policy': '', 'Source': [], 'Dest': [], 'Port': [], 'Action': [], 'Defined_As': '','Address_Set': []}
      
  policies_list = []   
  sourceLogic = False
  destLogic = False

  if( dest == 'all'):
    pol_dict['Source'] = source
    sourceLogic = True
    addressSetFind = source
  elif(source == 'all'):
    pol_dict['Dest'] = dest
    destLogic = True
    addressSetFind = dest

  list_of_objects = []

  junos_config_path = 'junos-config_' + hostname + '.xml'

  xmlparser = jxmlease.Parser()
  xml = open(junos_config_path).read()
  data = jxmlease.parse(xml)
  # print data

  policies_vrs = GlobalPoliciesMatch(path=junos_config_path)
  policies = policies_vrs.get() 

  zone_vrs = PolicyContextTable(path=junos_config_path)
  zone_context = zone_vrs.get() 

  xcvrs = GlobalAddressBook(path=junos_config_path)
  IP_Address = xcvrs.get() 

  address_vrs = GlobalAddressSet(path=junos_config_path)
   
  for item in IP_Address:
    
    if (item.address == addressSetFind):
      
      address_obj = item.name
      pol_dict['Defined_As'] = item.name
      list_of_objects.append(address_obj)

      address_vrs = GlobalAddressSet(path=junos_config_path)
      AddressSet = address_vrs.get()
      
      for item in AddressSet:    
        if(item.address):
          if(address_obj in item.address):
            print ('{} is in Address Set: {}').format(address_obj, item.set_name)
            address_set = item.set_name
            pol_dict['Address_Set'].append(address_set)
            list_of_objects.append(address_set)
      print list_of_objects
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
  
  for addr_obj in list_of_objects:
    for item in policies:
      if sourceLogic == True:
        src_match=False     
        if isinstance(item.match_src, str):
          if (addr_obj == item.match_src):
            src_match = True
            pol_dict['Source'] = item.match_src
            pol_dict['Src_Zone'] = 'global'
            pol_dict['Dst_Zone'] = 'global'
            pol_dict['Dest'] = item.match_dst
            pol_dict["Port"] = item.match_app  
            pol_dict['Action'] = item.action 
            pol_dict['Policy'] = item.name 
        else:
          for src in item.match_src:
            if (addr_obj == src):
              src_match = True
              pol_dict['Source'] = item.match_src
              pol_dict['Src_Zone'] = 'global'
              pol_dict['Dst_Zone'] = 'global'
              pol_dict['Dest'] = item.match_dst
              pol_dict["Port"] = item.match_app
              pol_dict['Action'] = item.action 
              pol_dict['Policy'] = item.name 
          if(src_match):
            policies_list.append(pol_dict.copy())

      if destLogic == True:
        match = False
        if isinstance(item.match_dst, str):
          if (addr_obj == item.match_dst):
            print('addr_obj {}').format(addr_obj)
            match = True
            pol_dict['Source'] = item.match_src
            pol_dict['Src_Zone'] = 'global'
            pol_dict['Dst_Zone'] = 'global'
            pol_dict['Dest'] = item.match_dst
            pol_dict["Port"] = item.match_app  
            pol_dict['Action'] = item.action 
            pol_dict['Policy'] = item.name 
        else:
          for dst in item.match_dst:
            if (addr_obj == dst):
              print('addr_obj list {}').format(addr_obj)
              match = True
              pol_dict['Source'] = item.match_src
              pol_dict['Src_Zone'] = 'global'
              pol_dict['Dst_Zone'] = 'global'
              pol_dict['Dest'] = item.match_dst
              pol_dict["Port"] = item.match_app
              pol_dict['Action'] = item.action 
              pol_dict['Policy'] = item.name 
          if(match):
            policies_list.append(pol_dict.copy())          
  return policies_list 

def get_policy_info(hostname, policy_name):
      
  pol_dict = {'Policy': '', 'Source': [], 'Dest': [], 'Port': [], 'Action': [], 'Defined_As': '','Address_Set': []}
      

  policies_list = []   
  
  list_of_objects = []

  junos_config_path = 'junos-config_' + hostname + '.xml'

  policies_vrs = GlobalPoliciesMatch(path=junos_config_path)
  policies = policies_vrs.get() 
  
  for item in policies:
    name_match=False     
    if isinstance(item.name, str):   
      if (policy_name == item.name):
        print ("Policy Name is: {}").format(item.name) 
        name_match = True
        pol_dict['Source'] = item.match_src
        pol_dict['Src_Zone'] = 'global'
        pol_dict['Dst_Zone'] = 'global'
        pol_dict['Dest'] = item.match_dst
        pol_dict["Port"] = item.match_app  
        pol_dict['Action'] = item.action 
        pol_dict['Policy'] = item.name 
      if(name_match):
        policies_list.append(pol_dict.copy())
        
  return policies_list 

def get_source_dest_app_policy_info(hostname, source_name, dest_name, app_name):
      

  policies_list = []   
  
  list_of_objects = []

  junos_config_path = 'junos-config_' + hostname + '.xml'

  policies_vrs = GlobalPoliciesMatch(path=junos_config_path)
  policies = policies_vrs.get() 
  
  for item in policies:
    match=False     
    if isinstance(item.match_src, str) and isinstance(item.match_dst, str) and not isinstance(item.match_app, str):   
      if (source_name == item.match_src and dest_name == item.match_dst):
        print ("Source is: {} Dest is: {} ").format(item.match_src, item.match_dst) 
        match = True
        pol_dict['Source'] = item.match_src
        pol_dict['Src_Zone'] = 'global'
        pol_dict['Dst_Zone'] = 'global'
        pol_dict['Dest'] = item.match_dst
        pol_dict["Port"] = item.match_app  
        pol_dict['Action'] = item.action 
        pol_dict['Policy'] = item.name 
      if(match):
        policies_list.append(pol_dict.copy())
        
  return policies_list 

def GetArpEntry():

  arps = ArpTable(a_device)
  arps.get()
  for arp in arps:  
        print 'mac_address: ', arp.mac_address
        print 'ip_address: ', arp.ip_address
        print 'interface_name:', arp.interface_name
        print 'hostname:', arp.host


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

