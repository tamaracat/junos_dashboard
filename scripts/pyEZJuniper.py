from jnpr.junos import Device
from jnpr.junos.factory.factory_loader import FactoryLoader
from jnpr.junos.exception import ConnectError
from jnpr.junos.exception import LockError
from jnpr.junos.exception import UnlockError
from jnpr.junos.exception import ConfigLoadError
from jnpr.junos.exception import CommitError
import ipaddress, yaml, json, csv, os
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
### SRX Application set
### ---------------------------------------------------------------------------
ApplicationSet:
  get: applications/application/term
  key-field:
    name
  view: ApplicationSetView
ApplicationSetView: 
  groups:
    match: match
    then: then
  fields_match:
    match_port: destination-port

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

class host_object:
      
    policies_list_object = {'Policy': '', 'Source': [], 'Dest': [], 'Port': [], 'Action': '', 'Defined_As': [],'Address_Set': []}

    def __init__(self):
      
        self.policies_list_object
      
    def __delete__(self, instance):
        print "deleted in descriptor object"
        del self.value

def find_obj_defn(hostname, address_entered):

  list_of_objects = []

  global_str = 'global'

  address_var = determine_and_format_ip( address_entered )

  junos_config_path = 'junos-config_' + str(hostname) + '.xml'

  xcvrs = GlobalAddressBook(path=junos_config_path)

  IP_Address = xcvrs.get() 

  for item in IP_Address:
   if( global_str in str(item)):    
    if (item.address == address_var):
      
      address_obj = item.name
      list_of_objects.append(address_obj)

  return list_of_objects

def create_address_object( host ):
      
  address_object = str(host) + '.ci.global'

  return address_object

def get_source_and_dest_info(hostname, source_entered, dest_entered):

  policies_list = []

  pol_dict = {'Policy': '', 'Source': [], 'Dest': [], 'Port': [], 'Action': [], 'Defined_As': '','DstDefined_As': '','Address_Set': [],'Dst_Address_Set': []}

  if(source_entered != '' and dest_entered != ''):
    source = determine_and_format_ip( source_entered ) 
    dest = determine_and_format_ip( dest_entered )   
    pol_dict['Source'] = source
    pol_dict['Dest'] = dest
    addressSetFind = source
    addressSetFindDest = dest

  list_of_objects = []
  list_of_dst_objects = []

  junos_config_path = 'junos-config_' + hostname + '.xml'


  policies_vrs = GlobalPoliciesMatch(path=junos_config_path)
  policies = policies_vrs.get() 

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

  for item in IP_Address:
    
    if (item.address == addressSetFindDest):  
      dst_address_obj = item.name
      pol_dict['DstDefined_As'] = item.name
      list_of_dst_objects.append(dst_address_obj)

      address_vrs = GlobalAddressSet(path=junos_config_path)
      AddressSet = address_vrs.get()
      
      for item in AddressSet:    
        if(item.address):
          if(dst_address_obj in item.address):
            print ('{} is in Address Set: {}').format(dst_address_obj, item.set_name)
            address_set = item.set_name
            pol_dict['Dst_Address_Set'].append(address_set)
            list_of_dst_objects.append(address_set)
        
        
  for addr_obj in list_of_objects:
    for item in policies:
      src_match=False     
      if isinstance(item.match_src, str):
        my_list = [item.match_src]
      else: 
        my_list = item.match_src
      for src in my_list:
        if (addr_obj == src):
          src_match = True
          print ("Source match: {}").format(addr_obj)
          #check to see if destination ojject is in policy
          for dst_addr_obj in list_of_dst_objects:
            dst_match=False
            if isinstance(item.match_dst, str):
              my_dst_list = [item.match_dst]
            else: 
              my_dst_list = item.match_dst
            for dst in my_dst_list:
              if (dst_addr_obj == dst): 
                dst_match = True
                print ("Dest match: {}").format(dst_addr_obj)
                pol_dict['Source'] = item.match_src
                pol_dict['Src_Zone'] = 'global'
                pol_dict['Dst_Zone'] = 'global'
                pol_dict['Dest'] = item.match_dst
                pol_dict["Port"] = item.match_app
                pol_dict['Action'] = item.action 
                pol_dict['Policy'] = item.name 
            if(src_match and dst_match):
              policies_list.append(pol_dict.copy())
      
  return policies_list 

def determine_and_format_ip( host ):
      
  list_obj = host_object()

  print list_obj.policies_list_object
  try:
      ipv4host = ipaddress.ip_interface(unicode(host))
      print ipv4host
      network = ipv4host.network
      print network   
  except ValueError:
      print 'address/netmask is invalid for IPv4: {} ...exiting'.format(host)
      return 'object'

  return str(ipv4host)

def process_ip_address(junos_config_path, addressSetFind):
       
  list_of_address_objects = []

  xcvrs = GlobalAddressBook(path=junos_config_path)
  IP_Address = xcvrs.get() 

  print ('Processing address {}').format(addressSetFind)
      
  for item in IP_Address: 
    if (item.address == addressSetFind):    
      address_obj = item.name
      print ('{} is Defined as: {}').format(address_obj, item.name)
      list_of_address_objects.append(address_obj)
 
  print ('Address Objects : {}').format( list_of_address_objects )
  return list_of_address_objects

def process_ip_address_object(junos_config_path, list_of_address_objects): 
  
  list_of_objects = []

  address_vrs = GlobalAddressSet(path=junos_config_path)
  AddressSet = address_vrs.get()

  for item in AddressSet:       
    if(item.address):
      for obj in list_of_address_objects:
        if(obj in item.address):
          print ('{} is in Address Set: {}').format(obj, item.set_name)
          address_set = item.set_name
          list_of_objects.append(address_set)

  if list_of_objects == '':       
    print 'No Address Set Found'
  elif list_of_objects != '':
    print ('Address SET Objects : {}').format( list_of_objects )

  return list_of_objects

def process_object(object_entered, list_of_objects, pol_dict):

  try:
    import dns.resolver
    import dns.reversename
    from dns.exception import DNSException
    HAVE_DNS=True
  except ImportError:
    pass

  address_vrs = GlobalAddressSet(path=junos_config_path)
  AddressSet = address_vrs.get()

  pol_dict['Defined_As'] = address_obj
      
  for item in AddressSet:    
    if(item.address):
      if(address_obj in item.address):
        print ('{} is in Address Set: {}').format(address_obj, item.set_name)
        address_set = item.set_name
        pol_dict['Address_Set'].append(address_set)
        list_of_objects.append(address_set)

  return list_of_objects

def process_address_objects():

  list_of_address_objects = process_ip_address(junos_config_path, source)
  if list_of_address_objects:
    list_obj.policies_list_object['Defined_As'] = list_of_address_objects
    list_of_set_objects = process_ip_address_object(junos_config_path, list_of_address_objects)
        
    if list_of_set_objects:
      list_obj.policies_list_object['Address_Set'] = list_of_set_objects
      list_of_objects = list_of_address_objects + list_of_set_objects

def get_host_to_all_info(hostname, source_entered, dest_entered):
      
  junos_config_path = 'junos-config_' + hostname + '.xml'

  list_obj = host_object()
  policies_list = []   
  sourceLogic = False
  destLogic = False
  list_of_objects = []
  if( dest_entered == ''): 
    source = determine_and_format_ip( source_entered )  
    if( isinstance(source, str )): 
      list_of_address_objects = process_ip_address(junos_config_path, source)
      if list_of_address_objects:
        list_obj.policies_list_object['Defined_As'] = list_of_address_objects
        list_of_set_objects = process_ip_address_object(junos_config_path, list_of_address_objects)
        
        if list_of_set_objects:
          list_obj.policies_list_object['Address_Set'] = list_of_set_objects
          list_of_objects = list_of_address_objects + list_of_set_objects
        else:
          list_of_objects = list_of_address_objects
          list_obj.policies_list_object['Address_Set'] = ''
      sourceLogic = True
    else:
      exit()
  elif(source_entered == ''):
    dest = determine_and_format_ip( dest_entered )
    if( isinstance(dest, str )):
      list_of_address_objects = process_ip_address(junos_config_path, dest)
      if list_of_address_objects:
        list_obj.policies_list_object['Defined_As'] = list_of_address_objects
        list_of_set_objects = process_ip_address_object(junos_config_path, list_of_address_objects)
        if list_of_set_objects:
          list_obj.policies_list_object['Address_Set'] = list_of_set_objects
          list_of_objects = list_of_address_objects + list_of_set_objects   
        else:
          list_of_objects = list_of_address_objects 
          list_obj.policies_list_object['Address_Set'] = ''
      destLogic = True
    else:
      exit()
  
  policies_vrs = GlobalPoliciesMatch(path=junos_config_path)
  policies = policies_vrs.get() 
       
  for addr_obj in list_of_objects:
    for item in policies:
      if sourceLogic == True:
        src_match=False     
        if isinstance(item.match_src, str):
          my_list = [item.match_src]
        else: 
          my_list = item.match_src
        for src in my_list:
          if (addr_obj == src):
            print addr_obj
            src_match = True
            list_obj.policies_list_object['Source'] = item.match_src
            list_obj.policies_list_object['Src_Zone'] = 'global'
            list_obj.policies_list_object['Dst_Zone'] = 'global'
            list_obj.policies_list_object['Dest'] = item.match_dst
            list_obj.policies_list_object["Port"] = item.match_app
            list_obj.policies_list_object['Action'] = item.action 
            list_obj.policies_list_object['Policy'] = item.name 
        if(src_match):
          policies_list.append(list_obj.policies_list_object.copy())
          
      elif destLogic == True:
        match = False
        if isinstance(item.match_dst, str):
          my_list = [item.match_dst]
        else: 
          my_list = item.match_dst
        for dst in my_list:
          if (addr_obj == dst):
            match = True
            list_obj.policies_list_object['Source'] = item.match_src
            list_obj.policies_list_object['Src_Zone'] = 'global'
            list_obj.policies_list_object['Dst_Zone'] = 'global'
            list_obj.policies_list_object['Dest'] = item.match_dst
            list_obj.policies_list_object["Port"] = item.match_app
            list_obj.policies_list_object['Action'] = item.action 
            list_obj.policies_list_object['Policy'] = item.name 
        if(match):
          policies_list.append(list_obj.policies_list_object.copy()) 

  # print list_obj.policies_list_object   
  del list_obj
  return policies_list 

def get_policy_info(hostname, policy_name):
      
  pol_dict = {'Policy': '', 'Source': [], 'Dest': [], 'Port': [], 'Action': '', 'Defined_As': '','Address_Set': []}
      

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

def get_source_dest_app_policy_info(hostname, source_entered, dest_entered, app):
 
  policies_list = []

  pol_dict = {'Policy': '', 'Source': [], 'Dest': [], 'Port': [], 'Action': [], 'Defined_As': '','DstDefined_As': '','Address_Set': [],'Dst_Address_Set': []}

  if(source_entered != '' and dest_entered != ''):
    source = determine_and_format_ip( source_entered ) 
    dest = determine_and_format_ip( dest_entered )  
    pol_dict['Source'] = source
    pol_dict['Dest'] = dest
    addressSetFind = source
    addressSetFindDest = dest

  list_of_objects = []
  list_of_dst_objects = []

  junos_config_path = 'junos-config_' + hostname + '.xml'


  policies_vrs = GlobalPoliciesMatch(path=junos_config_path)
  policies = policies_vrs.get() 

  xcvrs = GlobalAddressBook(path=junos_config_path)
  IP_Address = xcvrs.get() 

  address_vrs = GlobalAddressSet(path=junos_config_path)
  AddressSet = address_vrs.get()

  for item in IP_Address:
    
    if (item.address == addressSetFind):  
      address_obj = item.name
      pol_dict['Defined_As'] = item.name
      list_of_objects.append(address_obj)
      
      for item in AddressSet:    
        if(item.address):
          if(address_obj in item.address):
            print ('{} is in Address Set: {}').format(address_obj, item.set_name)
            address_set = item.set_name
            pol_dict['Address_Set'].append(address_set)
            list_of_objects.append(address_set)
      print list_of_objects

  for item in IP_Address:
    
    if (item.address == addressSetFindDest):  
      dst_address_obj = item.name
      pol_dict['DstDefined_As'] = item.name
      list_of_dst_objects.append(dst_address_obj)
      
      for item in AddressSet:    
        if(item.address):
          if(dst_address_obj in item.address):
            print ('{} is in Address Set: {}').format(dst_address_obj, item.set_name)
            address_set = item.set_name
            pol_dict['Dst_Address_Set'].append(address_set)
            list_of_dst_objects.append(address_set)
      # print list_of_dst_objects
        
        
  for addr_obj in list_of_objects:
    for item in policies:       
      if isinstance(item.match_src, str):
        my_list = [item.match_src]
      else: 
        my_list = item.match_src
      for src in my_list:
        src_match=False
        if (addr_obj == src):
          src_match = True
          print ("Source match: {}").format(addr_obj)
          #check to see if destination ojject is in policy
          for dst_addr_obj in list_of_dst_objects: 
            if isinstance(item.match_dst, str):
              my_dst_list = [item.match_dst]
            else: 
              my_dst_list = item.match_dst
            for dst in my_dst_list:
              dst_match = False
              if (dst_addr_obj == dst): 
                dst_match = True
                if isinstance(item.match_app, str):
                  my_port_list = [item.match_app]
                else:
                  my_port_list = item.match_app
                for match_port in my_port_list:
                  port_match_bool=False
                  if( app == match_port ):
                    port_match_bool = True
                    print ("Port match: {}").format(match_port)
                    pol_dict['Source'] = item.match_src
                    pol_dict['Src_Zone'] = 'global'
                    pol_dict['Dst_Zone'] = 'global'
                    pol_dict['Dest'] = item.match_dst
                    pol_dict["Port"] = item.match_app 
                    pol_dict['Action'] = item.action 
                    pol_dict['Policy'] = item.name 
                if(src_match and dst_match and port_match_bool):
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

