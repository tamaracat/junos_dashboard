from jnpr.junos import Device
from jnpr.junos.factory.factory_loader import FactoryLoader
from jnpr.junos.exception import ConnectError
from jnpr.junos.exception import LockError
from jnpr.junos.exception import UnlockError
from jnpr.junos.exception import ConfigLoadError
from jnpr.junos.exception import CommitError
import ipaddress, yaml, json, csv, os, socket, sys
from socket import gethostbyname, gaierror
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
      
    policies_list_object = {'Policy': '', 'Source': [], 'Source_IP': '', 'Dest': [], 'Dest_IP': '', 'Port': [], 'Action': '', 'Defined_As': [],'DstDefined_As': '','Address_Set': [],'Dst_Address_Set': []}
    sourceLogic = False
    destLogic = False
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
  
  junos_config_path = 'junos-config_' + hostname + '.xml'
  list_obj = host_object()
  policies_list = []
  list_of_objects = []
  list_of_dst_objects = []
  dest_bool=True
  source_bool=False

  if(source_entered != '' and dest_entered != ''):
    source = determine_and_format_ip( source_entered ) 
    dest = determine_and_format_ip( dest_entered )   

  if( isinstance(source, str )): 
      list_of_objects = process_address_objects(junos_config_path, source, list_obj, source_bool)
  else:
      exit()
  if( isinstance(dest, str )):
      list_of_dst_objects = process_address_objects(junos_config_path, dest, list_obj, dest_bool)
  else:
      exit()

  policies_vrs = GlobalPoliciesMatch(path=junos_config_path)
  policies = policies_vrs.get() 
     
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
          # print ("Source match: {}").format(addr_obj)
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
                load_values_in_list_obj_instance(item, list_obj)
            if(src_match and dst_match):
              policies_list.append(list_obj.policies_list_object.copy())

  del list_obj   
  return policies_list 

def determine_and_format_ip( host ):
      
  try:
      ipv4host = ipaddress.ip_interface(unicode(host))
      print ipv4host
      network = ipv4host.network
      print network   
  except ValueError:
      print 'address/netmask is invalid for IPv4: {} ...processing as FQDN'.format(host)
      ipv4host = ''
    
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

  if not list_of_objects:       
    print 'No Address Set Found'
  elif list_of_objects:
    print ('Address SET Objects : {}').format( list_of_objects )

  return list_of_objects

def process_object(object_entered):
  
  try:
    host = socket.gethostbyname(object_entered)
  except socket.gaierror as e:
    print e   
  except socket.error as e:
    print e    
  except:
    print "Unexpected error:", sys.exc_info()[0]
    raise
  else:
    return host

def process_address_objects(junos_config_path, host, list_obj, dest):
  
  list_of_address_objects = []
  list_of_set_objects = []
  list_of_objects = []

  list_of_address_objects = process_ip_address(junos_config_path, host)
  if list_of_address_objects: 
    if dest:      
      list_obj.policies_list_object['DstDefined_As'] = list_of_address_objects
      list_of_set_objects = process_ip_address_object(junos_config_path, list_of_address_objects)
    else:
      list_obj.policies_list_object['Defined_As'] = list_of_address_objects
      list_of_set_objects = process_ip_address_object(junos_config_path, list_of_address_objects)
    if list_of_set_objects:
      print'list_of_set_objects is {}'.format(list_of_set_objects)
      if dest:
        list_obj.policies_list_object['Dst_Address_Set'] = list_of_set_objects
        list_of_objects = list_of_address_objects + list_of_set_objects
      else:
        list_obj.policies_list_object['Address_Set'] = list_of_set_objects
        list_of_objects = list_of_address_objects + list_of_set_objects
    else:
      list_of_objects = list_of_address_objects
      list_obj.policies_list_object['Address_Set'] = ''
  
  return list_of_objects

def load_values_in_list_obj_instance(item, list_obj):
      
  list_obj.policies_list_object['Source'] = item.match_src
  list_obj.policies_list_object['Src_Zone'] = 'global'
  list_obj.policies_list_object['Dst_Zone'] = 'global'
  list_obj.policies_list_object['Dest'] = item.match_dst
  list_obj.policies_list_object["Port"] = item.match_app
  list_obj.policies_list_object['Action'] = item.action 
  list_obj.policies_list_object['Policy'] = item.name 

def process_source(junos_config_path, list_obj, source_entered):

  source_bool=False
  dest_bool=True

  source = determine_and_format_ip( source_entered )  
  if source != '': 
      list_of_objects = process_address_objects(junos_config_path, source, list_obj, source_bool)
      list_obj.policies_list_object['Source_IP'] = source
      list_obj.sourceLogic = True
  else:
    host = process_object( source_entered )
    if host:
      source = determine_and_format_ip( host )  
      if source != '': 
          list_of_objects = process_address_objects(junos_config_path, source, list_obj, source_bool) 
          list_obj.policies_list_object['Source_IP'] = source
          list_obj.sourceLogic = True
      else:
          print 'Host {} not valid'.format( source )
    else:
        print 'Host {} not valid'.format( source )

  return list_of_objects

def process_dest(junos_config_path, list_obj, dest_entered):

  source_bool=False
  dest_bool=True

  dest = determine_and_format_ip( dest_entered )
  if dest != '':
      list_of_objects = process_address_objects(junos_config_path, dest, list_obj, dest_bool)
      list_obj.policies_list_object['Dest_IP'] = dest
      list_obj.destLogic = True
  else:
    host = process_object( dest_entered )   
    if host:
      dest = determine_and_format_ip( host )    
      if dest != '':
          try:
            list_of_objects = process_address_objects(junos_config_path, dest, list_obj, dest_bool)
          except: 
            print 'No List of Objects Returned'
            return
          list_obj.policies_list_object['Dest_IP'] = dest
          list_obj.destLogic = True        
      else:
        print 'Host {} not valid'.format( dest )
        return
    else:
      print 'Host {} not valid'.format( dest )
      return

  return list_of_objects

def get_host_to_all_info(hostname, source_entered, dest_entered):
      
  junos_config_path = 'junos-config_' + hostname + '.xml'
  policies_vrs = GlobalPoliciesMatch(path=junos_config_path)
  policies = policies_vrs.get() 

  list_obj = host_object()
  policies_list = []   
  sourceLogic = False
  destLogic = False
  list_of_objects = []
  
  if( dest_entered == ''):
    list_of_objects = process_source(junos_config_path, list_obj, source_entered)
  elif(source_entered == ''):  
    list_of_objects = process_dest(junos_config_path, list_obj, dest_entered)

  for addr_obj in list_of_objects:
    for item in policies:
      if list_obj.sourceLogic == True:
        src_match=False     
        if isinstance(item.match_src, str):
          my_list = [item.match_src]
        else: 
          my_list = item.match_src
        for src in my_list:
          if (addr_obj == src):
            src_match = True
            load_values_in_list_obj_instance(item, list_obj)
        if(src_match):
          policies_list.append(list_obj.policies_list_object.copy())
          
      elif list_obj.destLogic == True:
        match = False
        if isinstance(item.match_dst, str):
          my_list = [item.match_dst]
        else: 
          my_list = item.match_dst
        for dst in my_list:
          if (addr_obj == dst):
            match = True
            load_values_in_list_obj_instance(item, list_obj)
        if(match):
          policies_list.append(list_obj.policies_list_object.copy()) 
   
  del list_obj
  return policies_list 

def get_policy_info(hostname, policy_name):
 
  junos_config_path = 'junos-config_' + hostname + '.xml'

  list_obj = host_object()
  
  policies_list = []    

  policies_vrs = GlobalPoliciesMatch(path=junos_config_path)
  policies = policies_vrs.get() 
  
  for item in policies:
    name_match=False     
    if isinstance(item.name, str):   
      if (policy_name == item.name):
        print ("Policy Name is: {}").format(item.name) 
        name_match = True
        load_values_in_list_obj_instance(item, list_obj)
      if(name_match):
        policies_list.append(list_obj.policies_list_object.copy())
  del list_obj       
  return policies_list 

def get_source_dest_app_policy_info(hostname, source_entered, dest_entered, app):
 
  junos_config_path = 'junos-config_' + hostname + '.xml'

  list_obj = host_object()

  policies_list = []
  list_of_objects = []
  list_of_dst_objects = []

  policies_vrs = GlobalPoliciesMatch(path=junos_config_path)
  policies = policies_vrs.get() 
  
  if(source_entered != '' and dest_entered != ''):
    list_of_objects = process_source(junos_config_path, list_obj, source_entered)
    list_of_dst_objects = process_dest(junos_config_path, list_obj, dest_entered)
  elif(source_entered == '' and dest_entered != ''): 
    list_of_dst_objects = process_dest(junos_config_path, list_obj, dest_entered)
  elif(source_entered != '' and dest_entered == ''):
    list_of_objects = process_source(junos_config_path, list_obj, source_entered)

  if list_of_objects:    
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
            # print ("Source match: {}").format(addr_obj)
            #check to see if destination object is in policy
            if list_of_dst_objects:
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
                        load_values_in_list_obj_instance(item, list_obj)
                        print ("Port match: {}").format(match_port)
                    if(src_match and dst_match and port_match_bool):
                      policies_list.append(list_obj.policies_list_object.copy())
            else:
              if isinstance(item.match_app, str):
                 my_port_list = [item.match_app]
              else:
                my_port_list = item.match_app
                for match_port in my_port_list:
                  port_match_bool=False
                  if( app == match_port ):
                    port_match_bool = True
                    load_values_in_list_obj_instance(item, list_obj)
                    print ("Port match: {}").format(match_port)
                if(src_match and port_match_bool):
                  policies_list.append(list_obj.policies_list_object.copy())

  elif list_of_dst_objects:
      
    for dst_addr_obj in list_of_dst_objects: 
      for item in policies:
        if process_and_load_dest_objects(item, list_obj, dst_addr_obj, app):
          policies_list.append(list_obj.policies_list_object.copy())

  del list_obj  
  return policies_list 

def process_and_load_dest_objects(item, list_obj, dst_addr_obj, app):
  
  if isinstance(item.match_dst, str):
    my_dst_list = [item.match_dst]    
  else: 
    my_dst_list = item.match_dst
    for dst in my_dst_list:
      dst_match = False
      if (dst_addr_obj == dst): 
        print 'found a match for: {}'.format(dst_addr_obj)
        dst_match = True
        if isinstance(item.match_app, str):
          my_port_list = [item.match_app]
        else:
          my_port_list = item.match_app           
          for match_port in my_port_list:
            port_match_bool=False
            print app
            print match_port
            if( app == match_port ):  
              print 'found match for {}'.format( app)
              port_match_bool = True
              load_values_in_list_obj_instance(item, list_obj)
              print ("Port match: {}").format(match_port)
            if(dst_match and port_match_bool):
              return True
  return False

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

