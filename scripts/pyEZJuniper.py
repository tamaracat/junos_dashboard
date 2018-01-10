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
### SRX global address SRX
### ---------------------------------------------------------------------------
GlobalAddressBookSRX:
  get: security/address-book
  view: GlobalAddressViewSRX
GlobalAddressViewSRX:  
  fields:
    address: address
### ---------------------------------------------------------------------------
### SRX zone address book item table
### ---------------------------------------------------------------------------
Zone_itemTable:
  get: security/zones/security-zone/address-book/address
  required_keys:
    security_zone: name
  view: Zone_itemView
Zone_itemView:
  fields:
    ip_prefix: ip-prefix
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
### SRX global address set
### ---------------------------------------------------------------------------
GlobalAddressSetAll:
  get: security/address-book/address-set
  view: GlobalAddressSetViewAll
GlobalAddressSetViewAll:
  fields:
    set_name: name
    address: address/name
### ---------------------------------------------------------------------------
### SRX global address Zone
### ---------------------------------------------------------------------------
AddressSetZone:
  get: security/address-book
  
  view: AddressSetZoneView
AddressSetZoneView:
  
  fields:
    name: name
    address_name: address/name
    ip_prefix: address/ip-prefix
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

def get_host_to_all_info(hostname, a_device, source):
  data = a_device.rpc.get_config()
  # print(etree.tostring(data, encoding='unicode'))

  fd = open('junos-config.xml', 'w')
    # fd.write(output.strip())
  fd.write(etree.tostring(data, encoding='unicode'))
    # print output
  fd.close()
  
  xmldoc = etree.parse('junos-config.xml')
  docroot = xmldoc.getroot()

  policies_list = []   
  pol_dict = {'Src_Zone': '', 'Dst_Zone': '', 'Policy': '', 'Source': [], 'Dest': [], 'Port': [], 'Action': [], 'Source_IP': '', 'Defined_As': '', 'Defined_As': '', 'Address_Set': []}
  pol_dict['Source_IP'] = source
  # Global_VS_Zone = AddressSetZone(a_device).get()
  # for item in Global_VS_Zone:
    # print ("Address Zone: {} Address Name: {} IP Prefix: {}").format(item.name, item.address_name, item.ip_prefix)
  list_of_objects = []

  # IP_Address = GlobalAddressBook(a_device).get()
  # print IP_Address
  # IP_Address.savexml(path='AddressConfig.xml', hostname=True, timestamp=True)
  # IP_Address.savexml(path='AddressConfig.xml', hostname=True)
  
  # AddressSet = GlobalAddressSet(a_device).get()
  # AddressSet.savexml(path='AddressSetConfig.xml', hostname=True)

  # zone_context = PolicyContextTable(a_device).get()
  # zone_context.savexml(path='ZoneContextConfig.xml', hostname=True)

  # policies = GlobalPoliciesMatch(a_device).get(options=table_options)
  # policies.savexml(path='PoliciesConfig.xml', hostname=True)
  
  


  policies_path = 'PoliciesConfig_165.124.8.5.xml'
  policies_vrs = GlobalPoliciesMatch(path=policies_path)
  policies = policies_vrs.get() 

  zone_context_path = 'ZoneContextConfig_165.124.8.5.xml'
  zone_vrs = PolicyContextTable(path=zone_context_path)
  zone_context = zone_vrs.get() 

  global_address_path = 'AddressConfig_165.124.8.5.xml'
  xcvrs = GlobalAddressBook(path=global_address_path)
  IP_Address = xcvrs.get() 

  addr_set_path = 'AddressSetConfig_165.124.8.5.xml'
  address_vrs = GlobalAddressSet(path=addr_set_path)

  for item in zone_context:     
    zone_policies = PolicyRuleTable(a_device).get(policy=[item.from_zone,item.to_zone])
    zone_policies.savexml(path='Zone_PoliciesConfig.xml', hostname=True)


  zone_policies_path = 'Zone_PoliciesConfig_165.124.8.5.xml'
  zone_policies_vrs = PolicyRuleTable(path=zone_policies_path)
   

  for item in IP_Address:
    # print ("Name: {} IP Address: {}").format(item.name, item.address)
    if (item.address == source):
      # print ("Name for source is defined as {}").format(item.name)
      address_obj = item.name
      pol_dict['Defined_As'] = item.name
      list_of_objects.append(address_obj)

      # AddressSet = GlobalAddressSet(a_device).get()
      # print AddressSet
      address_vrs = GlobalAddressSet(path=addr_set_path)
      AddressSet = address_vrs.get()
      # print AddressSet.keys()

      for item in AddressSet:
        # print item.address
        # print address_obj
        if(address_obj in item.address):
          print ('{} is in Address Set: {}').format(address_obj, item.set_name)
          address_set = item.set_name
          pol_dict['Address_Set'].append(address_set)
          list_of_objects.append(address_set)

  csv_file = hostname + '_PolContext.csv'
  if (os.path.isfile(csv_file)):
    print 'exists'
  else:       
    allPolicies = PolicyContextTable(a_device).get()
    with open(csv_file, 'w') as csvfile:  
      fieldnames = ['Src_Zone', 'Dst_Zone']   
      writer = csv.DictWriter(csvfile,fieldnames=fieldnames)
      writer.writeheader()  
   
      for item in allPolicies:
        writer.writerow({'Src_Zone':  item.from_zone, 'Dst_Zone': item.to_zone})

      csvfile.close()

  with open(csv_file) as csvfile:
      reader = csv.DictReader(csvfile)
      for row in reader:
        # print(row['Src_Zone'], row['Dst_Zone'])
        # policies = PolicyRuleTable(a_device).get(policy=[row['Src_Zone'],row['Dst_Zone']])
        policies = zone_policies_vrs.get(policy=[row['Src_Zone'],row['Dst_Zone']])
        
        for item in policies:
          src_match=False     
          # print('From Zone: {} To Zone: {}').format(from_zone, to_zone)
          for addr_obj in list_of_objects:
        
            if(addr_obj == item.match_src ):
              pol_dict['Src_Zone'] = row['Src_Zone']
              pol_dict['Dst_Zone'] = row['Dst_Zone']
              src_match = True
              pol_dict['Source'] = item.match_src
              pol_dict['Dest'] = item.match_dst
              pol_dict["Port"] = item.match_app
              pol_dict['Action'] = item.action 
              pol_dict['Policy'] = item.name 
   
            if(src_match):
              policies_list.append(pol_dict.copy())
              print policies_list
  # 
  policies = policies_vrs.get(options=table_options)
  # policies = GlobalPoliciesMatch(a_device).get(options=table_options)
  # print policies
  for addr_obj in list_of_objects:
    for item in policies:
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
            # policies_list.append(pol_dict)
        else:
          for src in item.match_src:
            # print src
            if (addr_obj == src):
              src_match = True
              pol_dict['Source'] = item.match_src
              # print("Source Address: {}".format(item.match_src))
              pol_dict['Src_Zone'] = 'global'
              pol_dict['Dst_Zone'] = 'global'
              pol_dict['Dest'] = item.match_dst
              pol_dict["Port"] = item.match_app
              pol_dict['Action'] = item.action 
              pol_dict['Policy'] = item.name 
              # policies_list.append(pol_dict)
          if(src_match):
            policies_list.append(pol_dict.copy())
          # print policies_list
  # print policies_list
  return policies_list 

def get_host_info(hostname, a_device, source, dest, port):
    
  policies_list = []   
  pol_dict = {'Src_Zone': '', 'Dst_Zone': '', 'Policy': '', 'Source': [], 'Dest': [], 'Port': [], 'Action': [], 'Source_IP': '', 'Defined_As': '', 'Defined_As': '', 'Address_Set': []}
  pol_dict['Source_IP'] = source
  # Global_VS_Zone = AddressSetZone(a_device).get()
  global_policies = GlobalPoliciesMatch(a_device).get(options=table_options) 
  # for item in Global_VS_Zone:
    # print ("Address Zone: {} Address Name: {} IP Prefix: {}").format(item.name, item.address_name, item.ip_prefix)
  list_of_objects = []
  IP_Address = GlobalAddressBook(a_device).get(address_name=source)
  for item in IP_Address:
    # print ("Name: {} IP Address: {}").format(item.name, item.address)
    if (item.address == source):
      # print ("Name for source is defined as {}").format(item.name)
      address_obj = item.name
      pol_dict['Defined_As'] = item.name
      list_of_objects.append(address_obj)

      AddressSet = GlobalAddressSet(a_device).get(address_name=address_obj)

      for item in AddressSet:
        if(address_obj in item.address):
          # print ('{} is in Address Set: {}').format(address_obj, item.set_name)
          address_set = item.set_name
          pol_dict['Address_Set'].append(address_set)
          list_of_objects.append(address_set)

  csv_file = hostname + '_PolContext.csv'
  if (os.path.isfile(csv_file)):
    print 'exists'
  else:       
    allPolicies = PolicyContextTable(a_device).get()
    with open(csv_file, 'w') as csvfile:  
      fieldnames = ['Src_Zone', 'Dst_Zone']   
      writer = csv.DictWriter(csvfile,fieldnames=fieldnames)
      writer.writeheader()  
   
    for item in allPolicies:
      writer.writerow({'Src_Zone':  item.from_zone, 'Dst_Zone': item.to_zone})

    csvfile.close()

  with open(csv_file) as csvfile:
      reader = csv.DictReader(csvfile)
      for row in reader:
        print(row['Src_Zone'], row['Dst_Zone'])
        policies = PolicyRuleTable(a_device).get(policy=[row['Src_Zone'],row['Dst_Zone']])
          
      for item in policies:
        src_match=False     
      # print('From Zone: {} To Zone: {}').format(from_zone, to_zone)
        for addr_obj in list_of_objects:
        
          if(addr_obj == item.match_src ):
            pol_dict['Src_Zone'] = from_zone
            pol_dict['Dst_Zone'] = to_zone
            src_match = True
            pol_dict['Source'] = item.match_src
            pol_dict['Dest'] = item.match_dst
            pol_dict["Port"] = item.match_app
            pol_dict['Action'] = item.action 
            pol_dict['Policy'] = item.name 
   
          if(src_match):
            policies_list.append(pol_dict.copy())
            # print policies_list

  policies = GlobalPoliciesMatch(a_device).get(options=table_options)
  for addr_obj in list_of_objects:
    for item in policies:
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
            # policies_list.append(pol_dict)
        else:
          for src in item.match_src:
            # print src
            if (addr_obj == src):
              src_match = True
              pol_dict['Source'] = item.match_src
              # print("Source Address: {}".format(item.match_src))
              pol_dict['Src_Zone'] = 'global'
              pol_dict['Dst_Zone'] = 'global'
              pol_dict['Dest'] = item.match_dst
              pol_dict["Port"] = item.match_app
              pol_dict['Action'] = item.action 
              pol_dict['Policy'] = item.name 
              # policies_list.append(pol_dict)
          if(src_match):
            policies_list.append(pol_dict.copy())
          # print policies_list
  # print policies_list
  return policies_list 

def get_global_host_info(a_device, list_of_objects):

  policies = GlobalPoliciesMatch(a_device).get(options=table_options) 

  policies_list = []
  i=0
  pol_dict = {'Src_Zone': '', 'Dst_Zone': '', 'Policy': '', 'Source': [], 'Dest': [], 'Port': [], 'Action': []}
 
  
  for addr_obj in list_of_objects:
    for item in policies:
      src_match=False     
      if isinstance(item.match_src, str):
        if (addr_obj == item.match_src):
          src_match = True
          pol_dict['Source'].append(item.match_src)
          # print("Source Address: {}".format(item.match_src))
          pol_dict['Src_Zone'] = 'global'
          pol_dict['Dst_Zone'] = 'global'
          pol_dict['Dest'].append(item.match_dst)
          pol_dict["Port"].append(item.match_app)   
          pol_dict['Action'] = item.action 
          pol_dict['Policy'] = item.name 
          policies_dict.update(pol_dict)
      else:
        for src in item.match_src:
          # print src
          if (addr_obj == src):
            src_match = True
            pol_dict['Source']= item.match_src
            # print("Source Address: {}".format(item.match_src))
            pol_dict['Src_Zone'] = 'global'
            pol_dict['Dst_Zone'] = 'global'
            pol_dict['Dest'] = item.match_dst
            pol_dict["Port"] = item.match_app
            pol_dict['Action'] = item.action 
            pol_dict['Policy'] = item.name 
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
        pol_dict['Source'] = item.match_src    
        pol_dict['Dest'].append(item.match_dst)    
        pol_dict["Port"].append(item.match_app) 
        pol_dict['Action'] = item.action 
           
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