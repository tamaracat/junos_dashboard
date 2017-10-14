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
### SRX global address set
### ---------------------------------------------------------------------------

GlobalAddressBook:
  get: security/address-book/global
  view: GlobalAddressView
GlobalAddressView:
  fields:
    address: address

### ---------------------------------------------------------------------------
### SRX global policies
### ---------------------------------------------------------------------------

GlobalPolicies:
  get: security/policies/global/policy
  view: GlobalAddressView
GlobalAddressView:
  fields:
    policies: policies


 
 
"""




globals().update(FactoryLoader().load(yaml.load(myYAML)))


a_device = Device(host='165.124.17.133', user='srxadmin', password='l1b2bstssrx', port='22')
try:
  a_device.open(normalize=True)
except ConnectError as err:
  print ("Cannot connect to device: {0}".format(err))
   

data = a_device.rpc.get_config(options={'database' : 'committed'})
print(etree.tostring(data, encoding='unicode'))

    # Text format
# data = a_device.rpc.get_config(options={'format':'text'})
# print(etree.tostring(data))

    # Junos OS set format
# data = a_device.rpc.get_config(options={'format':'set'})
# print (etree.tostring(data))

# sp = a_device.rpc.get_global_firewall_policies(policy_name='14', dev_timeout=55)
# print sp
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

a_device.close() 

# pprint(a_device.facts)

# output_json = json.loads(arp.to_json())
# print json.dumps(output_json, indent=4)


# rsp = a_device.rpc.get_interface_information(interface_name='ge-0/0/0.0', terse=True)
# pprint  (rsp.xpath(".// \
    # address-family[normalize-space(address-family-name)='inet']/ \
    # interface-address/ifa-local")[0].text)

