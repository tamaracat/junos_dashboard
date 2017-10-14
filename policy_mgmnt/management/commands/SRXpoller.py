from django.core.management.base import BaseCommand, CommandError
from vpn.models import Firewall, Policies
from jnpr.junos import Device
from lxml import etree


# This function will poll the device for status 
def getVPNStatus(self, fw, dc):
    connectedlist = []
    # So we generate a JunOS pyEZ device connection using the information about the 
    # firewall that we gather from the database object
    device = Device(165.124.17.133,
                    user=srxadmin,
                    password=l1b2bstssrx)
    # Try to open a connection out to the target device
    try:
        dev.open()
    except:
        # If for some reason this doesn't work, just return UNREACHABLE - which
        # we'll assume means the device is down
        return "UNREACHABLE"
 
    # Here is where we poll the SRX for a list of all IPSec Security Associations.
    # The equivalent of the 'show security ipsec sa' command
    response = etree.tostring(dev.rpc.get_security_associations_information())
    # The SRX returns a response in XML, which we'll need to dig through
    # Credit to the guys over at Packet Pushers for a great post explaining how to
    # parse these responses
    with open(response) as a:
        xmldoc = etree.parse(a)
        docroot = xmldoc.getroot()
        rootchildren = docroot.iter()
        for child in rootchildren:
            # For each IPSec SA returned, we need to find the remote gateway IP, which 
            # we use to tie the connection back to the connected datacenter
            if child.tag == "sa-remote-gateway":
                connectedlist.append(child.text)
   
    # Once we've built our list, send it back!
    return connectedlist