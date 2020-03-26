from pox.lib.addresses import IPAddr

from pox.lib.packet.ethernet import ethernet
from pox.lib.packet.ipv4 import ipv4
from pox.lib.packet.udp import udp
from pox.lib.packet.tcp import tcp
from pox.lib.packet.icmp import icmp

import ipaddress

class FlowHeader():
  SPECIFIC  = 0
  LARGE     = 1
  """
  The flow header used on all the system. Just a simple tuple with src_ip, dst_ip and dport
  """
  def __init__(self, proto=1, sip=IPAddr("0.0.0.0"), sport=-1, dip=IPAddr("0.0.0.0"), dport=-1):
    self.proto = proto
    self.sip = sip
    self.sport = sport
    self.dip = dip
    self.dport = dport
  
  def flip(self):
    if self.proto == 1:
      if self.sport == self.dport:
        return FlowHeader(proto=self.proto, sip=self.dip, sport=8, dip=self.sip, dport=0)
      else:
        return FlowHeader(proto=self.proto, sip=self.dip, sport=0, dip=self.sip, dport=0)
    else:
      return FlowHeader(proto=self.proto, sip=self.dip, sport=self.dport, dip=self.sip, dport=self.sport)
  
  def __eq__(self, other):
    """
    Overrides the default implementation
    """
    if not isinstance(other, FlowHeader) : return False
    if self.proto != other.proto : return False
    if self.sip != other.sip : return False
    if self.sport != other.sport : return False
    if self.dip != other.dip : return False
    if self.dport != other.dport : return False
    return True

  # def is_applicable (self, other):
  def can_be_apply_to (self, other):
    if not isinstance(other, FlowHeader) : return (False, None)
    if self.__eq__(other): return (True, FlowHeader.SPECIFIC)
    if self.large_check(other): return (True, FlowHeader.LARGE)
    return (False, None)

  def large_check(self, other):
    if self.sip != IPAddr("0.0.0.0") and self.sip != other.sip : 
      if isinstance(self.sip, ipaddress.IPv4Network) and other.sip.in_network(network=self.sip):
        return False
    # if self.sport != -1 and self.sport != other.sport : return False
    if self.dip != IPAddr("0.0.0.0") and self.dip != other.dip : 
      if isinstance(self.dip, ipaddress.IPv4Network) and other.dip.in_network(network=self.dip):
        return False
    if self.dport != -1 and self.dport != other.dport : 
      return False
    return True

  def __cmp__ (self, other):
    return self.__eq__(self, other)

  def __ne__(self, other):
    return not self.__eq__(self, other)

  def __str__(self):
    return str(self.proto)+" - "+str(self.sip)+":"+str(self.sport)+" ==> "+str(self.dip)+":"+str(self.dport)

  def __hash__(self):
    return tuple((self.proto, self.sip, self.sport, self.dip, self.dport)).__hash__()

def get_flowheader(packet):
  flow_header = FlowHeader()
  if isinstance(packet, ipv4):
    flow_header.sip = packet.srcip
    flow_header.dip = packet.dstip
    flow_header.proto = packet.protocol
    packet = packet.next
    if isinstance(packet, udp) or isinstance(packet, tcp):
      flow_header.sport = packet.srcport
      flow_header.dport = packet.dstport
    elif isinstance(packet, icmp):
      flow_header.sport = packet.type
      flow_header.dport = packet.code
  # elif isinstance(packet, arp):
  #   if packet.opcode <= 255:
  #     flow_header.proto = packet.opcode
  #     flow_header.sip = packet.protosrc
  #     flow_header.dip = packet.protodst
  return flow_header

def ip_representation (address):
  if isinstance(address, IPAddr) or isinstance(address, ipaddress.IPv4Network):
    # print("ip_representation IPAddr %s", address)
    return address
  if type(address) is tuple:
    return ipaddress.IPv4Network(address, strict=False)

  # print("ip_representation str %s", address)
  addr = address.split('/', 2)
  if len(addr) == 1:
    return IPAddr(address)
  return ipaddress.IPv4Network(unicode(address), strict=False)

def in_network (ip, network):
  return ipaddress.ip_network( ( ip, infer_netmask(ip) ), strict=False ) == ipaddress.ip_network(network)

def get_network (ip):
  return ipaddress.ip_network((ip, infer_netmask(ip)), strict=False)

def infer_netmask (addr):
  """
  Uses network classes to guess the number of network bits
  """
  if not isinstance(addr, IPAddr):
    addr = IPAddr(addr)
  addr = addr.toUnsigned()
  if addr == 0:
    # Special case -- default network
    return 32-32 # all bits wildcarded
  if (addr & (1 << 31)) == 0:
    # Class A
    return 32-24
  if (addr & (3 << 30)) == 2 << 30:
    # Class B
    return 32-16
  if (addr & (7 << 29)) == 6 << 29:
    # Class C
    return 32-8
  if (addr & (15 << 28)) == 14 << 28:
    # Class D (Multicast)
    return 32-0 # exact match
  # Must be a Class E (Experimental)
  return 32-0