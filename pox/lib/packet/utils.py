from pox.lib.addresses import IPAddr

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

def get_flowheader(self, packet):
  flow_header = FlowHeader()
  if isinstance(packet, ipv4):
    log.debug("packet %s", packet)
    flow_header.ip_src = packet.srcip
    flow_header.ip_dst = packet.dstip
    flow_header.proto = packet.protocol
    packet = packet.next
    if isinstance(packet, udp) or isinstance(packet, tcp):
      flow_header.p_src = packet.srcport
      flow_header.p_dst = packet.dstport
    elif isinstance(packet, icmp):
      flow_header.p_src = packet.type
      flow_header.p_dst = packet.code
  # elif isinstance(packet, arp):
  #   if packet.opcode <= 255:
  #     flow_header.proto = packet.opcode
  #     flow_header.ip_src = packet.protosrc
  #     flow_header.ip_dst = packet.protodst
  return flow_header