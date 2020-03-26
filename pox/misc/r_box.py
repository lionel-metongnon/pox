# Rear Box
#
# Based on of_tutorial by James McCauley

from pox.core import core
import pox.openflow.libopenflow_01 as of

from pox.lib.packet.ethernet import ethernet
from pox.lib.packet.xmp import *

from pox.misc.list import *
from pox.misc.utils import *

from pox.lib.util import dpid_to_str, str_to_dpid
log = core.getLogger()

# Interval for the parallel function repetition
check_time = .5

# Mitigate at the source
source_mitigation = True
class R_Box (object):
  DEFAULT_PERMISSION_DURATION_DROP = 100
  DEFAULT_DDOS_RATIO = 3
  """
  A R_Box object is created for each switch that connects.
  A Connection object for that switch is passed to the __init__ function.
  """
   # Here will be the instance stored.
  __instance = None

  @staticmethod
  def getInstance(connection, network=None):
    # print("getInstance")
    """ Static access method. """
    if R_Box.__instance is None:
      R_Box(connection, network)
    elif connection is not None:
      R_Box.__instance.connection = connection
      connection.addListeners(R_Box.__instance)
    return R_Box.__instance

  def __init__ (self, connection, network):
    # For the first instance
    R_Box.__instance = self

    # my network
    self.network = ip_representation(network)
    # Keep track of the connection to the switch so that we can
    # send it messages!
    self.connection = connection

    # For the local switch communication
    self.macToPort = dict()

    # The message manager the protocol message
    self.msgMngr = Manager(self)
    # Listen to incoming traffic
    start_new_thread(Manager.routine, (self.msgMngr,))

    # The record to queue the events
    self.eventQueue = dict()

    # The flow record
    self.flowQueue = dict()
  
    # The 4 list 
    self.alertList = AlertList()
    self.flowList = None
    self.policyList = PolicyList()
    self.permList = PermissionList()


    # Permission record for plot purpose
    self.permRecord = dict()

    # scanning ip reported set
    self.scanIpListReported = set()

    # all (past + current) communication information
    self.allFlowInformation = dict()

    # This binds our PacketIn event listener
    connection.addListeners(self)

    # checking for automatic list
    # For the scheduling check
    self.watchtimer = sched.scheduler(time.time, time.sleep)
    self.watchtimer.enter(check_time, 1, self.do_checking, (source_mitigation,))
    # self.watchtimer.enter(check_time, 1, self.get_flows, ())
    start_new_thread(self.watchtimer.run, ())

    # register the box to the zoneBox
    register_msg = network_register(id=0, box_network_id=self.network, controler=list(("127.0.0.1", self.msgMngr.port)), top=list((str(top_ip[0]), top_ip[1])))
    self.msgMngr.box_network_id[register_msg.box_network_id] = register_msg.controler
    self.msgMngr.sr_pkt(None, xmp(mid=random.randint(1, 65535), code=xmp.RGT, message=register_msg))

# standard functions flood, send drop
  def flood (self, event, message = None):
    """ Floods the packet """
    packet = event.parsed # This is the parsed packet data.
    packet_in = event.ofp # The actual ofp_packet_in message.zero
    switch_port = event.port # the port on the switch

    msg = of.ofp_packet_out()
    if time.time() - self.connection.connect_time >= 0:
      if message is not None:
        log.debug(message)
      log.debug("flood %s -> %s", packet.src, packet.dst)
      # OFPP_FLOOD is optional; on some switches you may need to change
      # this to OFPP_ALL.
      msg.actions.append(of.ofp_action_output(port = of.OFPP_FLOOD))
    else:
      pass
      log.info("Holding down flood for %s", dpid_to_str(event.dpid))
    msg.data = packet_in
    msg.in_port = switch_port
    self.connection.send(msg)

  def send(self, event, priority = None, idle_timeout=10, hard_timeout=30):
    # Sender
    """
    send packet in messages to the switch.
    """
    packet = event.parsed
    self.macToPort[packet.src] = event.port # 1

    if packet.dst.is_multicast:
      self.flood(event) # 3a
    else:
      if packet.dst not in self.macToPort: # 4
        self.flood(event, "Port for %s unknown -- flooding" % (packet.dst,)) # 4a
      else:
        port = self.macToPort[packet.dst]
        if port == event.port: # 5
          # 5a
          log.warning("Same port for packet from %s -> %s on %s.%s.  Drop."
              % (packet.src, packet.dst, dpid_to_str(event.dpid), port))
          self.drop(packet, event.ofp, event.port, idle_timeout)
          return
        # 6
        log.debug("installing flow for %s.%i -> %s.%i" %
                  (packet.src, event.port, packet.dst, port))
        msg = of.ofp_flow_mod()
        msg.match = of.ofp_match.from_packet(packet, event.port)
        msg.idle_timeout = idle_timeout
        msg.hard_timeout = hard_timeout
        if priority is not None:
          msg.priority = priority
        msg.actions.append(of.ofp_action_output(port = port))
        msg.data = event.ofp # 6a
        self.connection.send(msg)
  
  def drop (self, packet, packet_in, switch_port, duration = None):
    """
    Drops this packet and optionally installs a flow to continue
    dropping similar ones for a while
    """
    if duration is not None:
      if not isinstance(duration, tuple):
        duration = (duration, duration)
      msg = of.ofp_flow_mod()
      msg.match = of.ofp_match.from_packet(packet)
      msg.idle_timeout = duration[0]
      msg.hard_timeout = duration[1]
      msg.priority = 1
      msg.buffer_id = packet_in.buffer_id
      self.connection.send(msg)
    elif packet_in.buffer_id is not None:
      msg = of.ofp_packet_out()
      msg.buffer_id = packet_in.buffer_id
      msg.priority = 1
      msg.in_port = switch_port
      self.connection.send(msg)

  def is_control_packet(self, packet):
    # Check the packet type
    if packet.type == ethernet.IP_TYPE :
      return False
    return True

  def do_firewall (self, event):
    """ The code in here will be executed for every packet.
    """
    # The code in here will be executed for every packet.
    packet = event.parsed # This is the parsed packet data.
    flowHeader = get_flowheader(packet.next)

    log.debug("do_firewall ethernet of type %d, ports %s -> %s."
              % (packet.type, packet.src, packet.dst))
    log.debug("do_firewall flowHeader %s", str(flowHeader))
    # print("do_firewall flow_hea0der %s", str(flowHeader))
    # log.debug("IP %d %d  %s => %s", packet.next.v, packet.next.protocol, packet.next.srcip,packet.next.dstip)

    if in_network(flowHeader.sip, self.network):
      # outgoing
      if not self.permList.exists(flowHeader):
        # print("outgoing ", str(flowHeader.dip))
        # for id in self.msgMngr.box_network_id:
        #   print(str(id))
        
        box = self.msgMngr.box_network_id.get (get_network(flowHeader.dip), None)
        if box is None:
          #default policies
          log.debug("do_firewall No box found for %s", str(flowHeader.dip))
          self.drop(packet, event.ofp, event.port, R_Box.DEFAULT_PERMISSION_DURATION_DROP)
        else:
          policy = self.policyList.get(flowHeader.sip)
          # perm = self.msgMngr.
          permission_request_msg = permission_request(proto=flowHeader.proto, sip=flowHeader.sip, sport=flowHeader.sport, dip=flowHeader.dip, dport=flowHeader.dport, duration=policy.policyList['permission']['duration'])
          xmp_pkt = xmp(mid=random.randint(1, 65535) , code=xmp.PERM_RQT, message=permission_request_msg)
          self.save(event, xmp_pkt.mid, flowHeader.dip, flowHeader.dport)
          self.msgMngr.sr_pkt(event, xmp_pkt, flowHeader.dip)
          # self.permList.add(flowHeader, Permission(flowHeader, True, policy.policyList['permission']['duration']))
      else:
        perm = self.permList.get(flowHeader)
        diff = time.time() - perm.timestamp
        log.debug("do_firewall %s %s %s", perm.answer, perm.duration, diff)
        if perm.answer and perm.duration > (time.time() - perm.timestamp):
          # forward packets
          log.debug("do_firewall send outgoing packet, because we ack bidirectional perm")
          self.send(event, 1, perm.duration, perm.duration)
        
        # remove because permission still present but duration is expired so drop rule is add to the table
        # else:
        #   # drop the packet
        #   log.debug("do_firewall outgoing packet drop")
        #   self.drop(packet, event.ofp, event.port, R_Box.DEFAULT_PERMISSION_DURATION_DROP)
    else:
      # incoming

      # check scanning here
      if self.scan_pattern(flowHeader.sip, self.allFlowInformation):
        self.alertList.add(flowHeader.dip, Alert(flowHeader.dip, flowHeader, Alert.SCAN))
        self.drop(packet, event.ofp, event.port, R_Box.DEFAULT_PERMISSION_DURATION_DROP)

      if not self.permList.exists(flowHeader):
        box = self.msgMngr.box_network_id.get (get_network(flowHeader.sip), None)
        if box is None:
          #default policies
          self.drop(packet, event.ofp, event.port, R_Box.DEFAULT_PERMISSION_DURATION_DROP)
        else:
          # send alert to the box
          log.debug("do_firewall incoming packet without permission")
          alert_request_msg = alert_request(proto=flowHeader.proto, sip=flowHeader.sip, sport=flowHeader.sport, dip=flowHeader.dip, dport=flowHeader.dport, alertType=Alert.PERMISSION, deviceIP=flowHeader.sip)
          xmp_pkt = xmp(mid=random.randint(1, 65535) , code=xmp.ALT_RQT, message=alert_request_msg)
          self.msgMngr.sr_pkt(None, xmp_pkt, flowHeader.sip)
          self.permList.add(flowHeader, Permission(flowHeader, False, R_Box.DEFAULT_PERMISSION_DURATION_DROP))
          self.alertList.add(flowHeader.dip, Alert(flowHeader.dip, flowHeader, Alert.PERMISSION))
          # drop the packet
          self.drop(packet, event.ofp, event.port, R_Box.DEFAULT_PERMISSION_DURATION_DROP)
      else:
        perm = self.permList.get(flowHeader)
        diff = time.time() - perm.timestamp
        log.debug("do_firewall %s %s %s", perm.answer, perm.duration, diff)
        if perm.answer and perm.duration > (time.time() - perm.timestamp):
          # forward packets
          log.debug("do_firewall send incoming packet")
          self.send(event, 1, perm.duration, 3*perm.duration)
        else:
          # drop the packet
          log.debug("do_firewall incoming packet drop")
          self.drop(packet, event.ofp, event.port, R_Box.DEFAULT_PERMISSION_DURATION_DROP)

  def _handle_PacketIn (self, event):
    """
    Handles packet in messages from the switch.
    """
    packet = event.parsed # This is the parsed packet data.
    if not packet.parsed:
      log.warning("Ignoring incomplete packet")
      return

    if self.is_control_packet(packet):
      self.send(event)
    else:
      self.do_firewall(event)

  def msgManage(self, xmp_pkt, sender_info):
    self.permRecord[time.time()] = (xmp_pkt.code, xmp_pkt.mid)
    message = xmp_pkt.message
    if xmp_pkt.code == xmp.PERM_RQT:
      flowHeader = FlowHeader(message.proto, message.sip, message.sport, message.dip, message.dport)
      log.debug("msgManage PERM_RQT %s", flowHeader)
      policy = self.policyList.get(flowHeader.dip)
      reply = permission_reply(ip=message.dip, port=message.dport)
      if self.policy_can_be_apply(policy):
        reply.decision = True
        reply.duration = policy.policyList['permission']['duration']
        self.permList.add(flowHeader, Permission(flowHeader, True, policy.policyList['permission']['duration']))
        self.permList.add(flowHeader.flip(), Permission(flowHeader.flip(), True, policy.policyList['permission']['duration']))
      else:
        reply.decision = False
        reply.duration = R_Box.DEFAULT_PERMISSION_DURATION_DROP
        self.permList.add(flowHeader, Permission(flowHeader, False, R_Box.DEFAULT_PERMISSION_DURATION_DROP))
        self.permList.add(flowHeader.flip(), Permission(flowHeader.flip(), False, R_Box.DEFAULT_PERMISSION_DURATION_DROP))
      self.msgMngr.send_message(xmp(mid=xmp_pkt.mid+1, code=xmp.PERM_RPY, message=reply), sender_info[0])
    elif xmp_pkt.code == xmp.PERM_RPY:
      log.debug("msgManage PERM_RPY %s", message.decision)
      if message.decision :
        flowHeader = self.flowQueue.get((xmp_pkt.mid - 1, message.ip, message.port))
        event = self.load(xmp_pkt.mid - 1, message.ip, message.port)
        if event is None:
          log.debug("msgManage PERM_RPY Here we go again")
        policy = self.policyList.get(flowHeader.sip)
        self.permList.add(flowHeader, Permission(flowHeader, True, policy.policyList['permission']['duration']))
        self.permList.add(flowHeader.flip(), Permission(flowHeader.flip(), True, policy.policyList['permission']['duration']))
        self.send(event, 1, message.duration, 3*message.duration)
      else:
        self.permList.add(flowHeader, Permission(flowHeader, False, R_Box.DEFAULT_PERMISSION_DURATION_DROP))
        self.permList.add(flowHeader.flip(), Permission(flowHeader.flip(), False, R_Box.DEFAULT_PERMISSION_DURATION_DROP))
        self.drop(event.parsed, event.ofp, event.port, R_Box.DEFAULT_PERMISSION_DURATION_DROP)
    elif xmp_pkt.code == xmp.ALT_RQT:
      flowHeader = FlowHeader(message.proto, message.sip, message.sport, message.dip, message.dport)
      log.debug("msgManage ALT_RQT %s", flowHeader)
      self.alertList.add(message.deviceIP, Alert(message.deviceIP, flowHeader, message.alertType))
      self.msgMngr.send_message(xmp(mid=xmp_pkt.mid + 1, code=xmp.ACK), sender_info[0])

  def save(self, event, mid, info_0, info_1 ):
    self.eventQueue[(mid, info_0, info_1)] = event

  def load(self, mid, info_0, info_1):
    return self.eventQueue.pop((mid, info_0, info_1), None)

  def policy_can_be_apply(self, policy):
    return True

  def get_flows(self, periodic=True):
    log.debug ("get_flows")
    for connection in core.openflow.connections.keys():
      core.openflow.connections[connection].send(of.ofp_stats_request(body=of.ofp_flow_stats_request()))
      if self.flowList is not None:
        self.flowList.check()
    if periodic:
      self.watchtimer.enter(check_time, 1, self.get_flows, ())

  # def do_check_record(self):
  #   log.debug("do check record")
  #   if self.flowList is not None:
  #     for flow in self.first_sender:
  #       if flow not in self.flowList.sip_flow:
  #         self.first_sender.discard(flow)
  #   self.watchtimer.enter(10, 1, self.do_check_record, ())
  def show_record(self):
    for elt in self.permRecord.keys():
      print str(elt)+"\t"+str(self.permRecord[elt][0])+"\t"+str(self.permRecord[elt][1])

  def do_checking(self, source_mitigation):
    print("begining")
    self.show_record()
    print("end")

    self.get_flows(False)
    for elem in self.permList.list.keys():
      log.debug("do_checking %s", str(elem))
      diff = time.time() - self.permList.list[elem].timestamp
      log.debug("do_checking %s %s", str(diff), str(self.permList.list[elem].duration) ) 
      if (time.time() - self.permList.list[elem].timestamp) >= self.permList.list[elem].duration:
        del self.permList.list[elem]

    log.debug("do_checking %d ", len(self.alertList.list))
    for elem in self.alertList.list.keys():
      # alert = self.alertList.list[elem]
      alert = self.alertList.list.pop(elem)
      if isinstance(alert.flowHeader, list):
        listLen = len(alert.flowHeader)
        for i in range(listLen):
          self.mitigation(Alert(alert.deviceIP, alert.flowHeader[i], alert.alertType, alert.flow[i]), source_mitigation, (i, listLen))
      else:
        self.mitigation(alert, source_mitigation)
      
      # self.alertList.delete(elem)

    self.watchtimer.enter(check_time, 1, self.do_checking, (source_mitigation,))

  def mitigation(self, alert, sourceMitigation=False, data=None):
    if alert.deviceIP == alert.flowHeader.dip:
      # The device is mine
      policy = self.policyList.get(alert.flowHeader.dip)
      if alert.alertType == Alert.DOS:
        print('Under DoS ', alert.deviceIP, str(alert.flow) )
        dropFlow(alert.flow, self.connection, policy.policyList['under-dos']['duration'])
      elif alert.alertType == Alert.DDOS:
        if alert.flowHeader.sip not in Policy.DEFAULT_POLICY['whiteList'] and (data[0] % R_Box.DEFAULT_DDOS_RATIO == 0 or data[1] == 1):
          print('Under DDoS')
          dropFlow(alert.flow, self.connection, policy.policyList['under-ddos']['duration'])
      elif alert.alertType == Alert.SCAN:
        print('Under Scan')
        if alert.flowHeader.sip in self.flowList.sip_flow:
          list_ = self.flowList.sip_flow[alert.flowHeader.sip]
          for elt in list_:
            dropFlow(list_[elt], self.connection, policy.policyList['under-scan']['duration'])

      elif alert.alertType == Alert.PERMISSION:
        print('Under Permission')
      
      self.permList.delete(alert.flowHeader)
      if sourceMitigation:
        # Send the notification to the destination
        flowHeader = alert.flowHeader.flip()
        alert_request_msg = alert_request(proto=flowHeader.proto, sip=flowHeader.sip, sport=flowHeader.sport, dip=flowHeader.dip, dport=flowHeader.dport, alertType=alert.alertType, deviceIP=alert.deviceIP)
        xmp_pkt = xmp(mid=random.randint(1, 65535) , code=xmp.ALT_RQT, message=alert_request_msg)
        self.msgMngr.sr_pkt(None, xmp_pkt, alert.flowHeader.sip)

        self.permList.delete(alert.flowHeader)
    else:
      # I am attacking someone and need to stop
      # we get a flip flow but we need the attacker flow
      flowHeader = alert.flowHeader.flip()
      policy = self.policyList.get(flowHeader.sip)
      if alert.alertType == Alert.DOS:
        print('Doing DoS', alert.deviceIP, str(flowHeader) )
        flow = self.flowList.sip_flow.get(flowHeader.sip, {}).get(flowHeader)
        if flow is not None:
          dropFlow(flow, self.connection, policy.policyList['doing-dos']['duration'])
        else:
          print ('Doing DoS We are in trouble again')
        # dropFlowHeader(alert.flowHeader, self.connection, policy.policyList['doing-dos']['duration'])
      elif alert.alertType == Alert.DDOS:
        print('Doing DDoS')
        flow = self.flowList.sip_flow.get(flowHeader.sip, {}).get(flowHeader)
        if flow is not None:
          dropFlow(flow, self.connection, policy.policyList['doing-ddos']['duration'])
        else:
          print ('Doing DDoS We are in trouble again')
        # dropFlow(alert.flowHeader, self.connection, policy.policyList['doing-scan']['duration'])
      elif alert.alertType == Alert.SCAN:
        print('Doing Scan')
        self.scanIpListReported.add(flowHeader.sip)
        # dropFlowHeader(alert.flowHeader, self.connection, policy.policyList['doing-scan']['duration'])
      elif alert.alertType == Alert.PERMISSION:
        print('Doing Permission')
      
      self.permList.delete(flowHeader)

  def scan_pattern (self, suspect_ip, list_ = None):
    if list_ is None:
      list_ = self.flowList.sip_com
    print ("scan_pattern %s", suspect_ip)
    if get_network(suspect_ip) == self.network:
      return False
    if suspect_ip in list_:
      print (len(list_[suspect_ip]))
      if suspect_ip in self.scanIpListReported and len(list_[suspect_ip]) > FlowList.DEFAULT_REPORTED_SCAN_IP_CONNEXION_ALLOW:
        return True
      elif len(list_[suspect_ip]) > FlowList.DEFAULT_SCAN_MAX_CONNEXION:
        return True

    return False

class FlowList(object):
  DEFAULT_DOS_RATIO = 100
  DEFAULT_DDOS_DURATION = 15
  DEFAULT_DDOS_MAX_SIZE = 5000
  DEFAULT_SCAN_MAX_CONNEXION = 50
  DEFAULT_REPORTED_SCAN_IP_CONNEXION_ALLOW = 2
  """
  The information of the flow from the switch
  """
  def __init__ (self, stats, network):
    # Keep track of the connection to the switch so that we can
    # send it messages!
    self.stats = stats
    self.network = unicode(network)
    self.update_status = False

    self.dip_com = dict()
    self.sip_com = dict()

    self.dip_flow = dict()
    self.sip_flow = dict()

    self.ip_scanning_flow = dict()
    self.box = R_Box.getInstance(None)
    self.box.flowList = self
    self.update()

  # def get_flowheader(self, flow):
  #   if isinstance(flow, FlowHeader):
  #     return flow
  #   return FlowHeader(proto=flow.match.nw_proto, sip=flow.match.nw_src, dip=flow.match.nw_dst, sport=flow.match.tp_src, dport=flow.match.tp_dst)

  def update(self):
    for flow in self.stats:
      if flow.match.nw_proto in (1, 6, 17) and (flow.match.tp_src is not  None or flow.match.tp_dst is not None):
        self.add_info(flow.match.nw_src, flow.match.nw_dst, self.dip_com)
        self.add_info(flow.match.nw_dst, flow.match.nw_src, self.sip_com)

        self.add_flow(flow, flow.match.nw_dst, self.dip_flow)
        self.add_flow(flow, flow.match.nw_src, self.sip_flow)

        self.add_scanning_flow(flow, flow.match.nw_src, self.ip_scanning_flow)

  def upgrade(self):
    if len(self.box.allFlowInformation) == 0:
      self.box.allFlowInformation = copy.deepcopy(self.sip_com)
    else:
      for elt in self.sip_com.keys():
        if elt in self.box.allFlowInformation:
          self.box.allFlowInformation[elt].update(self.sip_com[elt])
        else:
          self.box.allFlowInformation[elt] = copy.deepcopy(self.sip_com[elt])


  def add_info(self, other_info, ip, flowList):
    if ip not in flowList:
      flowList[ip] = set()
    
    if other_info in flowList[ip]:
      flowList[ip].discard(other_info)
    else:
      flowList[ip].add(other_info)

  def add_flow(self, flow, ip, flowList):
    flheader = FlowHeader(proto=flow.match.nw_proto, sip=flow.match.nw_src, dip=flow.match.nw_dst, sport=flow.match.tp_src, dport=flow.match.tp_dst)
    # log.debug("add_flow %s %s %s", ip, str(flheader), hex(id(flowList)) )
    if ip not in flowList:
      flowList[ip] = dict()
    flowList[ip][flheader] = flow
      
  def add_scanning_flow(self, other_info, ip, flowList):
    if ip not in flowList:
      flowList[ip] = set()
    
    if other_info in flowList[ip]:
      flowList[ip].discard(other_info)
    else:
      flowList[ip].add(other_info)

  def check(self):
    print("check_traffic", len(self.dip_flow), len(self.sip_flow))
    for elt in self.dip_flow.keys():
      if get_network(elt) == ipaddress.ip_network(self.network) :
        if self.dos_attack(elt, self.dip_flow[elt]):
          log.debug("dos detected")
        elif self.ddos_attack(elt, self.dip_flow[elt]):
          log.debug("ddos detected")

  def dos_attack (self, suspect_ip, flow_list):
    suspect_header = []
    suspect_flow = []
    for key in flow_list:
      elt = flow_list[key]
      if elt.packet_count > 1:
        print (str(key), elt.packet_count, elt.byte_count, elt.duration_sec, elt.duration_nsec)
      if len(elt.actions) > 0 and elt.packet_count > 5 and elt.byte_count/(elt.duration_sec + 10**-9 * elt.duration_nsec) > FlowList.DEFAULT_DOS_RATIO:
        if elt.duration_sec > 0:
          print (str(key), elt.packet_count, elt.byte_count, elt.duration_sec, elt.duration_nsec)
          suspect_header.append(key)
          suspect_flow.append(elt)
        # return (True, elt)
    if len(suspect_flow) > 0:
      self.box.alertList.add(suspect_ip, Alert(suspect_ip, suspect_header, Alert.DOS, suspect_flow))
      return True
    return False

  def ddos_attack (self, suspect_ip, flow_list):
    size = 0
    duration = 0
    suspect_header = []
    suspect_flow = []
    for key in flow_list:
      elt = flow_list[key]
      suspect_header.append(key)
      suspect_flow.append(elt)
      # print ("ddos_attack ", elt.byte_count)
      # print ("ddos_attack %s %s %s %s %s ", str(key), elt.packet_count, elt.byte_count, elt.duration_sec, elt.duration_nsec)
      size += elt.byte_count
      if len(elt.actions) > 0 and elt.duration_sec >= FlowList.DEFAULT_DDOS_DURATION:
        duration += 1
    print (size >= FlowList.DEFAULT_DDOS_MAX_SIZE, duration, (4.0/5) * len(flow_list), duration >= (4.0/5) * len(flow_list))
    if size >= FlowList.DEFAULT_DDOS_MAX_SIZE and duration >= (4.0/5) * len(flow_list): #len(elt)/2
      self.box.alertList.add(suspect_ip, Alert(suspect_ip, suspect_header, Alert.DDOS, suspect_flow))
      return True
    return False
# class Detection(object):

#   def __init__():
#     po

def dropFlow(flow, connection, duration):
  if not isinstance(duration, tuple):
    duration = (duration, duration)
  msg = of.ofp_flow_mod()
  msg.match = flow.match
  msg.idle_timeout = duration[0]
  msg.hard_timeout = duration[1]
  msg.priority = 1
  # msg.priority = FlowList.RATE_LIMITER_PRIORITY
  msg.actions = []
  connection.send(msg)

def dropFlowHeader(flowheader, connection, duration):
  if not isinstance(duration, tuple):
    duration = (duration, duration)
  msg = of.ofp_flow_mod()
  msg.match.dl_type = 0x800 # IPV4
  msg.match.nw_proto = flowheader.proto
  msg.match.nw_src = flowheader.sip
  msg.match.tp_src = flowheader.sport
  msg.match.nw_dst = flowheader.dip
  msg.match.tp_src = flowheader.dport
  msg.idle_timeout = duration[0]
  msg.hard_timeout = duration[1]
  msg.actions = []
  # msg.priority = FlowInfo.RATE_LIMITER_PRIORITY
  connection.send(msg)
  
def launch (network="10.0.0.0/8"):
  """
  Starts the component
  """
  def start_switch (event):
    log.debug("Controlling %s %s" % (event.connection, network))
    R_Box.getInstance(event.connection, network)

  def handle_flow_stats(event):
    log.debug ("handle flow %d", len(event.stats))
    FlowList(event.stats, network)

  core.openflow.addListenerByName("ConnectionUp", start_switch)
  core.openflow.addListenerByName("FlowStatsReceived", handle_flow_stats)
