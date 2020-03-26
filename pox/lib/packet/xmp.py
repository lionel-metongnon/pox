from packet_utils import *

from packet_base import packet_base

from pox.lib.addresses import IPAddr,IPAddr6,EthAddr

from thread import *
from socket import *

import struct, json, bson, random, sys, ipaddress


from pox.misc.utils import *

top_ip = (IPAddr("127.0.0.1"), 15075)
my_ip = [IPAddr("127.0.0.1"), 0]
class Manager():
  """
  The class to manage the xmp system
  """
  def __init__(self, box=None, myIP=IPAddr("127.0.0.1"), top=False):
    print("__init__", str(myIP), top)
    self.top_level = top
    self.my_ip = myIP
    self.box = box

    self.records = dict()
    self.box_network_id = dict()
    
    self.controler_version = 0
    random.seed()

    self.port = random.randint(1025, 65535)
    my_ip[1] = self.port
    if top: 
      self.port = top_ip[1]
    self.socket_listener = socket(AF_INET, SOCK_STREAM)
    try:
      self.socket_listener.bind(('', self.port))
      print("Listening on: %d", self.port)
    except error as msg:
      print("Bind failed with " +msg[1])
      sys.exit()
    self.socket_listener.listen(100)
  
# send xmp from socket
  def send_message(self, xmp_pkt, socket_client):
    # print("send_message", str(xmp_pkt))
    if not isinstance(xmp_pkt, xmp): return
    try:
      socket_client.sendall(str(xmp_pkt)+"*")
    except error as msg:
      print("Error here ",msg[0])
  
  def get_socket(self, network_id=IPAddr("127.0.0.1")):
    # print("get_socket %s", str(network_id))
    # for add in self.box_network_id:
    #   print ("get_socket add %s:", add )
    # if network_id == IPAddr("127.0.0.1"):
    #   address_client = top_ip
    # else:
    address_client = self.box_network_id.get(network_id, None)
    if address_client is None:
      return None

    socket_client = socket(AF_INET, SOCK_STREAM)
    socket_client.connect(tuple((str(address_client[0]), address_client[1])))
    socket_client.setsockopt(IPPROTO_TCP, TCP_NODELAY, 1)
    return socket_client

  def sr_pkt(self, event, xmp_pkt, dst_ip=IPAddr("127.0.0.1"), thread=True):
    # print("send packet ", str(xmp_pkt), dst_ip)
    if dst_ip == IPAddr("127.0.0.1"):
      address_client = top_ip
      # socket_client = self.get_socket()
      socket_client = socket(AF_INET, SOCK_STREAM)
      socket_client.connect(tuple((str(address_client[0]), address_client[1])))
      socket_client.setsockopt(IPPROTO_TCP, TCP_NODELAY, 1)
    else:
      network_id = get_network(dst_ip)
      address_client = self.box_network_id.get(network_id)
      socket_client = self.get_socket(network_id)

      if socket_client is None:
        print( "I don't have it")
        if self.port != top_ip[1]:
          self.sr_pkt(None, xmp(mid=random.randint(1, 65535), code=xmp.LOOKUP, message=lookup(box_network_id=network_id)), IPAddr("127.0.0.1"), False)
          socket_client = self.get_socket(network_id)
          if socket_client is None:
            print( "We are in deep trouble")
      else:
        self.box.save(event, xmp_pkt.mid, address_client[0], address_client[1])
        if xmp_pkt.code == xmp.PERM_RQT:
          flowHeader = FlowHeader(xmp_pkt.message.proto, xmp_pkt.message.sip, xmp_pkt.message.sport, xmp_pkt.message.dip, xmp_pkt.message.dport)
          self.box.flowQueue[(xmp_pkt.mid, xmp_pkt.message.dip, xmp_pkt.message.dport)] = flowHeader

    print(address_client)
    if socket_client is None:
      print ("We are in trouble")
    self.send_message(xmp_pkt, socket_client)
    if thread:
      start_new_thread(self.recv_message, (socket_client, address_client, True))
    else:
      self.recv_message(socket_client, address_client, True)

#listen to the incoming packets
  @staticmethod
  def routine (self, socket_listener=None):
    if socket_listener is None:
      socket_listener = self.socket_listener
    while True:
      socket_client, address_client = socket_listener.accept()
      start_new_thread(self.recv_message, (socket_client, address_client, True))
    socket_listener.close()
  
  def recv_message(self, socket_client, address_client, limit=False):
    info = socket_client.recv(1024)

    if not info: 
      return socket_client.sendall(str(xmp(mid=random.randint(1, 65535) , code=xmp.MSG_ERR)))
    info = info.rstrip().split("*")
    # info = info.split("*")
    info = info[:-1]
    if len(info) == 0 : 
      return socket_client.sendall(str(xmp(mid=random.randint(1, 65535) , code=xmp.MSG_ERR)))
    for data in info:
      if not self.is_xmp(data):
        print ("recv_message", data)
        return socket_client.sendall(str(xmp(mid=random.randint(1, 65535) , code=xmp.MSG_ERR)))
      xmp_pkt = xmp(data=json.loads(data))
      # print ("recv_message ",  str(xmp_pkt))
      if self.top_level:
        self.do_management(xmp_pkt, socket_client, address_client)
      else:
        self.do_message(xmp_pkt, socket_client, address_client)
    socket_client.close()

# manage the xmp message
  def do_management(self, xmp_pkt, socket_client, address_client):
    # print("do_management", str(xmp_pkt))
    if xmp_pkt.code == xmp.LOOKUP:
      lookup_msg = xmp_pkt.message
      if lookup_msg.box_network_id in self.box_network_id:
        psh_msg = push_address( id=self.controler_version, box_network_id=lookup_msg.box_network_id, controler=self.box_network_id[lookup_msg.box_network_id], top=list(('127.0.0.1', self.port)) )
        self.send_message(xmp(mid=xmp_pkt.mid + 1, code=xmp.PSH_ADDR, message=psh_msg), socket_client)
      else:
        self.send_message(xmp(mid=xmp_pkt.mid + 1, code=xmp.MSG_ERR), socket_client)
    
    elif xmp_pkt.code == xmp.RGT:
      network_register_msg = xmp_pkt.message
      # The controler information is already in xmp by default
      self.box_network_id[network_register_msg.box_network_id] = network_register_msg.controler     

      for controler_addr in self.box_network_id.keys():
        self.push_data(controler_addr, self.get_socket(controler_addr))
        # psh_msg = push_address(id=self.controler_version, box_network_id=network_register_msg.box_network_id, controler=network_register_msg.controler, top=list(top_ip))
        # self.send_message(xmp(mid=random.randint(1, 65535), code=xmp.PSH_ADDR, message=psh_msg), self.get_socket(controler_addr))

      self.send_message(xmp(mid=xmp_pkt.mid + 1, code=xmp.ACK), socket_client)
      self.push_data(network_register_msg.box_network_id, socket_client)
    
    elif xmp_pkt.code == xmp.ALT_RQT:
      box_network_id = get_network(xmp_pkt.message.sip)
      print('alt_rqt ', box_network_id)
      for controler_addr in self.box_network_id.keys():
        if self.box_network_id.get(controler_addr) != self.box_network_id.get(box_network_id):
          self.send_message(xmp_pkt, self.get_socket(controler_addr))
    else:
      print ("not specify")

  def auth_sec_check(self, sip, box_ip):
    # type of authentification check
    box_network_id = get_network(sip)
    address = self.box_network_id.get (box_network_id , None)
    if address is None:
      print( "I don't have it")
      if self.port != top_ip[1]:
        lookup_msg = lookup(box_network_id=box_network_id)
        self.sr_pkt(None, xmp(mid=random.randint(1, 65535) , code=xmp.LOOKUP, message=lookup_msg), IPAddr("127.0.0.1") ,False)
        address = self.box_network_id.get (box_network_id , None)
        if address is None:
          print( "We are in deep trouble")
    # print ("auth_sec_check", box_ip, box_network_id, my_ip, self.box_network_id[box_network_id][0])
    if box_ip[1] == address[1] or box_ip[1] == my_ip[1]:
      return True
    return False

  def do_message(self, xmp_pkt, socket_client, address_client):
    # print("do_message ", str(xmp_pkt))
    if xmp_pkt.code == xmp.MSG_ERR:
      self.replay(xmp_pkt.mid, socket_client, address_client)
    elif xmp_pkt.code == xmp.PSH_ADDR:
      print("PSH_ADDR %s", str(xmp_pkt.message.box_network_id))
      if tuple(xmp_pkt.message.top) != top_ip:
        self.send_message(xmp(mid=xmp_pkt.mid + 1, code=xmp.MSG_ERR), socket_client)
      else:
        self.box_network_id[xmp_pkt.message.box_network_id] = xmp_pkt.message.controler
        # print("push")
      return
    elif xmp_pkt.code == xmp.ACK:
      print("Ack")
      return
    else:
      self.box.msgManage(xmp_pkt, (socket_client, address_client))

# checking the message received
  def is_xmp(self, xmp_msg):
    try:
      data = json.loads(xmp_msg)
      # print("%s is a dict\n", data)
    except:
      print("sorry %s not a xmp message \n", xmp_msg)
      return False
    xmp_pkt = xmp(data=data)
    return xmp_pkt.is_xmp()

  def push_data(self, controler_addr, socket_client):
    print('push_data')
    mid = random.randint(1, 65535)
    for id in self.box_network_id.keys():
      # if id != box_network_id:
      psh_msg = push_address(id=self.controler_version, box_network_id=id, controler=self.box_network_id[id], top=list(top_ip))
      # socket_client = self.c_socket(box_network_id)
      self.send_message(xmp(mid=mid + 1, code=xmp.PSH_ADDR, message=psh_msg), socket_client)

  def replay (self, xmp_pkt_id, socket_client, address_client):
    print("replay")

class permission_request():
  def __init__(self, **kwargs):
    data = kwargs.get('data')
    if data is None:
      self.proto = kwargs.get('proto', 1)
      self.sip = ip_representation(kwargs.get('sip', "0.0.0.0"))
      self.sport = kwargs.get('sport', -1)
      self.dip = ip_representation(kwargs.get('dip', "0.0.0.0"))
      self.dport = kwargs.get('dport', -1)
      self.duration = kwargs.get('duration', 10)
    else :
      self.proto = data.get('proto', 1)
      self.sip = ip_representation(data.get('sip', "0.0.0.0"))
      self.sport = data.get('sport', -1)
      self.dip = ip_representation(data.get('dip', "0.0.0.0"))
      self.dport = data.get('dport', -1)
      self.duration = data.get('duration', 10)
    # print("__init__", self.__str__())

  def __eq__(self, other):
    if not isinstance (other, permission_request): return False
    if self.proto != other.proto: return False
    if self.sip != other.sip: return False
    if self.sport != other.sport: return False
    if self.dip != other.dip: return False
    if self.dport != other.dport: return False
    if self.duration != other.duration: return False
    return True

  def __cmp__(self, other):
    return self.__eq__(self, other)

  def __ne__(self, other):
    return not self.__eq__(self, other)

  def data(self):
    return {"proto" : self.proto, "sip" : str(self.sip), "sport" : self.sport, "dip" : str(self.dip), "dport" : self.dport, "duration" : self.duration}

  def __str__(self):
    return json.dumps({'proto' : self.proto, 'sip' : str(self.sip), 'sport' : self.sport, 'dip' : str(self.dip), 'dport' : self.dport, 'duration' : self.duration})
    # return "{sip : %s, dip : %s, dport : %d, duration : %d}" % (str(self.sip), str(self.dip), self.dport, self.duration)

class permission_reply():
  def __init__(self, **kwargs):
    data = kwargs.get('data')
    if data is None:
      self.ip = ip_representation(kwargs.get('ip', "0.0.0.0"))
      self.port = kwargs.get('port', False)
      self.decision = kwargs.get('decision', False)
      self.duration = kwargs.get('duration', 30)
    else :
      self.ip = ip_representation(data.get('ip', "0.0.0.0"))
      self.port = data.get('port', 0)
      self.decision = data.get('decision', False)
      self.duration = data.get('duration', 30)   
  
  def __eq__(self, other):
    if not isinstance (other, permission_reply): return False
    if self.ip != other.ip: return False
    if self.port != other.port: return False
    if self.decision != other.decision: return False
    if self.duration != other.duration: return False
    return True

  def __cmp__(self, other):
    return self.__eq__(self, other)

  def __ne__(self, other):
    return not self.__eq__(self, other)

  def data(self):
    return {"ip" : str(self.ip), "port" : self.port, "decision" : self.decision, "duration" : self.duration}

  def __str__(self):
    return json.dumps({'ip' : str(self.ip), 'port' : self.port, 'decision' : self.decision, 'duration' : self.duration})
    # return "{decision : %d, duration : %d}" % (self.decision, self.duration)

class alert_request (permission_request):

  def __init__(self, **kwargs):
    permission_request.__init__(self, **kwargs)
    data = kwargs.get('data')
    if data is None:
      self.alertType = kwargs.get('alertType', 1)
      self.deviceIP = ip_representation(kwargs.get('deviceIP', "0.0.0.0"))
    else :
      self.alertType = data.get('alertType', 1)
      self.deviceIP = ip_representation(data.get('deviceIP', "0.0.0.0"))
  
  def __eq__(self, other):
    if not isinstance (other, alert_request): return False
    if self.proto != other.proto: return False
    if self.sip != other.sip: return False
    if self.sport != other.sport: return False
    if self.dip != other.dip: return False
    if self.dport != other.dport: return False
    if self.duration != other.duration: return False
    if self.alertType != other.alertType: return False
    if self.deviceIP != other.deviceIP: return False
    return True

  def __cmp__(self, other):
    return self.__eq__(self, other)

  def __ne__(self, other):
    return not self.__eq__(self, other)

  def data(self):
    return {"proto" : self.proto, "sip" : str(self.sip), "sport" : self.sport, "dip" : str(self.dip), "dport" : self.dport, "duration" : self.duration, "deviceIP" : str(self.deviceIP), "alertType" : self.alertType}

  def __str__(self):
    return json.dumps({'proto' : self.proto, 'sip' : str(self.sip), 'sport' : self.sport, 'dip' : str(self.dip), 'dport' : self.dport, 'duration' : self.duration, 'deviceIP' : str(self.deviceIP), 'alertType' : self.alertType})

alert_reply = permission_reply

class push_address():
  def __init__(self, **kwargs):
    data = kwargs.get('data')
    if data is None :
      self.id = kwargs.get('id', -1)
      self.box_network_id = ip_representation(kwargs.get('box_network_id', "0.0.0.0"))
      self.controler = kwargs.get('controler', ("0.0.0.0", 0))
      self.top = kwargs.get('top', top_ip)
    else:
      self.id = data.get('id')
      self.box_network_id = ip_representation(data.get('box_network_id', "0.0.0.0"))
      self.controler = data.get('controler', ("0.0.0.0", 0))
      self.top = data.get('top', top_ip)
  
  def __eq__(self, other):
    if not isinstance(other, push_address): return False
    if self.id == other.id: return False
    if self.box_network_id == other.box_network_id: return False
    if self.controler == other.controler: return False
    if self.top == other.top: return False
    return True
  
  def __cmp__(self, other):
    return self.__eq__(self, other)

  def __ne__(self, other):
    return not self.__eq__(self, other)

  def data(self):
    return {"id": self.id, "box_network_id": str(self.box_network_id), "controler": [str(self.controler[0]), self.controler[1]], "top": [str(self.top[0]), self.top[1]]}
  
  def __str__(self):
    return json.dumps({'id': self.id, 'box_network_id': str(self.box_network_id), 'controler': str(self.controler), 'top': self.top})

network_register = push_address
lookup = push_address

class xmp(packet_base):

  ACK           = 0
  MSG_ERR       = 1
  RGT	          = 2
  PERM_RQT      = 3
  PERM_RPY      = 4
  ALT_RQT       = 9
  ALT_RPY       = 10
  LOOKUP        = 13
  PSH_ADDR      = 14


  def __init__(self, **kwargs):
    self.version = 1
    data = kwargs.get('data')
    if data is None:
      self.mid = kwargs.get('mid')
      self.code = kwargs.get('code')
      self.message = kwargs.get('message')
      self.box_ip = kwargs.get('box_ip', my_ip)
    else :
      self.mid = data.get('mid')
      self.code = data.get('code')
      self.box_ip = data.get('box_ip')
      # print ("xmp",self.box_ip)
      if self.code == xmp.ACK:
        self.message = None
      elif self.code == xmp.PERM_RQT:
        self.message = permission_request(data=data.get('message'))
      elif self.code == xmp.PERM_RPY:
        self.message = permission_reply(data=data.get('message'))
      elif self.code == xmp.ALT_RQT:
        self.message = alert_request(data=data.get('message'))
      elif self.code == xmp.ALT_RPY:
        self.message = alert_reply(data=data.get('message'))
      elif self.code == xmp.RGT:
        self.message = network_register(data=data.get('message'))
      elif self.code == xmp.MSG_ERR:
        self.message = data.get('message')
      elif self.code == xmp.LOOKUP:
        self.message = lookup(data=data.get('message'))
      elif self.code == xmp.PSH_ADDR:
        self.message = push_address(data=data.get('message'))
  
  def is_xmp(self):
    if self.mid is None or self.code is None : return False
    return True
  
  def __eq__(self, other):
    if not isinstance (other, xmp): return False
    if self.version != other.version: return False
    if self.mid != other.mid: return False
    if self.code != other.code: return False
    if self.message != other.message: return False
    if self.box_ip != other.box_ip: return False
    return True
  
  def __cmp__(self, other):
    return self.__eq__(self, other)
  
  def __ne__(self, other):
    return not self.__eq__(self, other)

  def __str__(self):
    if self.message is None:
      return json.dumps({'version' : self.version, 'mid' : self.mid, 'code' : self.code, 'box_ip': [str(self.box_ip[0]), self.box_ip[1]], 'message' : self.message })
    return json.dumps({'version' : self.version, 'mid' : self.mid, 'code' : self.code, 'box_ip': [str(self.box_ip[0]), self.box_ip[1]], 'message' : self.message.data() })
