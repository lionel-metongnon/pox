# List of the box
#
# Based on of_tutorial by James McCauley
from pox.misc.utils import *

import time, sched, copy, ipaddress

class Permission(object):
  def __init__(self, flowHeader, answer, duration):
    self.flowHeader = flowHeader
    self.answer = answer
    self.duration = duration
    self.timestamp = time.time()

  def __eq__(self, other):
    if not isinstance (other, Permission): return False
    if self.flowHeader != other.flowHeader: return False
    if self.answer != other.answer: return False
    if self.duration != other.duration: return False
    if self.timestamp != other.timestamp: return False
    return True

  def __cmp__(self, other):
    return self.__eq__(self, other)

  def __ne__(self, other):
    return not self.__eq__(self, other)

class List(object):
  
  def __init__(self):
    self.list = {}

  def add(self, key, obj):
    if isinstance(key, list) and isinstance(obj, list) and len(key) == len(obj):
      for i in range(len(key)):
        self.list[key[i]] = obj[i]
    self.list[key] = obj
  
  def exists(self, key):
    return key in self.list

  def get(self, key):
    return self.list[key]

  def delete(self, key):
    # print("received key: ", str(key), len(self.list))
    # for i in self.list.keys():
    #   print(i)
    if self.exists(key):
      del self.list[key]

## List of permissions with flowheader for the key and Permission for object
PermissionList = List
POLICY_UNDER_TIME = 30
POLICY_DOING_TIME = 60

class Policy(object):
  DEFAULT_POLICY = {'whiteList':[], 'permission':{'duration' : 10}, 'under-dos':{'duration' : POLICY_UNDER_TIME}, 'doing-dos':{'duration' : POLICY_DOING_TIME}, 'under-scan':{'duration' : POLICY_UNDER_TIME}, 'doing-scan':{'duration' : POLICY_DOING_TIME}, 'under-ddos':{'duration' : POLICY_UNDER_TIME}, 'doing-ddos':{'duration' : POLICY_DOING_TIME}}
  def __init__(self, deviceIP, policyList):
    self.deviceIP = deviceIP
    self.policyList = policyList

  def __eq__(self, other):
    if not isinstance (other, Policy): return False
    if self.deviceIP != other.deviceIP: return False
    if self.policyList != self.policyList: return False
    return True

  def __cmp__(self, other):
    return self.__eq__(self, other)

  def __ne__(self, other):
    return not self.__eq__(self, other)

## List of policy with the object IP for the key and Policy for object
class PolicyList (List):
  def get(self, key):
    data =  self.list.get (key, None)
    if data is None:
      return Policy(key, Policy.DEFAULT_POLICY)
    else:
      return data

class Alert(object):
  PERMISSION = 0
  DOS = 1
  DDOS = 2
  SCAN = 3
  REFLEXION = 4

  def __init__(self, deviceIP, flowHeader, alertType, flow=None):
    self.deviceIP = deviceIP
    self.flowHeader = flowHeader
    self.alertType = alertType
    self.flow = flow

  def __eq__(self, other):
    if not isinstance (other, Alert): return False
    if self.deviceIP != other.deviceIP: return False
    if self.flowHeader != other.flowHeader: return False
    if self.alertType != other.alertType: return False
    return True

  def __cmp__(self, other):
    return self.__eq__(self, other)

  def __ne__(self, other):
    return not self.__eq__(self, other)

class AlertList(List):
  """ List of alert with the object IP for the key and Alert for object
  """
  def isMine(self, key):
    if key not in self.list:
      return False
    obj = self.list[key]
    if key == obj.flowHeader.sip:
      return True
    return False
