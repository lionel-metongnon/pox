# from scapy.all import *

# def main ():
#   parser = argparse.ArgumentParser()
#   parser.add_argument("-i", "--address", help="addresses ip", default='10.0.0.1')
#   parser.add_argument("-r", "--range", help="addresses range", default=10)
#   parser.add_argument("-p", "--ports", help="Port to analyse", default=[80])
#   args = parser.parse_args()

#   start_ip = int( ipaddress.IPv4Address(args.address) )
#   end_ip = start_ip + int(args.range)
  
#   for ip_int in range(int(start_ip), int(end_ip)):
#     a = sr1( IP(dst="www.slashdot.org")/ICMP()/"XXXXXXXXXXX")
#     # a = sr1( IP(dst=str(ipaddress.IPv4Address(ip_int)))/ICMP()/"XXXXXXXXXXX")
#     # a = sr1(IP(dst="192.168.5.1")/UDP()/DNS(rd=1,qd=DNSQR(qname="www.slashdot.org")))
#     print(a)
#     a.show()

# if __name__ == '__main__':
#     main()

import scapy.all as scapy
import sys, ipaddress, argparse, time, random

# def get_arguments():
#     parser = argparse.ArgumentParser()
#     parser.add_argument("-t", "--target", dest="target",
#                         help="Target IP/IP Range")
#     options = parser.parse_args()
#     return options

# def scan(ip):
#     arp_request = scapy.ARP(pdst=ip)
#     broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
#     arp_request_broadcast = broadcast/arp_request
#     answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]

#     clients_list = []
#     for element in answered_list:
#         client_dict = {"ip": element[1].psrc, "mac": element[1].hwsrc}
#         clients_list.append(client_dict)
#     return clients_list

# def print_result(results_list):
#     print("IP\t\t\tMAC Address")
#     print("----------------------------------------------------")
#     for client in results_list:
#         print(client["ip"] + "\t\t" + client["mac"])

# options = get_arguments()
# scan_result = scan(options.target)
# print_result(scan_result)

def get_arguments():
  parser = argparse.ArgumentParser()
  parser.add_argument("-t", "--target", nargs='+', dest="target", help="Target IP/IP Range")
  parser.add_argument("-p", "--port", help="Port to analyse", default=80)
  parser.add_argument("-o", "--timeout", help="Timeout", default=5)
  parser.add_argument("-d", "--delay", help="Delay before the start", default=0)
  options = parser.parse_args()
  return options

def scan(ip, port, timeout):
  # startTime = time.time()
  if not isinstance(ip, list):
    ip = scapy.Net(ip)
    ip_list = [p for p in ip]
  else:
    ip_list = ip

  request = []
  for addr in ip_list:
    request.append(scapy.IP(dst=addr)/scapy.ICMP())#scapy.UDP(dport=port)

  # for r in request:
    # ans, unans = scapy.sr(r, timeout=timeout, retry=0, verbose=False)
    # answer.append((ans, unans))
  ans, non_ans = scapy.sr(request, timeout=timeout, inter=timeout, retry=0, verbose=False)
  # print ('Time taken:', time.time() - startTime)
  clients_list = []
  
  for pkt in ans:
    client_dict = {"time": str(pkt[0].sent_time - pkt[0].time), "ip": pkt[0].dst, "found": '1'}
    clients_list.append(client_dict)
  
  for pkt in non_ans:
    client_dict = {"time": str(pkt[0].sent_time - pkt[0].time), "ip": pkt[0].dst, "found": '0'}
    clients_list.append(client_dict)

  return clients_list

def print_result(results_list,):
  # print("Time\t\t\tIP Address\t\t\tfound")
  # print("-----------------------------------------------------------------------------")
  for client in results_list:
      print(client["time"] + "\t" + client["ip"] + "\t" + client["found"])

if __name__ == '__main__':
  options = get_arguments()

  delay = int(options.delay)
  if delay != 0:
    time.sleep(delay)
  else:
    time.sleep(random.uniform(6, 20))

  results_list = scan(options.target, int(options.port), int(options.timeout))
  print_result(results_list)