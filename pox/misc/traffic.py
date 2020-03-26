import scapy.all as scapy
import sys, ipaddress, argparse, time, random, socket, select

def get_arguments():
  parser = argparse.ArgumentParser()
  parser.add_argument("-i", "--source", dest="source", help="Source IP")
  parser.add_argument("-t", "--target", dest="target", help="Target IP/IP Range")
  parser.add_argument("-p", "--port", help="Port to analyse", default=80)
  parser.add_argument("-o", "--duration", help="Duration between two communication", default=5)
  parser.add_argument("-r", "--retry", help="The retry", default=1)
  parser.add_argument("-s", "--size", help="The traffic size", default=200)
  parser.add_argument("-u", "--proto", help="The protocol", default=6)
  parser.add_argument("-d", "--delay", help="Delay before the start", default=0)
  options = parser.parse_args()
  return options


def gen_traffic (src_ip, protocol, ip, port, timeout, size):
  if not isinstance(ip, list):
    ip = scapy.Net(ip)
    ip_list = [p for p in ip]
  else:
    ip_list = ip

  if protocol == 6:
    protocol = socket.SOCK_STREAM
  else:
    protocol = socket.SOCK_DGRAM

  # s = socket.socket(socket.AF_INET, protocol)
  # s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
  # s.settimeout(timeout)
  # s.setblocking(1)
  answer = []
  data = size * 'C'
  str_time = time.time()
  # for addr in ip_list:
  sport = random.randint(1024,65535)
  s = socket.socket(socket.AF_INET, protocol)
  s.bind( (src_ip, sport) )
  for i in range(len(ip_list)):
    if protocol == socket.SOCK_STREAM:
      s.connect((ip_list[i], port))
      s.sendall(data.encode())
    else:
      s.sendto(data.encode(), (ip_list[i] ,port))

    found = '0'
    get = select.select([s], [], [], timeout)
    if get[0]:
      found = '1'
      end_time = time.time()
      # print (i, " ", len(ip_list), i < len(ip_list) - 1)
      if len(ip_list) > 1 and i < len(ip_list) - 1:
        # print("timeout")
        time.sleep(timeout)
      else :
        time.sleep(timeout/10)
    else:
      end_time = time.time() - timeout
    answer.append( (end_time - str_time, found) )
  
  s.close()
  clients_list = []
  for elt in range(len(ip_list)):
    client_dict = {"time": str(answer[elt][0]), "ip": ip_list[elt], "traffic-answer": answer[elt][1], "traffic-non-ans": answer[elt][1]}
    clients_list.append(client_dict)
  return clients_list

def recv(socket_client, address_client):
  data = socket_client.recv(2048)
  if data:
    socket_client.send(data)
  socket_client.close()

def traffic(ip, port, timeout, size, proto):
  if not isinstance(ip, list):
    ip = scapy.Net(ip)
    ip_list = [p for p in ip]
  else:
    ip_list = ip

  request = []
  data = size * 'X'
  sport = random.randint(1024,65535)
  for addr in ip_list:
    if proto == 6:
      request.append( scapy.IP(dst=addr)/scapy.TCP(sport=sport, dport=port)/data )
    else :
      request.append( scapy.IP(dst=addr)/scapy.UDP(sport=sport, dport=port)/data )

  answer = []
  # for r in request:
  ans, non_ans = scapy.sr(request, timeout=timeout, inter=timeout, verbose=True)
  answer.append((ans,non_ans))
  # print("ans", ans.show())
  # print("non ans", non_ans.show())
  # print (len(ans), len(non_ans))
  
  clients_list = []
  for pkt in ans:
    # for i in pkt:
    #   print (i.sent_time - i.time, i.dst)
    # print(pkt[0].sent_time - pkt[0].time, pkt[0].dst)
    client_dict = {"time": str(pkt[0].sent_time - pkt[0].time), "ip": pkt[0].dst, "traffic-answer": '1', "traffic-non-ans": '0'}
    clients_list.append(client_dict)
  
  for pkt in non_ans:
    # print(pkt.sent_time - pkt.time, pkt.dst)
    client_dict = {"time": str(pkt.sent_time - pkt.time), "ip": pkt.dst, "traffic-answer": '0', "traffic-non-ans": '1'}
    clients_list.append(client_dict)

  return clients_list

def print_result(results_list):
  # print("Time\t\t\tIP Address\t\t\tfound")
  # print("-----------------------------------------------------------------------------")
  for client in results_list:
    # print(client["time"] + "\t" + client["ip"] + "\t" + client["traffic"])
    print(client["time"] + "\t" + client["ip"] + "\t" + client["traffic-answer"]+ "\t" + client["traffic-non-ans"])

if __name__ == '__main__':
  start = time.time()
  options = get_arguments()
  ip_list = []
  for i in range(int(options.retry)):
    ip_list.append(options.target)
  delay = int(options.delay)
  if delay != 0:
    time.sleep(delay)
  else:
    time.sleep(random.uniform(6, 20))

  ans = gen_traffic(str(options.source), int(options.proto), ip_list, int(options.port), int(options.duration), int(options.size))

  # ans = traffic(ip_list, int(options.port), int(options.duration), int(options.size), int(options.proto))
  print_result(ans)
  print ("end", time.time() - start)