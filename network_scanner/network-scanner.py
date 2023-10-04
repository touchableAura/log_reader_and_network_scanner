import socket
import struct
import sys
from scapy.all import *

print("********* ICMP / TCP NETWORK SCANNER *******\n")

# user interface
# Prompt the user for the scanning mode
scan_mode = input("Now, choose a scanning mode (ICMP or TCP): ").strip().lower()

# Check if the user input is valid
if scan_mode not in ["icmp", "tcp"]:
    print("Invalid scanning mode. Please choose either ICMP or TCP.")
else:



########################################################################
########################################################################
# ICMP Mode: IP Scanner ################################################
########################################################################
########################################################################
    if scan_mode == "icmp":
        print("\n************  ICMP Mode Started ************\n")
        ip_input = input("Enter IP Address to for ICMP Scan:\na) default (192.168.0.1 - 192.168.0.24)\nb) custom (user input - user input)\nEnter 'a' or 'b': ")
        if ip_input not in ["a", "b"]:
            print("Invalid entry, please enter 'a' or 'b'.")
        else:
            if ip_input == "a":
                start_ip = "192.168.0.1"
                end_ip = "192.168.0.24"
                print(f"\nsending pings from {start_ip} to {end_ip}")
            elif ip_input == "b":
                start_ip = input("Enter start IP address:\n")
                end_ip = input("Enter end IP address:\n")
                print(f"\nsending pings from {start_ip} to {end_ip}")

            # Convert the start and end IP addresses to integers
            start_ip_int = struct.unpack("!I", socket.inet_aton(start_ip))[0]
            end_ip_int = struct.unpack("!I", socket.inet_aton(end_ip))[0]

            # Initialize an empty list to store the responding IP addresses
            responding_ips = []
            print("\n\n * * ICMP SCAN START* * * * *** ** * *********\n")

            # Loop through the IP range and send ICMP echo requests
            for ip_int in range(start_ip_int, end_ip_int + 1):
                ip_address = socket.inet_ntoa(struct.pack("!I", ip_int))
                #########################################################
                # Packet crafting   #####################################
                icmp_pkt = IP(dst=ip_address) / ICMP()
                #########################################################
                # Transmission      #####################################
                response, _ = sr(icmp_pkt, timeout=2, verbose=False)
                # Check if a response was received
                if response:
                    print(f"Response received from {ip_address}")
                    responding_ips.append(ip_address)

            print("\n\n * * ICMP SCAN END* * * * ****** ** * *********\n")

            # Print the list of responding IP addresses in the summary
            print("\nSummary of ICMP Scan")
            print(f"IP Address range scanned: {start_ip} - {end_ip}")
            response_count = len(responding_ips)
            print(f"Number of responses: {response_count}")
            ############################################################
            # Output            ########################################
            print(f"List of responses:")
            for ip_address in responding_ips:
                print(ip_address)  # Print each IP address directly

        print("\n* * ** PROGRAM FINISHED * * * PROGRAM FINISHED ***\n")
        sys.exit(0)



########################################################################
########################################################################
# TCP Mode: Port Scanner ###############################################
########################################################################
########################################################################
    if scan_mode == "tcp":
        print("\n*************  TCP Mode Started *************\n")
        # Choose IP Address
        ip_address = input("Enter IP Address:\na) demo (45.33.32.156)\nb) default (192.168.0.1)\nc) custom (user input)\nenter: 'a', 'b' or 'c' and hit 'return:'")
        ip_input = ""

        if ip_address == "a":
            ip_input = "45.33.32.156"
            print(f"\nuser selected: {ip_input}\n")
            # ports to scan
            dport_input = input("Enter port number(s) to scan:\na) default (1,1024)\nb) custom (user input)")
            if dport_input == "a":
                port_input = 1,1024
                print(f"\nscanning port(s): {port_input}\n")
            elif dport_input == "b":
                port_input = input("Enter port number(s): \n")
                print(f"\nuser selected: {port_input}\n")
            elif dport_input == "c":
                port_input = "not available right now"
        elif ip_address == "b":
            ip_input = "192.168.0.1"
            print(f"\nuser selected: {ip_input}\n")
            # ports to scan
            dport_input =  input("Enter port number(s) to scan:\na) default (1,1024)\nb) custom (user input)\n")
            if dport_input == "a":
                port_input = 1,1024
                print(f"\nscanning port(s): {port_input}\n")
            elif dport_input == "b":
                port_input = input("Enter port number(s)")
                print(f"\nuser selected: {port_input}\n")
            elif dport_input == "c":
                port_input = "not available right now"
        elif ip_address == "c":
            ip_input = input("Enter custom IP Adress:\n")
            print(f"\nuser selected: {ip_input}\n")
            # ports to scan
            dport_input =  input("Enter port number(s) to scan:\na) default (1,1024)\nb) custom (user input)\n")
            if dport_input == "a":
                port_input = 1,1024
                print(f"\nscanning port(s): {port_input}\n")
            elif dport_input == "b":
                port_input = input("Enter port number(s)")
                print(f"\nuser selected: {port_input}\n")
            elif dport_input == "c":
                port_input = "not available right now"
        print(f"sending TCP SYN packets to port(s): {port_input} at ip address: {ip_input}\n")
    #####################################################################
    # Packet crafting   #################################################
    tcp_pkts = IP(dst=ip_input) / TCP(sport=RandShort(), dport=(1, 1024), flags="S")
  
    #####################################################################
    # Transmission      #################################################
    print("\n\n\n * * * ans, unans = sr(tcp_pkts, timeout=20, retry=2) *****sr()** TRANSMISSION ***\n")
    ans, unans = sr(tcp_pkts, timeout=20, retry=2)

    #####################################################################
    # Output ############################################################
    # Initialize a set to store unique responses
    unique_responses = set()

    # Loop through the responses and add unique IP addresses and port numbers to the set
    for s, r in ans:
        unique_responses.add((r[IP].src, r[TCP].dport))

    # Print the unique responses 
    print("\n\n * * *  IPADDRRESS:PORT * * * RESPONSES * ****\n")
    print("OUTPUT ~ ipaddress:port# \nresponses from TCP SYN packets:\n")
    for response in unique_responses:
        print(f"{response[0]}:{response[1]}")
    print("\n * * TCP SCAN * * * * COMPLETE ********* * * * * * *\n")

    # Print summary
    print(f"\nSummary for TCP Scan\nIP Address: {ip_input}\nPort(s): {port_input}")
    print(f"Total Responses: {len(unique_responses)}")
    print("\n* * ** PROGRAM FINISHED * * * PROGRAM FINISHED ***n\n")








    # un/comment to see example of TCP packet
    # print("example TCP packet contents\n")
    # tcp_pkts.show()





