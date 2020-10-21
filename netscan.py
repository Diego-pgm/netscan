#!/usr/bin/env python3

import scapy.all as scapy
import argparse

"""
Program to search for a device or devices in the network we are connected to.

"""

def scan(ip):
	"""
	This function creates an arp request (who-has) certain ip, sends packets and recieves them 
	and get all the responses of the devices with the ip and stores it into a dictionary
	that its stored in a list.

	Parameters
	------------
	ip : string
		Ip/ip range to search
	
	Returns
	-----------
	list
		list of dictionaries with the ip and mac of the responses.

	Call the function scan(10.0.0.1/24) to search for all the ips in the range 10.0.0.1/10.0.0.255
	"""

	arp_request = scapy.ARP(pdst=ip)
	broadcast = scapy.Ether(dst='ff:ff:ff:ff:ff:ff')
	arp_request_broadcast = broadcast/arp_request
	answered_list = scapy.srp(arp_request_broadcast, timeout=1)[0]
	clients_list = []
	for elem in answered_list:		
		clients_dict = {'ip':elem[1].psrc, 'mac':elem[1].hwsrc}
		clients_list.append(clients_dict)
	return clients_list


def print_results(clients_list):
	"""
	Prints all the ips and mac that are stored in the clients_list given from the function scan()

	Parameters
	-------------
	clients_list : list

	It prints the values for the keys "ip" and "mac" in the dictionaries stored in clients_list
	"""
	print('IP\t\t\tMAC ADDRESS-------------------------------\n')
	for elem in clients_list:
		print(elem['ip']+"\t\t"+elem['mac'])
	
def get_arguments():
	"""
	Returns a string for an ip or an ip range
	
	Returns
	------------
	string: (ip range)

	Error
	-------------
	Throws an error if the ip is not specified correctly

	"""
	parser = argparse.ArgumentParser(description='Specify the interface and the new MAC address')
	parser.add_argument('-t', '--target', dest='target', help='Ip or ip range to search for')
	options = parser.parse_args()
	if not options.target:
		parser.error('[-] Please specify a valid ip-ip range, use --help for more info')
	return options

	
options = get_arguments()	
clients_list = scan(options.target) 
print_results(clients_list)
