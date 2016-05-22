#!/usr/bin/python
import os
from subprocess import Popen, call, PIPE

DN = open(os.devnull, 'w')

def validate_handshake(target, capfile):
		"""
		<<<<<<<<borrowed heavily from wifite>>>>>>>>
			Uses cowpatty to check for a handshake.
			Returns "True" if handshake is found, false otherwise.
		"""
		# Call cowpatty to check if capfile contains a valid handshake.
		cmd = ['cowpatty',
			   '-r', capfile,  # input file
			   '-s', target,  # SSID
			   '-c']  # Check for handshake
		print "cmd =", cmd	   
		proc = Popen(cmd, stdout=PIPE, stderr=DN)
		proc.wait()
		response = proc.communicate()[0]
		print "validation result:", response
		if response.find('incomplete four-way handshake exchange') != -1:
			return False
		elif response.find('Unsupported or unrecognized pcap file.') != -1:
			return False
		elif response.find('Unable to open capture file: Success') != -1:
			return False
		return True

def strip():
	print "placeholder"
	#pyrit -r /home/odroid/hs/hs-01.cap -o /home/odroid/hs/strip strip

def analyze():
	print "placeholder"
	#pyrit -r /home/odroid/hs/hs-01.cap -o /home/odroid/hs/strip strip


