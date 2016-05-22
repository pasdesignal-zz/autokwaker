#!/usr/bin/python

import time
import subprocess
import os
import signal
import xml.etree.cElementTree as ET
from subprocess import Popen, call, PIPE
from signal import SIGINT, SIGTERM
from xml_arse import xml_parse_focus
from multiprocessing import Process, Pipe
##improvements:
##create temp folders that dont exist make folders that don't exist automatically
##
##xml_write class so that parameters can be adjusted
##

target = '/home/odroid/targets/target.xml'
output_file = '/home/odroid/xmls/'
DN = open(os.devnull, 'w')
handshake = '/home/odroid/hs/'

##This could be made to be WAAAAAAAY more efficient.....
def tidy():
	directory=output_file
	files_xml = os.listdir(directory)
	print "removing existing xmls files:", files_xml
	for file in  files_xml:
		try:
			os.remove(directory+"/"+file)        
		except OSError:
			pass
	directory = '/home/odroid/targets'
	files_targets= os.listdir(directory)
	print "removing existing target files:", files_targets
	for file in  files_targets:
		try:
			os.remove(directory+"/"+file)        
		except OSError:
			pass
	directory = handshake
	files_handshake= os.listdir(directory)
	print "removing existing handshake files:", files_handshake
	for file in  files_handshake:
		try:
			os.remove(directory+"/"+file)        
		except OSError:
			pass

def check_pid(pid):        
	""" Check For the existence of a unix pid. """
	try:
		os.kill(pid, 0)
	except OSError:
		return False
	else:
		return True
	
def send_interrupt(process, PID):
	"""
		Sends interrupt signal to process's PID.
	"""
	print "attempting to kill process...."
	print process.pid
	try:
		process.terminate()
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

def remove_file(filename):
	"""
		Attempts to remove a file. Does not throw error if file is not found.
	"""
	try:
		os.remove(filename)
	except OSError:
		pass

#general scan looking for likely networks
#when suitable target networks detected stop general scan
def g_scan(channel=0, iface='wlan1mon', conn=0):
		print "Starting process airodump-ng"
		command = ['airodump-ng','-a', '--output-format', 'netxml', '--write-interval', '10', '-w', output_file]
		if channel != 0:
			command.append('-c')
			command.append(str(channel))
		command.append(iface)
		print "Using command:", command 
		proc = Popen(command, stdout=DN, stderr=DN)
		PID = proc.pid
		print "Airodump PID:", PID
		time_started = time.time()
		print "time_started:", time_started
		while True:
			time.sleep(1)
			scanning = airodump_child_conn.recv()    
			print "airodump child scanning:", scanning
			if scanning == False:
				print "Attempting to kill process airodump:", PID
				send_interrupt(proc, PID)	
				break			
		
#focussed scan targetting likely network
def f_scan(params, iface='wlan1mon', conn=0):
	# call focussed airodump-ng scan on target network
	print "focussing on wifi network:", params[0]
	print params[1]
	print params[2]
	print "Starting process f_airodump-ng"
	command = ['airodump-ng', '--output-format', 'netxml', '--write-interval', '10', '-w', handshake]
	command.append('--essid')
	command.append(str(params[0]))
	command.append('--channel')
	command.append(str(params[1]))
	command.append('--bssid')
	command.append(str(params[2]))
	command.append(iface)
	print "Using command:", command 
	proc = Popen(command, stdout=DN, stderr=DN)
	PID = proc.pid
	print "f_scan PID:", PID
	time_started = time.time()
	print "time_started:", time_started
	while True:
		time.sleep(1)
		f_scanning = f_airodump_child_conn.recv()    
		print "f_scan child scanning:", scanning
		if f_scanning == False:
			print "Attempting to kill process f_airodump-ng:", PID
			send_interrupt(proc, PID)	
			break	

def watch_this(conn=0):
	print "Starting watchdoggy.py"
	command = ['python', 'watchdoggy.py','/home/odroid/xmls',]
	print "command:", command
	watching = subprocess.Popen(command)
	PID = watching.pid
	print "Watchdog PID:", PID
	time_started = time.time()
	print "time_started:", time_started
	while True:
		time.sleep(1)
		scanning = watchdog_child_conn.recv()
		print "watchdog child scanning:", scanning
		if scanning == False:
			print "Attempting kill process watchdog:", PID
			send_interrupt(watching, PID)	
			break		

if __name__ == '__main__':
	airodump_parent_conn, airodump_child_conn = Pipe()
	watchdog_parent_conn, watchdog_child_conn = Pipe()
	print "Housekeeping..."
	tidy()
	print "Creating process for general scan"
	airodump = Process(target=g_scan, args=(0, 'wlan1mon', airodump_child_conn,))
	print  "Creating process for watchdog"
	watchdog = Process(target=watch_this, args=(watchdog_child_conn,))
	print "Attempting to start general scan...."
	airodump.start()
	scanning = True
	time_started = time.time()
	print "time_started:", time_started
	print "Attempting to start watchdog..." 
	watchdog.start()
	while True:
		time.sleep(1)
		airodump_parent_conn.send(scanning)
		watchdog_parent_conn.send(scanning)
		print "parent scanning:", scanning
		print time.time() - time_started
		if time.time() - time_started >= 30:
			print "times up, aborting general scan bitches..."	
			scanning = False
			break
		if os.path.exists(target):
			print "targets detected, aborting general scan bitches..."
			scanning = False
			parameters = xml_parse_focus(target)
			break	   
	airodump_parent_conn.send(scanning)
	watchdog_parent_conn.send(scanning)
	print "parent scanning:", scanning
	airodump_parent_conn.close()
	watchdog_parent_conn.close()
	time.sleep(2)

#take GPS position and plot name of wifi network on map
#To be writted here.....

#start airodump focussed attack using deets parsed from xml
#parse xml exported previously with target deets
#create list from xml
#run airodump with parameters from list
	if os.path.exists(target):
		parameters = xml_parse_focus(target)
		print "Suitable network detected:"
		print "parameters:", parameters
		f_airodump_parent_conn, f_airodump_child_conn = Pipe()
		f_airodump = Process(target=f_scan, args=(parameters, 'wlan1mon', airodump_child_conn,))
		print "Attempting to start focussed attack..."
		scanning = True
		f_airodump.start()
		time_started = time.time()
		print "time_started:", time_started
		while True:
			time.sleep(1)
			f_airodump_parent_conn.send(scanning)
			print "parent scanning:", scanning
			print time.time() - time_started
			if time.time() - time_started >= 60:
				print "times up, aborting focussed scan bitches..."	
				scanning = False
				f_airodump_parent_conn.send(scanning)	
				print "parent scanning:", scanning
				f_airodump_parent_conn.close()
				time.sleep(2)
				break			
	else:
		print "No suitable networks detected"
	print "up to here..."
	


#when handshake detected stop focussed attack
  #not sure how to do this but possibly by parsing xmls and looking for handshake?
  #stop foccused attack of airodump

#process handshake file if required

#export processed handshake file and email to processing server

#return to top of loop and continue scanning...