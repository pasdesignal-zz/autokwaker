#!/usr/bin/python

import time
import subprocess
import os
import signal
import operator
import glob
import requests
import json
import sys
import getopt
import xml.etree.cElementTree as ET
from subprocess import Popen, call, PIPE
from signal import SIGINT, SIGTERM
from multiprocessing import Process, Pipe
from validate import validator
from scanner import scanner
#from watchdog.events import PatternMatchingEventHandler  
#from watchdog.observers import Observer
from xml_arse import xml_machine

##!!!!!!!!Remeber Vivet Ramachandra said that the incomplete handshake captures fail unless tidied up!!!!!!!!! This is why verifications are failing...

#file locations 
##These should be improved to be located in temp files and then cleaned up afterwards
target_dir = '/home/odroid/targets/'
output_dir = '/home/odroid/xmls/'
handshake_dir = '/home/odroid/hs/'
cracked_dir = '/home/odroid/cracked/'

if __name__ == '__main__':
	try: 
		#use hs capture with maybe only two packets or known good capture and test why not getting positive results......
		valid = validator(SSID=('FLACserve'), 				#add correct variables here
		BSSID=('48:5B:39:12:9C:9B'), 		#add correct variables here
		capfile=(handshake_dir+'test.cap'))		#add correct variables here
		print "Stripping handshake cap file of unnecessary packets"
		valid.strip(handshake_dir+'test_strip.cap')
		valid_strip = validator(SSID=('FLACserve'), 				#add correct variables here
		BSSID=('48:5B:39:12:9C:9B'), 		#add correct variables here
		capfile=(handshake_dir+'test_strip.cap'))		#add correct variables here
		valid_strip.validate_handshake()
		print "Validation result of handshake capture:", valid_strip.validation_result
		valid_strip.analyze()
		print "Analysis result of handshake capture:", valid_strip.analyze_result
#when handshake detected stop focussed attack			
		if valid_strip.validation_result or valid_strip.analyze_result == True:			
			print "Handshake captured, my job here is done..."	
	except KeyboardInterrupt:
		print "manually interrupted!"
		tidy()
#export processed handshake file and email to processing server
#return to top of loop and continue scanning...