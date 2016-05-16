#!/usr/bin/python
import time
import subprocess
import os
import signal
##output string which can be used to launch focussed
##airodump-ng instance for attack
#def crackable(focus):
#   arguments = ['sudo airodump-ng', '--channel', (focus['channel']), '-essid', (focus['essid']), \
#    '--write', '/home/odroid/dump_focus', '--output-format', 'pcap', '-a','wlan1mon']  
#   index = 0
#   args = ""
#   for items in arguments:
#      args = args+" "+arguments[index]
#      index = index+1
#   return args 

##main 


#start general scan and dump of xml files into designated folder
print "Starting process airodump-ng"
g_scan = subprocess.Popen(['airodump-ng', '--output-format', 'netxml', '--write-interval', '10', '--write', '/home/odroid/xmls/dumpy', 'wlan1mon']) 
pid = g_scan.pid
print "Process g_scan has PID:", pid
print "waiting 60 secs"
time.sleep(60)

#detect creation of xmls and parse for appropriate targets

#when suitable target networks detected stop general scan
print "killing process airodump-ng"
g_scan.terminate()
try:
    os.kill(pid, 0)
    g_scan.kill()
    print "Forced kill"
except OSError, e:
    print "Terminated gracefully"

#take GPS position and plot name of wifi network on map

#start airodump focussed attack using deets parsed from xml
  #parse xml exported previously with target deets
  #create list from xml
  #run airodump with parameters from list

#when handshake detected stop focussed attack
  #not sure how to do this but possibly by parsing xmls and looking for handshake?
  #stop foccused attack of airodump

#process handshake file if required

#export processed handshake file and email to processing server

#return to top of loop and continue scanning...