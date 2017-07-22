#!/usr/bin/python

import os
import time
from subprocess import Popen, call, PIPE
from termcolor import colored

#print colored('hello', 'red'), colored('world', 'green')

#Improvements:
#This code needs to be refined and improved. a lot copied here from wifite project..
#add creds for wifite writer

class validator(object):
    
    DN = open(os.devnull, 'w')

    def __init__(self, SSID, BSSID, capfile):
        """Return a validator object"""
        self.SSID = SSID
        self.BSSID = BSSID
        self.capfile = capfile
        #self.validate_handshake()
        #self.analyze()

    def validate_handshake(self):
        """
        <<<<<<<<borrowed heavily from wifite>>>>>>>>
            Uses cowpatty to check for a handshake.
            Returns "True" if handshake is found, false otherwise.
        """
        # Call cowpatty to check if capfile contains a valid handshake.
        print color("Analysing file for EAPOL handshake packets (cowpatty)", 'yellow')
        cmd = ['cowpatty',
               '-r', self.capfile,      # input file
               '-s', self.SSID,         # SSID
               '-c',                    # check for handshake
               '-v']                    # verbose mode    
        proc = Popen(cmd, stdout=PIPE, stderr=self.DN)
        proc.wait()
        response = proc.communicate()[0]
        print colored("Handshake search result:", 'green'), colored(response, 'green')    #using colouring for important messages
        if response.find('incomplete four-way handshake exchange') != -1:
            response = False
        elif response.find('Unsupported or unrecognized pcap file.') != -1:
            response = False
        elif response.find('Unable to open capture file: Success') != -1:
            response = False
        if response != False:
            self.validation_result=True
            return
        cmd.append('-2')                  #switch to enable "non-strict" validation
        proc = Popen(cmd, stdout=PIPE, stderr=self.DN)
        proc.wait()
        response = proc.communicate()[0]
        if response.find('incomplete four-way handshake exchange') != -1:
            response = False
        elif response.find('Unsupported or unrecognized pcap file.') != -1:
            response = False
        elif response.find('Unable to open capture file: Success') != -1:
            response = False
        if response != False:
            self.validation_result=True
            return
        self.validation_result=False

    def strip(self, outfile):
        ####!!!!!This could be done in "strip-live" mode?? faster, less problems??? 
#Strips cap file down to bare essential packets, uses pyrit
        print color("Attempting to strip unnecessary packets from cap file (pyrit)", 'yellow')
        cmd = ['pyrit',
               '-r', self.capfile,  # input file
               '-o', outfile,  # output file
               'strip'] #strip command 
        print color("DEBUG: cmd =", 'red'), color(cmd, 'red')     
        proc = Popen(cmd, stdout=PIPE, stderr=self.DN)
        proc.wait()
        if os.path.exists(outfile):
            print "Strip process successful..."
            print "New cap file written to:", outfile
        else:
            print color("ERROR: There was a problem stripping handshake file.", 'red')

    def analyze(self):
        ####!!!! This needs work, not working yet.........!!!!!!!!!
#Analyze cap file for valid handshake capture using pyrit
#Heavily borrowed from wifite
        print color("Analysing file for EAPOL handshake packets (pyrit)", 'yellow')
        cmd = ['pyrit', '-r', self.capfile, 'analyze']
        #print "cmd =", cmd                 #debug   
        proc = Popen(cmd, stdout=PIPE, stderr=self.DN)
        proc.wait()
        hit_essid = False
        for line in proc.communicate()[0].split('\n'):
            # Iterate over every line of output by Pyrit
            print color(line, 'green')     #debug
            if line == '' or line == None: continue
            if line.find("AccessPoint") != -1:
                hit_essid = (line.find("('" + self.SSID + "')") != -1) and \
                            (line.lower().find(self.BSSID.lower()) != -1)
                #hit_essid = (line.lower().find(target.bssid.lower()))
                #print "1 hit_essid:", hit_essid
            else:
                # If Pyrit says it's good or workable, it's a valid handshake.
                if hit_essid and (line.find(', good, ') != -1 or \
                                              line.find(', workable, ') != -1):
                    #print "2 hit_essid:", hit_essid
                    self.analyze_result =True
                    return
        self.analyze_result=False

#check_me = validator(target, capfile)
#print "check_me.target =", check_me.target
#print "check_me.capfile =", check_me.capfile
#print "check_me.DN =", check_me.DN
#print "Validating check_me object:"
#check = check_me.validate_handshake()
#print "returns:", check
#analyze = check_me.analyze()
#print "returns:", 
#check_me.strip('/home/odroid/hs/stripper.cap')
