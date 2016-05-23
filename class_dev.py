#!/usr/bin/python

import os
from subprocess import Popen, call, PIPE

class validator(object):
    """A work in progress trying out classes. The validatin object is
    hopefully a good use case.
    """

    DN = open(os.devnull, 'w')

    def __init__(self, target, capfile):
        """Return a validator object"""
        self.target = target
        self.capfile= capfile

    def validate_handshake(self):
        """
        <<<<<<<<borrowed heavily from wifite>>>>>>>>
            Uses cowpatty to check for a handshake.
            Returns "True" if handshake is found, false otherwise.
        """
        # Call cowpatty to check if capfile contains a valid handshake.
        cmd = ['cowpatty',
               '-r', self.capfile,  # input file
               '-s', self.target,  # SSID
               '-c']  # Check for handshake
        print "cmd =", cmd     
        proc = Popen(cmd, stdout=PIPE, stderr=self.DN)
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

    def strip(self, outfile):
        print "Attempting to strip unnecessary packets from cap file (pyrit)..."
        cmd = ['pyrit',
               '-r', self.capfile,  # input file
               '-o', outfile,  # output file
               'strip'] #strip command 
        print "cmd =", cmd     
        proc = Popen(cmd, stdout=PIPE, stderr=self.DN)
        proc.wait()
        if os.path.exists(outfile):
            print "Strip process successful..."
            print "New cap file written to:", outfile
        else:
            print "ERROR: There was a problem stripping handshake file." 

    def analyze(self):
        print "Attempting to analyze cap file (pyrit)..."
        cmd = ['pyrit', '-r', self.capfile, 'analyze']
        print "cmd =", cmd     
        proc = Popen(cmd, stdout=PIPE, stderr=self.DN)
        proc.wait()
        hit_essid = False
        for line in proc.communicate()[0].split('\n'):
            # Iterate over every line of output by Pyrit
            if line == '' or line == None: continue
            if line.find("AccessPoint") != -1:
                hit_essid = (line.find("('" + target.ssid + "')") != -1) and \
                            (line.lower().find(target.bssid.lower()) != -1)
                #hit_essid = (line.lower().find(target.bssid.lower()))
            else:
                # If Pyrit says it's good or workable, it's a valid handshake.
                if hit_essid and (line.find(', good, ') != -1 or \
                                              line.find(', workable, ') != -1):
                    return True
        return False

check_me = validator(target, capfile)
print "check_me.target =", check_me.target
print "check_me.capfile =", check_me.capfile
print "check_me.DN =", check_me.DN
print "Validating check_me object:"
check = check_me.validate_handshake()
print "returns:", check
analyze = check_me.analyze()
print "returns:", 
check_me.strip('/home/odroid/hs/stripper.cap')
