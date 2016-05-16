#!/usr/bin/python

#a lot of this code is borrowed from:
#http://eli.thegreenplace.net/2012/03/15/processing-xml-in-python-with-elementtree
#This code can be used a s a module by calling function "parse" and passing it an xml file
#as a variable

##Further development:
##Return a list of networks that satisfy
##criteria, not just the first.

import xml.etree.cElementTree as ET
import subprocess
from subprocess import Popen, call, PIPE
import os

DN = open(os.devnull, 'w')
XML = ""

def xml_write(essid, channel, bssid, packets):
   root = ET.Element("targets")
   doc = ET.SubElement(root, "network")
   ET.SubElement(doc, "essid").text = "%s" % (essid)
   ET.SubElement(doc, "channel").text = "%s" % (channel)
   ET.SubElement(doc, "bssid").text = "%s" % (bssid)
   ET.SubElement(doc, "packets").text = "%s" % (packets)
   tree = ET.ElementTree(root)
   tree.write('/home/odroid/targets/target.xml')

#Tests for signal level greater than -80dBm
def test_power(network):
   snr = network.find("snr-info")
   lastsig = int((snr.find("last_signal_dbm")).text)
   if -lastsig <= 86:
      power = 1
      return power
   else:  
      power = 0
      return power

#Tests for sufficient traffic to be worth cracking(indicative of activity)
def test_packets(network):
   packets = int((network.find("packets")).find("total").text)
   if packets >= 1:
      packets = 1
   else:
      packets = 0
   return packets

#this function tests for attached clients
#returns int if at least one client found, returns 0
#if none found.
def test_clients(network):
   if network.findall("wireless-client"):
      clients = network.findall("wireless-client")
      for clit in clients:
         clients_count = int(clit.attrib["number"])
   else:
      clients_count = 0        
   return clients_count   

#Parses element for variables necessary to focus attack 
#on a crackable wifi network. Returns list of critical
#variables for a focussed attack
def crackvar(crackme):
   crackthis = {
      'essid' : '',
      'channel' : '',
      'bssid' : '',
      'packets' : '',
   }
   SSID = crackme.find("SSID")
   essid = SSID.find("essid").text
   crackthis ['essid'] = essid
   channel = crackme.find("channel").text
   crackthis ['channel'] = channel
   BSSID = crackme.find("BSSID").text
   crackthis ['bssid'] = BSSID
   packets = int((crackme.find("packets")).find("total").text)
   crackthis ['packets'] = packets
   ##crackthis ['clients_connected'] = clients
   return crackthis
   
#main program:

#Open XML document using ET parser.
#This is the one line of code that does all the work: 
#ET.parse takes one argument and returns a parsed 
#representation of the XML document. 
def parse_names(XML): 
   tree = ET.parse(XML)
   print "xml tree:", tree
   #fetch the root element:
   root = tree.getroot()
   print "xml tree root element:", root
   #fetch root tag and attrributes
   print "root element tag:", root.tag
   print "root element attributes:", root.attrib
   rootlength = len(root)
   #print "Root element %s has %s child elements:" % (root.tag, rootlength)
   crackable_list = []
   for child in root:
      print "Child:", child
      power = test_power(child)
      print "Power:", power
      if power == 1:
         clients = test_clients(child)
         print "Clients:", clients
         if clients >=  1:
            packets = test_packets(child)
            if packets >= 1: 
               SSID = child.find("SSID")
               print "SSID:", SSID
               if SSID:
                  essid = (SSID.find("essid").text)
                  if essid: 
                     crackable_list.append(essid)     
                     print "crackable_list:", crackable_list     
   return crackable_list

def parse_deets(XML,SSID): 
   print "Focussing on wifi network:", SSID
   tree = ET.parse(XML)
   print "tree:", tree
   root = tree.getroot()
   print "root:", root
   for child in root:
      print "child:", child
      crackthis = crackvar(child)
      if crackthis['essid'] == SSID:
         clients = test_clients(child)
         crackthis['clients'] = clients
         break
      else:
         1 == 1   
   return crackthis      


