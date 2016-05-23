#!/usr/bin/python

#a lot of this code is borrowed from:
#http://eli.thegreenplace.net/2012/03/15/processing-xml-in-python-with-elementtree
#This code can be used a s a module by calling function "parse" and passing it an xml file
#as a variable

##Further development:
####!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!####
##!!!! Make this an object based module: 1 for parsing and one for writing!!!!!!!!!!!##
####!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!####
##Return a list of networks that satisfy
##criteria, not just the first.

import xml.etree.cElementTree as ET
import subprocess
from subprocess import Popen, call, PIPE
import os

DN = open(os.devnull, 'w')
XML = ""

def xml_write_focus(name, PID, dest):
   root = ET.Element("process")
   ET.SubElement(root, "name").text = "%s" % (name)
   ET.SubElement(root, "PID").text = "%s" % (PID)
   tree = ET.ElementTree(root)
   tree.write(dest)

def xml_parse_focus(target):
   #print "target:", target
   tree = ET.parse(target)
   #print "tree:", tree
   root = tree.getroot()
   #print "root:", root
   for child in root:
      #print "child:", child
      essid = child.find("essid").text
      channel = child.find("channel").text
      bssid = child.find("bssid").text
      #clients_list = child.find("clients_list").text
      params = [essid, channel, bssid]
      return params

def xml_write_general(essid, channel, bssid, packets, clients, dest):
   root = ET.Element("targets")
   doc = ET.SubElement(root, "network")
   ET.SubElement(doc, "essid").text = "%s" % (essid)
   ET.SubElement(doc, "channel").text = "%s" % (channel)
   ET.SubElement(doc, "bssid").text = "%s" % (bssid)
   ET.SubElement(doc, "packets").text = "%s" % (packets)
   ET.SubElement(doc, "client_count").text = "%s" % (client_count)
   tree = ET.ElementTree(root)
   tree.write(dest)

#Tests for signal level greater than -80dBm
def test_power(network):
   snr = network.find("snr-info")
   lastsig = int((snr.find("last_signal_dbm")).text)
   if -lastsig <= 80:
      power = 1
      return power
   else:  
      power = 0
      return power

#Tests for sufficient traffic to be worth cracking(indicative of activity)
def test_packets(network):
   packets = int((network.find("packets")).find("total").text)
   return packets

#this function tests for attached clients
#returns int if at least one client found, returns 0
#if none found.
##THIS NEEDS TO BE IMPROVED TO RETURN CLIENTS MAC ADDRESSES
def test_clients(network):
   client_count = 0
   client_list = []
   if network.findall("wireless-client"):
      clients = network.findall("wireless-client")
      for clit in clients:
         client_list.append(clit.find("client-mac").text)
         client_count = int(clit.attrib["number"])        
   return client_count, client_list   

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
   return crackthis
   
#Open XML document using ET parser.
#This is the one line of code that does all the work: 
#ET.parse takes one argument and returns a parsed 
#representation of the XML document. 
def parse_names(XML): 
   tree = ET.parse(XML)
   root = tree.getroot()
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
            print "Packets:", packets
            if packets >= 4: 
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
   #print "tree:", tree
   root = tree.getroot()
   #print "root:", root
   for child in root:
   #   print "child:", child
      crackthis = crackvar(child)
      if crackthis['essid'] == SSID:
         client_count, client_list = test_clients(child)
         crackthis['client_list'] = client_list
         crackthis['client_count'] = client_count
         break  
   return crackthis      


