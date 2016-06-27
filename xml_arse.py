#!/usr/bin/python

import xml.etree.cElementTree as ET
import subprocess
from subprocess import Popen, call, PIPE
import os

###Improvements:
##Make this class handle an invalid xml file......
##make methods of loading and saving "cracked" APs to/from 
##dict data structure to/from XML file

###Return an xml manipulator object###
#requires string variable which should be path to xml file to open/parse
class xml_machine(object):
	 
	 ##Class attributes go here

	def __init__(self, input_xml):

#Open XML document using ET parser.
#ET.parse takes one argument and returns a parsed 
#representation of the XML document.
##!!!!!Make this tolerate a invalid XML somehow!!!!!!!!!!@######## 
		self.input_xml = input_xml
		#print "Opening XML:", self.input_xml				#debug
		self.tree = ET.parse(self.input_xml)
		#print "tree:", self.tree  							#debug
		self.root = self.tree.getroot()
		#print "root:", self.root 							#debug
		self.rootlength = len(self.root)
		#print "XML file %s Root element %s has %s child elements:" % (self.input_xml, self.root.tag, self.rootlength)
		self.name = 'none'
		self.channel = 0
		self.bssid = 'none'
		self.packets = 0
		self.client_list = []
		self.client_count = 0

###Return a list of "crackable" networks within an airodump-ng xml dump###
	def crackables(self): 
		crackable_list = []
		for child in self.root:
			power = self.test_power(child)
			if power == 1:
				clients = self.test_clients(child)
				if clients >=  1:
					packets = self.test_packets(child)
					if packets >= 2: 
						SSID = child.find("SSID")
						if SSID:
							essid = (SSID.find("essid").text)
							if essid: 
								crackable_list.append(essid)   
		return crackable_list

##returns dict of properties/deets of wifi network parsed as element child from XML file
##requires string "SSID" which is name of target network essid
	def parse_deets(self, SSID):
		print "focussing on network SSID:", SSID  		#debug
		for child in self.root:
			_SSID = child.find("SSID")
			if _SSID:
				_SSID_essid = (_SSID.find("essid").text)
				if _SSID_essid == SSID:
					self.name = _SSID.find("essid").text
					self.channel = str(child.find("channel").text)
					self.bssid = str(child.find("BSSID").text)
					self.packets = int((child.find("packets")).find("total").text)
					client_count, client_list = self.test_clients(child)
					self.client_count = client_count
					self.client_list = client_list

	def parse_name(self):
		for child in self.root:
			SSID = child.find("SSID")
			name = SSID.find("essid").text
			#print "SSID:", SSID 					#debug
			#print "name:", name 					#debug
			self.name=name
			return name

###WRITE####t
##creates xml object	
##This could be improved and made more modular
	def xml_tree(self, essid='', channel='', bssid='', packets='', client_count=0, client_list=[]):
		root = ET.Element("targets")
		net = ET.SubElement(root, "wireless-network")
		SS = ET.SubElement(net, "SSID")
		ET.SubElement(SS , "essid").text = "%s" % (essid)
		ET.SubElement(net, "channel").text = "%s" % (channel)
		ET.SubElement(net, "BSSID").text = "%s" % (bssid)
		pac = ET.SubElement(net, "packets")
		ET.SubElement(pac, "total").text = "%s" % (packets)
		ET.SubElement(net, "cracked").text = "False"
		index = 1
		for MAC in client_list:
			#print "MAC:", MAC 				#debug
			number = str(index)
			wir = ET.SubElement(net, "wireless-client", {'number':number})
			ET.SubElement(wir, "client-mac").text = "%s" % (MAC)
			index = (index + 1)
		self.tree = ET.ElementTree(root)

##writes xml object to file
#requires string for output file destination
	def xml_write(self, output_xml):
		self.tree.write(output_xml)

####TESTS####

 #Tests for signal level greater than -XBm
	def test_power(self, network):
		snr = network.find("snr-info")
		lastsig = int((snr.find("last_signal_dbm")).text)
		if -lastsig <= 88:
			power = 1
			return power
		else:  
			power = 0
			return power

	#Tests for sufficient traffic to be worth cracking(indicative of activity)
	def test_packets(self, network):
		packets = int((network.find("packets")).find("total").text)
		return packets

	#this function tests for attached clients within specified network
	def test_clients(self, network):
		client_count = 0
		client_list = []
		if network.findall("wireless-client"):
			clients = network.findall("wireless-client")
			for clit in clients:
				client_list.append(clit.find("client-mac").text)
				client_count = int(clit.attrib["number"])        
		return client_count, client_list

	def test_cracked(self):
		for child in self.root:
			if child.find("cracked") != None:
				cracked = str(child.find("cracked").text)
			else: 
				cracked = False		
		return cracked

#xml1='/home/odroid/targets/xml1.xml'
#xml2='/home/odroid/targets/xml2.xml'

#_xml1 = xml_machine(xml1)
#_xml2 = xml_machine(xml2)

#_xml1.parse_name()
#print _xml1.name
#_xml2.parse_name()
#print _xml2.name
#_xml1.parse_deets(_xml1.name)
#print _xml1.name
#print _xml1.channel
#print _xml1.packets
#print _xml1.bssid
#print _xml1.client_list
#print _xml1.client_count
#_xml2.parse_deets(_xml2.name)
#print _xml2.name
#print _xml2.channel
#print _xml2.packets
#print _xml2.bssid
#print _xml2.client_list
#print _xml2.client_count

#crackable_list = test.crackables()
#print "crackable_list:", crackable_list
#for cracker in crackable_list:
#	deets = test.parse_deets(cracker)
#	if deets != 'None':
#		print "network essid:", deets["essid"]
#		print "network channel:", deets["channel"]
#		print "network packet count:", deets["packets"]
#		print "network AP MAC:", deets["bssid"]
#		print "network clients detected:", deets["client_count"]
#		print "network client list MAC:", deets["client_list"]
#test.xml_tree(deets["essid"], deets["channel"],	deets["bssid"], deets["packets"], deets["client_count"],)
#test.xml_write('/home/odroid/targets/testes_write.xml')
