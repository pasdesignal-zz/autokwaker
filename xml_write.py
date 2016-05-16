#!/usr/bin/python

import xml.etree.cElementTree as ET

def xml_write(essid, channel, bssid, packets, dest):
	root = ET.Element("targets")
	doc = ET.SubElement(root, "network")

	ET.SubElement(doc, "essid").text = "%s" % (SSID)
	ET.SubElement(doc, "channel").text = "%d" % (channel)
	ET.SubElement(doc, "bssid").text = "%d" % (bssid)
	ET.SubElement(doc, "packets").text = "%d" % (packets)

	tree = ET.ElementTree(root)
	tree.write(dest)