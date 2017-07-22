#!/usr/bin/python
#This script uses the Google Geolocation API for wifi AP MAC address location.
#REQUIRES AT LEAST 2 MAC ADDRESSES TO WORK
#SNR and dB are optional

import json
import requests

#mac1 = 'DC:09:4C:B7:4D:F0'
#snr1 = 0
#db1 = 0
#mac2 = '18:1F:45:15:C8:2C'
#snr2 = 0
#db2 = 0
key = 'AIzaSyCJ3ktnOO5l8U-6V9O-0vvmvNb550NSjAs' 	#unique googlemaps api key

def buildJson(mac1, db1, snr1, mac2, db2, snr2):
	obj = {}
	obj["considerIP"] = "false"
	obj[ "wifiAccessPoints" ] = [
	{"macAddress": mac1, "signalStrength": db1, "signalToNoiseRatio": snr1}, 
	{"macAddress": mac2, "signalStrength": db2, "signalToNoiseRatio": snr2},]
	text = json.dumps(obj)
	print text
	return text

def geolocate(_data):
	url = ('https://www.googleapis.com/geolocation/v1/geolocate?key='+key)
	headers = {'content-type': 'application/json'}
	location_data = _data
 	print location_data
	location_result = json.loads(requests.post(url, data=location_data, headers=headers).text)
	print(location_result)
	loc = location_result['location']
	accuracy = location_result['accuracy']
	lattitude = loc['lat']
	longitude = loc['lng']
	print("lattitude=", lattitude)
	print("longitude=", longitude)
	print("accuracy=", accuracy)
	print(lattitude, longitude)
	return lattitude, longitude, accuracy


#location_data = buildJson(mac1, snr1, db1, mac2, snr2, db2)
#geolocate(location_data)