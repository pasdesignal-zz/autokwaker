#this is used as a worksheet for breaking out functions and developing them without
#having to run the entire program

import requests
import json

bssid = "00:23:51:70:B3:B9"

def geo_locate(bssid, strength, ratio):
	key = 'AIzaSyACZk1FXBvka4ra3DxGg0OYHfPvDTe9Ma0' #googlemaps api key
	url = ('https://www.googleapis.com/geolocation/v1/geolocate?key='+key)
	print "url:", url
	location_data = {}
	location_data = {'considerIP' : 'false',
			'wifiAccessPoints' :[
			{"macAddress": bssid,"signalStrength": strength,"signalToNoiseRatio": ratio},
    		]
  			}
  	print "data:", location_data
  	json_data = json.dumps(location_data)
	r = requests.post(url, data=json_data)
	location_result = {}
	print "type:", type(location_result)
	location_result = json.loads(r.text)
	print "type:", type(location_result)
	loc = location_result['location']
	accuracy = location_result['accuracy']
	lattitude = loc['lat']
	longitude = loc['lng']
	print 'lattitude', lattitude
	print 'longitude', longitude
	print 'accuracy', accuracy
	return lattitude, longitude, accuracy

lat, lng, acc = geo_locate(bssid, "0", "0")	#power and snr to be added in future.....
print 'lat:', lat
print 'lng:', lng
print 'acc:', acc
