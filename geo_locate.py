#!/usr/bin/python
##This is a python module for requesting geolocation co-ordinates form Google API
##Heavily borrowed from: https://pypi.python.org/pypi/geocoder

import requests
import json

key = 'AIzaSyACZk1FXBvka4ra3DxGg0OYHfPvDTe9Ma0'

url = ('https://www.googleapis.com/geolocation/v1/geolocate?key='+key)
print "url:", url

data = {}
data = {'considerIP' : 'false',
'wifiAccessPoints' :[
    {
        "macAddress": "00:23:51:70:B3:B9",
        "signalStrength": -77,
        "signalToNoiseRatio": 0
    },
    {
        "macAddress": "00:60:64:DF:94:1E",
        "signalStrength": -81,
        "signalToNoiseRatio": 0
    }
  ]
  }
json_data = json.dumps(data)
r = requests.post(url, data=json_data)
response1 = r.text
print "response:", response1



#curl -d @your_filename.json -H "Content-Type: application/json" -i "https://www.googleapis.com/geolocation/v1/geolocate?key=YOUR_API_KEY"