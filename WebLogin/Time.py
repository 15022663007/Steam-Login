# -*- coding: UTF-8 -*-
#!/usr/bin/python

import requests 
import time
from requests.adapters import HTTPAdapter

class TimeAligner():

    header = {'User-Agent':'Mozilla/5.0 (Linux; U; Android 4.1.1; en-us; Google Nexus 4 - 4.1.1 - API 16 - 768x1280 Build/JRO03S) AppleWebKit/534.30 (KHTML, like Gecko) Version/4.0 Mobile Safari/534.30',
              'Accept-Encoding': 'gzip, deflate',
              'Accept': 'text/javascript, text/html, application/xml, text/xml, */*',
              'Host': 'api.steampowered.com',
              'Referer': 'https://steamcommunity.com',
            }
		
    def get_time_offset(self):
        req = requests.session()
        req.mount('https://', HTTPAdapter(max_retries=3))
        querytime_response = req.post(url="https://api.steampowered.com/ITwoFactorService/QueryTime/v0001",
                                           headers = self.header,params={'steamid':'0'},timeout = 12).json()
        ts = int(time.time())
        offset_time = int(querytime_response.get('response', {}).get('server_time', ts)) - ts  
        return offset_time



###------------------test--------------
#offset_time  = TimeAligner().get_time_offset()
#print(offset_time)