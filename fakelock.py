import requests
import time
import sys
import json

lock_id = sys.argv[1]

API_BASE_ADDR="http://slip-d-api.herokuapp.com/"
# API_BASE_ADDR="http://localhost:5000/"

def api_endpoint(endpoint=''):
    return '{}/{}'.format(API_BASE_ADDR,endpoint)

response = requests.get(api_endpoint('im-open/{}'.format(lock_id)))
data = json.loads(response.text)
is_open = data

while(True):
    if is_open:
        print "{}: open".format(lock_id)
        response = requests.get(api_endpoint('im-open/{}'.format(lock_id)))
        if response.status_code == 200:
            is_open = False
            print "{}: closing...".format(lock_id)
    else:
        print "{}: closed".format(lock_id)
        response = requests.get(api_endpoint('im-closed/{}'.format(lock_id)))
        if response.status_code == 200:
            is_open = True
            print "{}: opening...".format(lock_id)
    time.sleep(1)
