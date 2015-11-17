import requests
import datetime
import time
import sys

is_open = False
close_time = datetime.datetime.max
lock_id = sys.argv[1]

API_BASE_ADDR="http://slip-d-4.herokuapp.com/"

def api_endpoint(endpoint=''):
    return '{}/{}'.format(API_BASE_ADDR,endpoint)

while(True):
    if is_open:
        print "{}: open".format(lock_id)
        response = requests.get(api_endpoint('im-open/{}'.format(lock_id)))
        if datetime.datetime.now() > close_time:
            print "{}: closing...".format(lock_id)
            is_open = False
            close_time = datetime.datetime.max
    else:
        print "{}: closed".format(lock_id)
        response = requests.get(api_endpoint('im-closed/{}'.format(lock_id)))
        if response.status_code == 200:
            is_open = True
            close_time = datetime.datetime.now() + datetime.timedelta(0,10)
            print "{}: opening... closing at {}".format(lock_id, close_time)
    time.sleep(1)
