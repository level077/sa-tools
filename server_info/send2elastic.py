#! /usr/bin/python
# coding:utf-8

import server_info
import process_info
import user_info
import json
import sys
import argparse
import datetime
import requests

def send_elastic(body,elastic_host,elastic_port):
    url = "http://"+ elastic_host + ":" + elastic_port + "/idc/server/"
    r = requests.post(url, data=body)
    print(r.status_code)

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("-e","--elastic_host",help="elasticsearch server ip")
    parser.add_argument("-p","--elastic_port",help="elasticsearch server port")
    args = parser.parse_args()
    if args.elastic_host:
        elastic_host = args.elastic_host
    else:
        print "need elasticsearch host"
        sys.exit(1)
    if args.elastic_port:
        elastic_port = args.elastic_port
    else:
        print "need elasticsearch port"
        sys.exit(1)
    server_info = server_info.get_result()
    server_info["process"],server_info["software"] = process_info.get_info()
    server_info["user"] = user_info.get_user()
    server_info["@timestamp"] = datetime.datetime.utcnow().isoformat()
    body = json.dumps(server_info)
    send_elastic(body,elastic_host,elastic_port)
    #print(body)
