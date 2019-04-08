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

def bulk_send(body=None,ts=None,elastic_host=None,elastic_port=None,product_serial=None,hostname=None,ip=None,product_uuid=None,index=None,doc_type=None):
    url = "http://"+ elastic_host + ":" + elastic_port + "/_bulk"
    headers = {"Content-Type":"application/x-ndjson"}
    payload = []
    meta = {"index":{"_index":index,"_type":doc_type}}
    for p in body:
      p["@timestamp"] = ts
      p["product_serial"] = product_serial
      p["product_uuid"] = product_uuid
      p["hostname"] = hostname
      p["ip"] = ip
      payload.append(json.dumps(meta))
      payload.append(json.dumps(p))
    pl = "\n".join(payload) + "\n"
    r = requests.post(url, data=pl,headers=headers)
    print(r.status_code)

def send_elastic(body=None,ts=None,elastic_host=None,elastic_port=None,index=None,doc_type=None):
    url = "http://"+ elastic_host + ":" + elastic_port + "/"+index+"/"+doc_type+"/"
    headers = {"Content-Type":"application/json"}
    body["@timestamp"] = ts
    r = requests.post(url, data=json.dumps(body),headers=headers)
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
    server = server_info.get_result()
    process,software = process_info.get_info()
    user = user_info.get_user()
    ts = datetime.datetime.utcnow().isoformat()
    product_serial = server["product_serial"]
    product_uuid = server["product_uuid"]
    hostname = server["hostname"]
    ip = server["default_ipv4"]["address"]
    bulk_send(body=process,index="process",doc_type="process",ts=ts,elastic_host=elastic_host,elastic_port=elastic_port,product_serial=product_serial,hostname=hostname,ip=ip,product_uuid=product_uuid)
    bulk_send(body=software,index="software",doc_type="software",ts=ts,elastic_host=elastic_host,elastic_port=elastic_port,product_serial=product_serial,hostname=hostname,ip=ip,product_uuid=product_uuid)
    bulk_send(body=user,index="user",doc_type="user",ts=ts,elastic_host=elastic_host,elastic_port=elastic_port,product_serial=product_serial,hostname=hostname,ip=ip,product_uuid=product_uuid)
    send_elastic(body=server,index="server",doc_type="server",ts=ts,elastic_host=elastic_host,elastic_port=elastic_port)
    #print(json.dumps(server_info))
