#! /usr/bin/python
# coding:utf-8

import server_info
import json
import httplib
import sys
import hashlib
import argparse

def send_elastic(id,body,elastic_host,elastic_port):
    url = "/idc/server/" + id + "/_update"
    final_body = {"doc":body,"doc_as_upsert":"true"}
    conn = httplib.HTTPConnection(elastic_host,elastic_port)
    conn.request('POST',url,json.dumps(final_body))
    response = conn.getresponse()
    print response.status

def md5(info):
    m = hashlib.md5()
    m.update(info)
    return repr(m.digest())

def is_changed(info):
    try:
        f = open("/tmp/.server_info")
    except IOError:
        last_digest = None
    else:
    	last_digest = f.read()
    digest = md5(info)
    if digest != last_digest:
        f = open("/tmp/.server_info",'w')
        f.write(digest)
        f.close()
        return "True"
    else:
        f.close()
        return False

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("-i","--idc",help="idc name")
    parser.add_argument("-e","--elastic_host",help="elasticsearch server ip")
    parser.add_argument("-p","--elastic_port",help="elasticsearch server port")
    args = parser.parse_args()
    if args.idc:
        idc = args.idc
    else:
        print "need idc name"
        sys.exit(1)
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
    server_info["idc"] = idc
    id = server_info["product_serial"]
    body = json.dumps(server_info)
    if is_changed(body):
        send_elastic(id,server_info,elastic_host,elastic_port)
