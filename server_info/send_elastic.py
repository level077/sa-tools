#! /usr/bin/python
# coding:utf-8

import server_info
import json
import httplib
import sys
import hashlib

def send_elastic(id,body):
    host = "172.28.5.57"
    port = 9200
    url = "/idc/server/" + id + "/_update"
    final_body = {"doc":body,"doc_as_upsert":"true"}
    conn = httplib.HTTPConnection(host,port)
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
    server_info = server_info.get_result()
    id = server_info["product_serial"]
    body = json.dumps(server_info)
    if is_changed(body):
        send_elastic(id,server_info)
