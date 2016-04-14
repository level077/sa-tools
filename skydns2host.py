#! /usr/bin/python
# coding:utf-8

import json
import httplib
import sys
import argparse

def skydns2host(host,port,url):
    conn = httplib.HTTPConnection(host,port)
    conn.request('GET',url)
    response = conn.getresponse()
    data = response.read()
    keys = json.loads(data) 
    if not keys.has_key("node"):
        print "can't find " + url
	return 0
    if keys["node"].has_key("nodes"):
       for item in keys["node"]["nodes"]:
           if item.has_key("dir"):
	       skydns2host(host,port,"/v2/keys" + item["key"])
	   elif item.has_key("value"):
	       host = json.loads(item["value"])["host"]
	       tmp = item["key"].split("/")
 	       del tmp[0:2]
	       tmp.reverse()
	       domain = ".".join(tmp)
	       print host,domain
    elif keys["node"].has_key("value"):
       host = json.loads(keys["node"]["value"])
       tmp = item["key"].split("/")
       del tmp[0:2]
       tmp.reverse()
       domain = ".".join(tmp)
       print host,domain

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("-s","--server",help="etcd server ip")
    parser.add_argument("-p","--port",help="etcd port")
    parser.add_argument("-d","--domain",help="domain")
    args = parser.parse_args()
    if args.server:
        host = args.server
    else:
        print "require skydns host"
        sys.exit(1)
    if args.port:
        port = args.port
    else:
        print "require skydns port"
        sys.exit(1)
    if args.domain:
        domain = args.domain
    else:
        print "require domain"
        sys.exit(1)
    tmp = domain.split(".")
    if tmp[-1] == "":
       tmp.pop()
    tmp.reverse()
    url = "/v2/keys/skydns/" + "/".join(tmp)
    skydns2host(host,port,url)
