#!/bin/sh

[ $# -ne 3 ] && echo "Usage: sh $0 domain host_file etcd_server" && exit 1
domain=$1
host_file=$2
etcd_server=$3
[ -z $domain ] && echo  "need domain" && exit 1
[ ! -f $host_file ] && echo "can't find $host_file" && exit 1
[ -z $etcd_server ] && echo "need ectd server" && exit 1
while read ip server_name
do
	for x in $server_name 
	do
		skydns=""
		if [ $(echo $x | grep $domain) ]
		then 
			num=$(echo $x | awk -F '.' "{print NF}")
			for((i=$num;i>0;i--))
			do
				skydns=$skydns/$(echo $x | awk -F '.' "{print \$$i}")
			done
			echo curl -XPUT "$etcd_server/v2/keys/skydns$skydns" -d value=\'{\"host\":\"$ip\"}\'
		fi
	done
done < $host_file
