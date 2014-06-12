工作中所使用到的一些工具，做为编程的练手，也是运维比较实用的一些小工具

ganglia-*
--------------
*ganglia监控模块，包括memcache，mysql，jvm GC等。

sniff
--------------
*抓包程序，可以抓取http，抓取mysql query，分析memcache请求。

innobackupex.sh
--------------
*innobackupex备份脚本，只建两个目录：full_back increment_back。每次备份都会进行prepare。

mysqlbackup.sh 
-------------
*mysqldump备份脚本

numa.pl
-------------
*查看某进程内存节点的分布情况，如cat /proc/[mysql pid]/numa_maps | perl numa.pl
