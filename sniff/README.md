python 抓包模块，作为python编程的练手。

安装：

cd pylibpcap-0.6.4

python ./setup.py install

note:确保已经安装了libpcap包，否则代码执行会报错。


sniff.py:抓取基本的tcp包，适合http的抓取

memkeys.py:通过分析memcached的二进制协议，打印出memcache请求，并将key及请求次数降序输出到文件/tmp/memkeys.log。

mysql_query_sniff.py:只抓取mysql query，不关注其他的mysql操作。可以将输出写到文件做后续的分析，如检查请求是否加入缓存等。适合初级的简单的统计之用
