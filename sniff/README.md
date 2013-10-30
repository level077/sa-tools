python 抓包模块，作为python编程的练手。

安装：
cd pylibpcap-0.6.4
python ./setup.py install
note:确保已经安装了libpcap包，否则代码执行会报错。


memkeys.py:抓取memcache包，打印请求并将key及请求次数输出到文件/tmp/memkeys.log

mysql_query_sniff.py:抓取mysql query，不关注其他的mysql操作。可以将输出写到文件做后续的分析，如检查请求是否加入缓存等。适合初级的简单的统计之用
