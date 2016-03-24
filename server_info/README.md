server_info.py
--------------
* 从ansible set模块中提取出来的脚本，去除了一些信息。

send_elastic.py
--------------
* 将server_info.py的json输出，发送到elasticsearch集群。

useage
-------------
* python send_elastic.py -i idc_name -e elastic_host -p elastic_port
