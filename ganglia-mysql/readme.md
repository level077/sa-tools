mysql 监控,目前主要监控select，insert，update，delete，create_tmp_table，create_tmp_disk_table，Threads_running等一些重要参数。

-----------------------------------部分配置说明---------------------------
<pre><code>
modules {
  module {
    name = "mysql"           #模块名
    language = "python"
    param RefreshRate {
        value = 2            #刷新频率
    }
    param Host {
        value = 192.168.0.201 #mysql服务器IP
    }
    param Port {
        value = 3308          #mysql 端口
    }
    param User {
        value = xxxx          #mysql user 需要有processlist权限
    }
    param Password {
        value = xxxxx
    }
  }
}
<pre><code>
