redis 监控。原理是通过redis-cli，执行info命令，然后处理数据

---------------------------------------部分配置------------------
<pre><code>
modules {
  module {
    name = "redis"    #模块名
    language = "python"
    param RefreshRate {
        value = 2        #刷新频率，这里是2秒
    }
    param Host {
        value = "192.168.10.1"   #redis服务器IP
    }
    param Port {
        value = "6379"     #redis 端口
    }
    param Redis-cli {
	value = "/usr/local/bin/redis-cli"  #redis-cli路径
    }
  }
}
