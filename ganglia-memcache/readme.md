memcache 监控,目前监控指标有get,set,flush的请求数，命中率，内存大小等等。原理是通过socket连接到memcached，执行stats命令，然后处理数据

---------------------------------------部分配置------------------
<pre><code>
modules {
  module {
    name = "memcache"    #模块名
    language = "python"
    param RefreshRate {
        value = 2        #刷新频率，这里是2秒
    }
    param Host {
        value = "192.168.0.144"   #memcached服务器IP
    }
    param Port {
        value = "11211"     #memcached 端口
    }
  }
}
<pre><code>

多实例情况，就拷贝成多个模块模式，如memcache_11212.py
