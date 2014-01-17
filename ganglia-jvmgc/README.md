JVM GC的性能统计，目前统计的三个指标是 full gc次数，年老代百分比，永久代百分比，所有数据均来自jstat命令。

注意：因为取pid时使用的是netstat，所以如果ganglia进程和java进程不是同一个用户在跑，则无法取到java pid。

----------------------------------部分配置说明------------------------
modules {
  module {
    name = "jvm_gc"   #模块名
    language = "python"
    param RefreshRate {
        value = 5          #刷新间隔，这里设置的是5秒
    }
    param JAVA_HOME {
        value = "/usr/local/jdk1.6.0_32"      #JAVA_HOME目录，用来寻找到jstat命令，必须
    }
    param Port {
        value = "8110"                        #端口号，用于在ganglia分图形分组，必须
    }

    param PID_CMD {
        value = "ps xau  | grep java | grep -v grep  | grep _8110 | awk '{print $2}'"    #用于找出唯一PID的shell命令,必须
    }
  }
}
