mongodb 监控。

---------------------------------------部分配置------------------
<pre><code>
modules {
    module {
        name = "mongodb"
        language = "python"
        param server_status {
            value = "mongo --quiet --eval 'printjson(db.serverStatus())'"
        }
        param rs_status {
            value = "mongo --quiet --eval 'printjson(rs.status())'"
        }
    }
}
