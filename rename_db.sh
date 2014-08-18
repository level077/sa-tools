#!/bin/sh

mysqlconn="mysql -u test -h 127.0.0.1 -P3306 -ptest"

olddb=old
newdb=new

params=$($mysqlconn -N -e "SELECT TABLE_NAME FROM INFORMATION_SCHEMA.TABLES WHERE table_schema='$olddb'")
for name in $params
do
      echo "$mysqlconn -e 'RENAME TABLE $olddb.$name to $newdb.$name'"
      $mysqlconn -e "RENAME TABLE $olddb.$name to $newdb.$name"
done
