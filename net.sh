#!/bin/bash
# maybe the $port is not necessary.
port=`curl -s /dev/null 'http://202.117.144.205' | awk  -F '>' 'NR==4 {print $0 ") " }' | awk -F '=' '{print $2 "）"}' | awk -F ';' '{print $1}' | awk -F ':' '{print $3}' | awk -F '/' '{print $1}'`

# ** PLEASE COMPLETE THE <ID> and <DAY> WITH GUIDE **
curl -s  /dev/null 'http://202.117.144.205:'$port'/snnuportal/login'  --data-raw 'sourceurl=null&account=[ID]&password=[DAY]%21&yys=&issave='|iconv -f gb2312 -t utf8 | grep 当前IP | awk -F '>' '{ print $2 }' | awk -F '</td' '{print $1}'
