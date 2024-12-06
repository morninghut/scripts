#!/bin/bash
split_line="\n\n###############################################################################\n\n"

# Color define
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
BOLD='\033[1m'
GRBOLD=$GREEN$BOLD
REDBOLD=$RED$BOLD
RESET='\033[0m'  # reset color

# color text test
#echo -e "${RED}这是红色文本${RESET}"
#echo -e "${GREEN}这是绿色文本${RESET}"
#echo -e "${YELLOW}这是黄色文本${RESET}"
#echo -e "${BLUE}这是蓝色文本${RESET}"
#echo -e "${GRBOLD}这是绿色加粗文本${RESET}"

draw_split(){
  echo -e "${YELLOW}${BOLD}$split_line${RESET}"
} # 黄色分割线

draw_split

echo -e "${GRBOLD}欢迎使用检查脚本${RESET}\n"

# 输出脚本执行时间
date=$(date '+%Y-%m-%d %H:%M:%S')
echo -e "${GRBOLD}现在时间：${RESET}$date"

# 检测本机IP地址
ipaddr=$(ifconfig -a | grep -w inet | awk '{ print $2 }' | grep -v "172.*\|127.0.0.1\|169.*")
if [ -z "$ipaddr" ]; then
  echo -e "${REDBOLD}未发现本机IP！${RESET}"
else
  echo -e "${GRBOLD}本机IP：${RESET}$ipaddr"
fi

# 检测内核版本
corever=$(uname -a)
if [ -z "$corever" ]; then
  echo -e "${REDBOLD}查看内核版本失败！${RESET}"
else
  echo -e "${GRBOLD}内核信息：${RESET}$corever"
fi

# 检查ARP信息
## ARP表
arptab=$(arp -a -n)
if [ -z "$arptab" ]; then
  echo -e "${REDBOLD}查看ARP表失败！${RESET}"
else
  echo -e "${GRBOLD}ARP表：${RESET}\n$arptab"
fi

# 检查TCP端口情况
tcp_open_ports=$(netstat -anltp | grep LISTEN | awk  '{print $4,$7}' | egrep "(0.0.0.0|:::)" | sed 's/:/ /g' | awk '{print $(NF-1),$NF}' | sed 's/\// /g' | awk '{printf "%-20s%-10s\n",$1,$NF}' | sort -n | uniq)
if [ -z "$tcp_open_ports" ]; then
  echo -e "${REDBOLD}查看TCP端口情况失败！请使用root用户执行脚本！${RESET}"
else
  echo -e "${GRBOLD}开放TCP端口情况：${RESET}\n$tcp_open_ports"
fi

# 检查UDP端口情况
udp_open_ports=$(netstat -anlup | awk '{print $4, $NF}' | grep -e "0.0.0.0\|:::" | sed -e 's/0.0.0.0/ /g' -e 's/:/ /g' -e 's/\// /g' | awk '{printf "%-20s%-10s\n", $1, $NF}' | sort -n | uniq)
if [ -z "$udp_open_ports" ]; then
  echo -e "${REDBOLD}查看UDP端口情况失败！请使用root用户执行脚本！${RESET}"
else
  echo -e "${GRBOLD}开放UDP端口情况：${RESET}\n$udp_open_ports"
fi

# 网络连接情况
netstatsum=$(netstat -n | awk '/^tcp/ {++S[$NF]} END {for(a in S) print a, S[a]}')
if [ -z "$netstatsum" ]; then
  echo -e "${REDBOLD}查看网络连接情况失败！请使用root用户执行脚本！${RESET}"
else
  echo -e "${GRBOLD}网络连接情况：${RESET}\n$netstatsum"
fi

# 网卡模式
ifconfigmode=$(ifconfig -a | grep flags | awk -F '[: = < >]' '{print "网卡:",$1,"模式:",$5}')
if [ -z "$ifconfigmode" ]; then
  echo -e "${REDBOLD}网卡检查结果为空！${RESET}"
else
  echo -e "${GRBOLD}网卡模式：${RESET}\n$ifconfigmode"
fi

# 检查是否有网卡处于监听/混杂模式
promisc_monitor=$(ifconfig | grep -e "PROMISC\|Mode:Monitor")
if [ -z "$promisc_monitor" ]; then
  echo -e "${GRBOLD}未发现有网卡处于监听/混杂模式${RESET}"
else
  echo -e "${REDBOLD}网卡处于监听/混杂模式！${RESET}"
fi

draw_split

# 检查开机自启服务
sysstartservices=$(systemctl list-unit-files | awk {'print $1,$2'} | grep enabled | awk {'print $1'})
echo -e "${GRBOLD}开机自启服务：${RESET}\n$sysstartservices"

# 检查crontab
syscrotab=$(cat /etc/crontab | grep -v "^#")
if [ -z "$syscrotab" ]; then
  echo -e "${REDBOLD}未发现crontab配置！${RESET}"
else
  echo -e "${GRBOLD}crontab配置：${RESET}\n$syscrotab"
fi

# 检查系统crontab中是否有可疑任务
suspicious_crontab=$(cat /etc/cron*/* | grep -E "wget|curl|fetch|fetchmail|fetch-crontab|rm|chmod|useradd|ssh|groupadd|chown|chattr|.*\.(sh|py|pl|rb|php|pyc|pyo|pyd|pyw|pyz|py3|py3c|py3w|py3z|py3p|py3d|py3w|py3z|py3p)" | grep -v "^#")
if [ -z "$suspicious_crontab" ]; then
  echo -e "${GRBOLD}未发现可疑crontab任务！${RESET}"
else
  echo -e "${REDBOLD}可疑crontab任务：${RESET}\n$suspicious_crontab"
fi

# 检查用户crontab中是否有可疑任务
rootcrontab=$(crontab -u root -l)
if [ $? -eq 0 ]; then
  echo -e "${GRBOLD}root用户crontab配置：${RESET}\n$rootcrontab"
else
  echo -e "${REDBOLD}root用户crontab配置检查失败！${RESET}"
fi
usercrontab=$(crontab -u $(whoami) -l)
if [ $? -eq 0 ]; then
  echo -e "${GRBOLD}$(whoami)用户crontab配置：${RESET}\n$usercrontab"
else
  echo -e "${REDBOLD}$(whoami)用户crontab配置检查失败！${RESET}"
fi

draw_split

# 检查路由表
route_tab=$(route -n)
if [ -z "$route_tab" ]; then
  echo -e "${REDBOLD}查看路由表失败！${RESET}"
else
  echo -e "${GRBOLD}路由表：${RESET}\n$route_tab"
fi

# 检查路由转发是否开启
ipforward=$(sysctl net.ipv4.ip_forward | awk -F '=' '{print $2}')
if [ -z "$ipforward" ]; then
  echo -e "${REDBOLD}查看路由转发是否开启失败！${RESET}"
elif [ "$ipforward" -eq 1 ]; then
  echo -e "${REDBOLD}路由转发已开启！${RESET}"
else
  echo -e "${GRBOLD}路由转发未开启！${RESET}"
fi

draw_split

# 分析进程
ps_info=$(ps -aux  --sort=-%cpu | head -n 10)
echo -e "${GRBOLD}进程分析：${RESET}\n$ps_info"

# 分析守护进程
daemon_info=$(systemctl list-units --type=service --state=running --no-pager)
echo -e "${GRBOLD}守护进程分析：${RESET}\n$daemon_info"

draw_split

# DNS文件检查
dns_info=$(cat /etc/resolv.conf | grep -E "nameserver" | awk '{print $NF}')
echo -e "${GRBOLD}本机使用如下DNS服务器：${RESET}\n$dns_info"

# Hosts文件检查
hosts_info=$(cat /etc/hosts | grep -v "^#")
echo -e "${GRBOLD}Hosts文件内容：${RESET}\n$hosts_info"

# 公钥私钥文件检查
if [ -e /root/.ssh/id_rsa ]; then
  echo -e "${GRBOLD}本机存在公钥文件：${RESET} /root/.ssh/id_rsa"
else
  echo -e "${REDBOLD}本机不存在公钥文件：${RESET} /root/.ssh/id_rsa"
fi

for user in $(getent group sudo | cut -d: -f4 | tr ',' ' '); do
  home_dir=$(getent passwd "$user" | cut -d: -f6)
  if [ -d "$home_dir/.ssh" ]; then
    echo -e "${GRBOLD}用户$user的公钥文件：${RESET}"
    find "$home_dir/.ssh" -name "id_*.pub" -print
  fi
done

draw_split

# 查看登录用户
last_login_users=$(lastlog | grep -v "从未登录过")
if [ -z "$last_login_users" ]; then
  echo -e "${REDBOLD}未发现最近登录信息！${RESET}"
else
  echo -e "${GRBOLD}最近登录信息：${RESET}\n$last_login_users"
fi

# 当前登录用户
current_login_users=$(who)
if [ -z "$current_login_users" ]; then
  echo -e "${REDBOLD}未发现当前登录用户！${RESET}"
else
  echo -e "${GRBOLD}当前登录用户：${RESET}\n$current_login_users"
fi

# 检查除root外，UID=0的超级用户
superusr=$(cat /etc/passwd | awk -F: '{if($3==0 && $1!="root") print $1}')
if [ -z "$superusr" ]; then
  echo -e "${GRBOLD}未发现除root外的UID=0的超级用户${RESET}"
else
  echo -e "${REDBOLD}存在除root外的UID=0的超级用户！${RESET}\n$superusr"
fi

# 检查sudoers
sudoers=$(cat /etc/group | grep sudo)
if [ -z "$sudoers" ]; then
  echo -e "${GRBOLD}未发现sudoers！${RESET}"
else
  echo -e "${GRBOLD}sudoers：${RESET}\n$sudoers"
fi

# 检查克隆用户
cloneusrs=$(awk -F: '{a[$3]++}END{for(i in a)if(a[i]>1)print i}' /etc/passwd)
if [ -z "$cloneusrs" ]; then
  echo -e "${GRBOLD}未发现克隆用户${RESET}"
else
  echo -e "${REDBOLD}存在克隆用户！${RESET}\n$cloneusrs"
fi

# 检查可以登录的用户
login_users=$(awk -F: '{if($7!="/usr/sbin/nologin" && $7!="/bin/false") print $1}' /etc/passwd)
if [ -z "$login_users" ]; then
  echo -e "${REDBOLD}未发现可以登录的用户！${RESET}"
else
  echo -e "${GRBOLD}可以登录的用户：${RESET}\n$login_users"
fi

# 检查shadow文件
shadow_info=$(cat /etc/shadow | grep -v "*\|!")
echo -e "${GRBOLD}shadow文件内容：${RESET}\n$shadow_info"

# 检查空口令用户
null_passwd_users=$(awk -F: '$(NF==2) && $2=="" {print $1}' /etc/shadow)
if [ -z "$null_passwd_users" ]; then
  echo -e "${GRBOLD}未发现空口令用户${RESET}"
else
  echo -e "${REDBOLD}存在空口令用户！${RESET}\n$null_passwd_users"
fi

# 检查口令未加密用户
unencrypted_users=$(awk -F: '$2!="x" {print $1}' /etc/passwd)
if [ -z "$unencrypted_users" ]; then
  echo -e "${GRBOLD}未发现口令未加密用户${RESET}"
else
  echo -e "${REDBOLD}存在口令未加密用户！${RESET}\n$unencrypted_users"
fi

# 检查root用户组除root外其他用户
rootsexroot=$(cat /etc/group | grep -v '^#' | awk -F: '{if ($1!="root"&&$3==0) print $1}')
if [ -z "$rootsexroot" ]; then
  echo -e "${GRBOLD}未发现root用户组除root外其他用户${RESET}"
else
  echo -e "${REDBOLD}存在root用户组除root外其他用户！${RESET}\n$rootsexroot"
fi

# 检查相同GID用户组
samegid=$(cat /etc/group | grep -v "^$" | awk -F: '{print $3}' | sort -n | uniq -d)
if [ -z "$samegid" ]; then
  echo -e "${GRBOLD}未发现相同GID用户组${RESET}"
else
  echo -e "${REDBOLD}存在相同GID用户组！${RESET}\n$samegid"
fi

# 检查相同用户组名
samegroup=$(cat /etc/group | grep -v "^$" | awk -F: '{print $1}' | sort | uniq -d)
if [ -z "$samegroup" ]; then
  echo -e "${GRBOLD}未发现相同用户组名${RESET}"
else
  echo -e "${REDBOLD}存在相同用户组名！${RESET}\n$samegroup"
fi

draw_split

# 检查root bash_history
dl_scripts=$(cat /root/.bash_history | grep -E "((wget|curl).*\.(sh|pl|py)$)" | grep -v grep)
suspicious_history=$(cat /root/.bash_history | grep -E "(whois|sqlmap|nmap|beef|nikto|john|ettercap|backdoor|proxy|msfconsole|msf)" | grep -v grep)
if [ -z "$dl_scripts" ] && [ -z "$suspicious_history" ]; then
  echo -e "${GRBOLD}未发现可疑bash_history${RESET}"
else
  echo -e "${REDBOLD}存在可疑bash_history！${RESET}\n$dl_scripts\n$suspicious_history"
fi

# 检查防火墙状态
firewalledstatus=$(systemctl status ufw | grep "active")
if [ -z "$firewalledstatus" ]; then
  echo -e "${REDBOLD}防火墙未开启！${RESET}"
else
  echo -e "${GRBOLD}防火墙状态：${RESET}\n$firewalledstatus"
fi

draw_split

# 检查sshd配置
emptypwd=$(cat /etc/ssh/sshd_config | grep "PermitEmptyPasswords no" | grep -v "^#")
if [ -z "$emptypwd" ]; then
  echo -e "${REDBOLD}sshd配置中未禁止空口令登录！${RESET}"
else
  echo -e "${GRBOLD}sshd配置中禁止空口令登录${RESET}"
fi

rootlogin=$(cat /etc/ssh/sshd_config | grep "PermitRootLogin no" | grep -v "^#")
if [ -z "$rootlogin" ]; then
  echo -e "${REDBOLD}sshd配置中未禁止root用户登录！${RESET}"
else
  echo -e "${GRBOLD}sshd配置中禁止root用户登录${RESET}"
fi

# 检查系统日志中登陆成功情况
loginsuccess=$(more /var/log/auth.log* | grep "Accepted password" | awk '{print $1,$2,$3,$9,$11}')
if [ -n "$loginsuccess" ];then
	echo -e "${GRBOLD}日志中分析到以下用户成功登录:${RESET}\n$loginsuccess"
	echo -e "${GRBOLD}登录成功的IP及次数如下：${RESET}\n$(grep "Accepted " /var/log/auth.log* | awk '{print $11}' | sort -nr | uniq -c )"
	echo -e "${GRBOLD}登录成功的用户及次数如下:${RESET}\n$(grep "Accepted" /var/log/auth.log* | awk '{print $9}' | sort -nr | uniq -c )"
else
	echo -e "${REDBOLD}日志中未发现成功登录的情况${RESET}"
fi

# 检查系统日志中登陆失败情况
loginfailed=$(more /var/log/auth.log* | grep "Failed password" | awk '{print $1,$2,$3,$9,$11}')
if [ -n "$loginfailed" ];then
	echo -e "${REDBOLD}日志中分析到以下用户登录失败:${RESET}\n$loginfailed"
else
	echo -e "${GRBOLD}日志中未发现登录失败的情况${RESET}"
fi

draw_split

# 检查环境变量
env_info=$(printenv)
echo -e "${GRBOLD}环境变量：${RESET}\n$env_info"

# 检查磁盘
disk_info=$(df -h | grep -E "/dev/nvme*|/dev/sda*")
echo -e "${GRBOLD}磁盘信息：${RESET}\n$disk_info"
diskfull=$(df -h | grep -E "/dev/nvme*|/dev/sda*" | awk '{print $5}' | awk -F% '{print $1}' | awk '$1 > 50')
if [ -n "$diskfull" ];then
	echo -e "${REDBOLD}有磁盘占用超50%！请检查！${RESET}\n$diskfull"
else
	echo -e "${GRBOLD}磁盘使用情况正常${RESET}"
fi

# 分析系统日志
# syslog_info=$(cat /var/log/syslog)
# echo -e "${GRBOLD}系统日志分析：${RESET}\n$syslog_info"
