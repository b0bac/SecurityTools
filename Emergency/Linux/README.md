# LinuxEmergency
***
Linux下的应急工具，支持CentOS系统和RedHat系统，安装方法：
```
git clone https://github.com/cisp/LinuxEmergency.git
cd LinuxEmergency
sh ./install.sh
```

要求root权限

# 查看操作系统信息：
***
```
[root@centos emergency]# python emergency.py -o

        内核版本 : Linux-3.10.0-514.26.2.el7.v7.4.qihoo.x86_64-x86_64-with-centos-7.2.1511-Core
        CORE数量 : 16
        CPU数量 : 16
        CPU使用率 : scputimes(user=1.0, nice=0.0, system=0.0, idle=15.0, iowait=0.0, irq=0.0, softirq=0.0, steal=0.0, guest=0.0, guest_nice=0.0)
        内存总量  : 33736994816
        内存使用率 : 5.1

[root@centos emergency]#
```

# 查看内核模块信息：
***
```
[root@centos emergency]# python emergency.py -k
内核模块 : nfnetlink_queue  来源  :
内核模块 : nfnetlink_log  来源  :
内核模块 : nfnetlink  来源  :  nfnetlink_log,nfnetlink_queue
内核模块 : bluetooth  来源  :
```

# 查看所有登录成功失败的IP地址：
***
```
[root@scentos emergency]# python emergency.py -l
192.168.100.35  失败
192.168.100.31  失败
127.0.0.1  失败
192.168.100.20  成功
```

# 查看登录成功和失败日志
***
```
# 成功的 -s
[root@centos emergency]# python emergency.py -s | more
账户 : emergency    时间 : 2017-08-09-11:20  来源 : (192.168.100.24)
账户 : emergency    时间 : 2017-08-09-14:34  来源 : (192.168.100.24)
账户 : root    时间 : 2017-09-28-12:38  来源 : (192.168.100.65)
账户 : root    时间 : 2017-09-28-12:46  来源 : (192.168.100.65)
账户 : root    时间 : 2017-09-28-13:13  来源 : (192.168.100.65)

# 失败的 -f
[root@centos emergency]# python emergency.py -f | more
账户 : emergency    时间 : 192.168.100.34  来源 : Jul-6-21:27---21:27
账户 : emergency    时间 : 192.168.100.34  来源 : Jul-6-21:25---21:25
账户 : admin    时间 : 127.0.0.1  来源 : Jul-5-15:32---15:32

# 如果需要指定IP 加-i参数 ，例如 -i 192.168.100.34；

```

# 查看进程列表和详细信息
```
# 列表信息
[root@centos emergency]# python emergency.py -a
***********************************************************************************************************
进程ID号: 2     进程名称: kthreadd     进程用户: root     启动时间: 2018-06-16 07:40:48
CPU占比: 0.0%     内存占比: 0.0%
网络连接:
***********************************************************************************************************
***********************************************************************************************************
进程ID号: 3     进程名称: ksoftirqd/0     进程用户: root     启动时间: 2018-06-16 07:40:48
CPU占比: 0.0%     内存占比: 0.0%
网络连接:
***********************************************************************************************************
...

#  详细信息
[root@centos emergency]# python emergency.py -p 28344
***********************************************************************************************************
进程ID号: 28344     进程名称: screen     进程用户: emergency     启动时间: 2018-06-22 13:25:30
工作路径: /home/emergency/
进程命令: SCREEN
父母进程: 1
亲子进程: [28345]
CPU占比: 0.0%     内存占比: 0.0046135703802%
网络连接:
进程环境:
        终端会话    :  /bin/bash
        安全会话    :
        登录账户    :  emergency
        工作账户    :  emergency
        权限路径    :  /usr/lib64/ccache:/usr/local/bin:/usr/bin:/usr/local/sbin:/usr/sbin:/home/emergency/tools:/usr/local/bin:/usr/local/sbin:/usr/local/python3/bin:/home/emergency/.local/bin:/home/emergency/bin
        用户目录    :  /home/emergency

***********************************************************************************************************
```

#  添加virustotal基本查询功能
```
# 检查样本
[root@centos emergency]# python vt.py -f ./LICENSE
******************************************
检测时间: 2018-07-09 07:31:04
报毒数量: 0
报毒引擎: []
引擎总数: 59
******************************************

# 检查URL
[root@centos emergency]# python vt.py -u http://1.1.1.2/bmi/docs.autodesk.com
******************************************
检测时间: 2018-07-09 16:33:29
关联样本: 0
关联连接: 0
关联域名: 0
******************************************

# 检查域名
[root@centos emergency]# python vt.py -d baidu.com
******************************************
检测时间: 2018-07-09 16:33:35
关联样本: 202
关联连接: 100
关联域名: 8
******************************************

# 检查IP
[root@centos emergency]# python vt.py -a 114.114.114.114
******************************************
检测时间: 2018-07-09 16:34:05
关联样本: 135
关联连接: 93
关联域名: 592
******************************************
```

#  增加查看whois信息的功能
```
[root@centos emergency]# python mywhois.py -d baidu.com
Domain Name: baidu.com
Registry Domain ID: 11181110_DOMAIN_COM-VRSN
Registrar WHOIS Server: whois.markmonitor.com
Registrar URL: http://www.markmonitor.com
Updated Date: 2017-07-27T19:36:28-0700
Creation Date: 1999-10-11T04:05:17-0700
Registrar Registration Expiration Date: 2026-10-11T00:00:00-0700
Registrar: MarkMonitor, Inc.
Registrar IANA ID: 292
Registrar Abuse Contact Email: abusecomplaints@markmonitor.com
Registrar Abuse Contact Phone: +1.2083895740
Domain Status: clientUpdateProhibited (https://www.icann.org/epp#clientUpdateProhibited)
Domain Status: clientTransferProhibited (https://www.icann.org/epp#clientTransferProhibited)
Domain Status: clientDeleteProhibited (https://www.icann.org/epp#clientDeleteProhibited)
Domain Status: serverUpdateProhibited (https://www.icann.org/epp#serverUpdateProhibited)
Domain Status: serverTransferProhibited (https://www.icann.org/epp#serverTransferProhibited)
Domain Status: serverDeleteProhibited (https://www.icann.org/epp#serverDeleteProhibited)
Registrant Organization: Beijing Baidu Netcom Science Technology Co., Ltd.
Registrant State/Province: Beijing
Registrant Country: CN
Admin Organization: Beijing Baidu Netcom Science Technology Co., Ltd.
Admin State/Province: Beijing
Admin Country: CN
Tech Organization: Beijing Baidu Netcom Science Technology Co., Ltd.
Tech State/Province: Beijing
Tech Country: CN
Name Server: ns4.baidu.com
Name Server: ns3.baidu.com
Name Server: dns.baidu.com
Name Server: ns2.baidu.com
Name Server: ns7.baidu.com
DNSSEC: unsigned
URL of the ICANN WHOIS Data Problem Reporting System: http://wdprs.internic.net/
>>> Last update of WHOIS database: 2018-07-09T02:21:59-0700 <<<

If certain contact information is not shown for a Registrant, Administrative,
or Technical contact, and you wish to send a message to these contacts, please
send your message to whoisrelay@markmonitor.com and specify the domain name in
the subject line. We will forward that message to the underlying contact.

If you have a legitimate interest in viewing the non-public WHOIS details, send
your request and the reasons for your request to abusecomplaints@markmonitor.com
and specify the domain name in the subject line. We will review that request and
may ask for supporting documentation and explanation.

The Data in MarkMonitor.com's WHOIS database is provided by MarkMonitor.com for
information purposes, and to assist persons in obtaining information about or
related to a domain name registration record.  MarkMonitor.com does not guarantee
its accuracy.  By submitting a WHOIS query, you agree that you will use this Data
only for lawful purposes and that, under no circumstances will you use this Data to:
 (1) allow, enable, or otherwise support the transmission of mass unsolicited,
     commercial advertising or solicitations via e-mail (spam); or
 (2) enable high volume, automated, electronic processes that apply to
     MarkMonitor.com (or its systems).
MarkMonitor.com reserves the right to modify these terms at any time.
By submitting this query, you agree to abide by this policy.

MarkMonitor is the Global Leader in Online Brand Protection.

MarkMonitor Domain Management(TM)
MarkMonitor Brand Protection(TM)
MarkMonitor AntiPiracy(TM)
MarkMonitor AntiFraud(TM)
Professional and Managed Services

Visit MarkMonitor at http://www.markmonitor.com
Contact us at +1.8007459229
In Europe, at +44.02032062220

For more information on Whois status codes, please visit
 https://www.icann.org/resources/pages/epp-status-codes-2014-06-16-en
--

```
