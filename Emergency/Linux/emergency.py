# -*- coding:utf-8 -*-


'''
Linux应急进程、网络信息查看器
'''


#  进入依赖库
import os
import sys
import time
import psutil
import platform
from optparse import OptionParser


# 全局函数:
def OSinfo():
    '''操作系统基本信息查看'''
    core_number = psutil.cpu_count()
    cpu_number = psutil.cpu_count(logical=True)
    cpu_usage_precent = psutil.cpu_times_percent()
    mem_info = psutil.virtual_memory()
    result = {
        "memtotal": mem_info[0],
        "memavail": mem_info[1],
        "memprecn": mem_info[2],
        "memusage": mem_info[3],
        "memfreed": mem_info[4],
    }
    print '''
        内核版本 : %s
        CORE数量 : %s
        CPU数量 : %s
        CPU使用率 : %s
        内存总量  : %s
        内存使用率 : %s
    '''%(str(platform.platform()),str(core_number),str(cpu_number),str(cpu_usage_precent),str(mem_info[0]),str(mem_info[2]))

def SuccessLoginDetail():
    '''查找登录成功的记录'''
    try:
        successer_list = os.popen("who /var/log/wtmp | awk '{print $1,$3\"-\"$4\"\",$5}'").read().split('\n')[:-1]
    except Exception, reason:
        print "读取记录失败"
        exit(0)
    if len(successer_list) == 1 and successer_list[0] == '':
        print "未找到成功的登录信息"
        exit(0)
    for success in successer_list:
        info_string = success.split(" ")
        try:
            print '账户 : %s    时间 : %s  来源 : %s'%(info_string[0],info_string[1],info_string[2])
        except Exception:
            continue


def FailedLoginDetail():
    '''查找登录失败的日志'''
    try:
        failer_list = os.popen("lastb | awk '{print $1,$3,$5\"-\"$6\"-\"$7\"-\"$8\"-\"$9}'").read().split('\n')[0:-3]
    except Exception, reason:
        print "读取记录失败"
        exit(0)
    if len(failer_list) == 1 and successer_list[0] == '':
        print "未找到失败的登录信息"
        exit(0)
    for failer in failer_list:
        info_string = failer.split(" ")
        try:
            print '账户 : %s    时间 : %s  来源 : %s'%(info_string[0],info_string[1],info_string[2])
        except Exception:
            continue

def LoginIpList():
    '''登录IP列表'''
    ipresult = []
    flag = True
    try:
        ip_failer_list = os.popen("lastb | awk '{print $3}' | sort | uniq -c | sort -k 1").read().split("\n")[2:-1]
    except Exception, reason:
        flag = False
    if flag:
        for ip in ip_failer_list:
            ipaddress = ip.lstrip().split(' ')
            ipaddr = ipaddress[1]
            if 'Thu' in ipaddr:
                continue
            ipresult.append((ipaddr,'失败'))
    flag = True
    try:
        ip_success_list =  os.popen("who /var/log/wtmp| awk '{print $5}' | sort | uniq -c | sort -k 1").read().split("\n")[:-1]
    except Exception, reason:
        flag = False
    if flag:
        if len(ip_success_list) == 0:
            pass
        else:
            for ip in ip_success_list:
                ipaddress = ip.lstrip().split(' ')
                ipaddr = ipaddress[1]
                if ':' in ipaddr:
                    continue
                ipaddr = ipaddr.replace('(','').replace(')','')
                ipresult.append((ipaddr,"成功"))
    for ip in ipresult:
        print '%s  %s'%(str(ip[0]),str(ip[1]))


def LoginCheckByIP(ipaddress,kind="success"):
    '''查看IP的登录信息查看'''
    command = "who /var/log/wtmp | grep -E \"%s\" | awk '{print $1,$3\"-\"$4\"\",$5}'"%ipaddress if kind == 'success' else "lastb | grep -E \"%s\" | awk '{print $1,$3,$5\"-\"$6\"-\"$7\"-\"$8\"-\"$9}'"%ipaddress
    try:
        _list = os.popen(command).read().split('\n')
    except Exception, reason:
        print "读取记录失败"
        exit(0)
    if len(_list) == 1 and _list[0] == '':
        print "未找到相关的登录信息"
        exit(0)
    for ip in _list:
        info_string = ip.split(" ")
        try:
            print '账户 : %s    时间 : %s  来源 : %s'%(info_string[0],info_string[1],info_string[2])
        except Exception:
            continue

def KernelModInfo():
    '''查看内核加载模块'''
    result = []
    try:
        modlist = os.popen("lsmod | awk '{print $1,$4}'").read().split('\n')[1:-1]
        for mod in modlist:
            modname = mod.split(' ')[0]
            modsource = mod.split(' ')[1]
            result.append((modname,modsource))
    except Exception, reason:
        pass
    for ret in result:
        print "内核模块 : %s  来源  :  %s"%(ret[0],ret[1])


def ShowProcessInfo(pid,detail=True):
    '''进程和网络信息查看'''
    process = psutil.Process(pid)
    command = ''
    for string in process.cmdline():
        command += ' %s'%string
    command = command.lstrip()
    connections = ""
    for connection in process.connections(kind='inet'):
        sip = connection[3][0].replace(":","")
        dip = connection[4][0].replace(":","")
        sport = connection[3][1]
        dport = connection[4][1]
        state = connection[5]
        connections += "\n    SIP:%s SPORT:%s - DIP:%s DPORT:%s  [%s]"%(str(sip),str(sport),str(dip),str(dport),state)
    envir = process.environ()
    evistring = """
        终端会话    :  %s
        安全会话    :  %s
        登录账户    :  %s
        工作账户    :  %s
        权限路径    :  %s
        用户目录    :  %s
    """%(str(envir.get("SHELL","")),str(envir.get('SECURITYSESSIONID','')),str(envir.get('LOGNAME','')),str(envir.get('USER','')),str(envir.get('PATH','')),str(envir.get('HOME','')))
    print "***********************************************************************************************************"
    print "进程ID号:",pid,"    进程名称:",process.name(),"    进程用户:",process.username(),"    启动时间:",time.strftime("%Y-%m-%d %H:%M:%S",time.localtime(int(process.create_time())))
    if detail:
        try:
            cwd = process.cwd()
            print "工作路径:",cwd
        except Exception:
            print "工作路径:"
        print "进程命令:",command
        print "父母进程:",process.ppid()
        print "亲子进程:",[x.pid for x in list(process.children())]
    print "CPU占比:",str(process.cpu_percent())+"%","    内存占比:",str(process.memory_percent())+"%"
    print "网络连接:",connections
    if detail:
        print "进程环境:",evistring
    print "***********************************************************************************************************"


if __name__ == "__main__":
    parser = OptionParser()
    parser.add_option("-p", "--process",dest="process",help="show process detail")
    parser.add_option("-a","--all",action='store_true',dest="all",help="show all process")
    parser.add_option("-o", "--osinfo",action='store_true',dest="osinfo",help="set search time")
    parser.add_option("-i","--ipaddress",dest="ipaddress",help="set search ipaddress")
    parser.add_option("-f","--failer",action='store_true',dest="failed",help="show failed login")
    parser.add_option("-s","--success",action='store_true',dest="successed",help="show successed login")
    parser.add_option("-l","--iplist",action='store_true',dest="iplist",help="show login ip list")
    parser.add_option("-k","--kernel",action='store_true',dest="kernel",help="show login ip list")
    (options, args) = parser.parse_args()
    if options.ipaddress not in [None,""] and options.successed:
        LoginCheckByIP(options.ipaddress,kind='success')
        exit(0)
    elif options.ipaddress not in [None,""] and options.failed:
        LoginCheckByIP(options.ipaddress,kind='failed')
        exit(0)
    if options.osinfo:
        OSinfo()
        exit(0)
    if options.iplist:
        LoginIpList()
    if options.kernel:
        KernelModInfo()
    if options.failed:
        FailedLoginDetail()
        exit(0)
    if options.successed:
        SuccessLoginDetail()
        exit(0)
    if options.all:
        for pid in psutil.pids():
            try:
                ShowProcessInfo(int(pid),detail=False)
            except Exception:
                pass
    else:
        if options.process != None:
            try:
                ShowProcessInfo(int(options.process))
            except Exception, reason:
                pass
