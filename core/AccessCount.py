# -*- coding:utf-8 -*-

import os
from AccessApi import *

def GetAccessIPList(filename):
    AccessListIP = {}
    command = "cat %s | awk '{print $1}' | sort -r | uniq -c | sort -r"%filename
    result = os.popen(command)
    for line in result.read().split('\n'):
        line =  line.lstrip()
        if line != "" and line != None:
            stuff = line.split(' ')
        key = int(stuff[0])
        value = stuff[1]
        if key not in AccessListIP:
            AccessListIP[key] = []
        AccessListIP[int(stuff[0])].append(stuff[1])
    keylist = AccessListIP.keys()
    keylist = sorted(keylist)
    keylist.reverse()
    print "日志文件:%s"%filename
    for index,value in enumerate(keylist):
        for ip in AccessListIP[value]:
            print "排名:%s 访问源地址:%s 访问次数:%s"%(index+1,ip,value)



def GetAccessIPListByTime(filename,accesstime,timezone=None):
    AccessListIP = {}
    accesstime = TimeFormat(accesstime,timezone)
    command = "cat %s | grep '%s' | awk '{print $1}'  | sort -r | uniq -c | sort -r"%(filename,accesstime)
    result = os.popen(command).read()
    for line in result.split('\n'):
        line =  line.lstrip()
        if line != "" and line != None:
            stuff = line.split(' ')
        else:
            continue
        key = int(stuff[0])
        value = stuff[1]
        if key not in AccessListIP:
            AccessListIP[key] = []
        AccessListIP[int(stuff[0])].append(stuff[1])
    keylist = AccessListIP.keys()
    keylist = sorted(keylist)
    keylist.reverse()
    print "日志文件:%s"%filename
    for index,value in enumerate(keylist):
        for ip in AccessListIP[value]:
            print "排名:%s 访问源地址:%s 访问次数:%s"%(index+1,ip,value)

def GetAccessIPListByDate(filename,date):
    AccessListIP = {}
    accesstime = TimeFormat(date).split(":")[0]
    command = "cat %s | grep '%s' | awk '{print $1}'  | sort -r | uniq -c | sort -r"%(filename,accesstime)
    result = os.popen(command).read()
    if result == '':
        return
    for line in result.split('\n'):
        line =  line.lstrip()
        if line != "" and line != None:
            stuff = line.split(' ')
        key = int(stuff[0])
        value = stuff[1]
        if key not in AccessListIP:
            AccessListIP[key] = []
        AccessListIP[int(stuff[0])].append(stuff[1])
    keylist = AccessListIP.keys()
    keylist = sorted(keylist)
    keylist.reverse()
    print "日志文件:%s"%filename
    for index,value in enumerate(keylist):
        for ip in AccessListIP[value]:
            print "排名:%s 访问源地址:%s 访问次数:%s"%(index+1,ip,value)
