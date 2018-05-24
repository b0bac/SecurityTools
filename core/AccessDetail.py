# -*- coding:utf-8 -*-

import os
from AccessApi import *

def GetAccessLogDetail(filename):
    print "文件:%s"%filename
    with open(filename,'r') as fr:
        while True:
            line = fr.readline()
            if line in ["","\r\n",'\n',None]:
                break
            informationlist = line.split(" ")
            ip = informationlist[0]
            accesstime = informationlist[3].split('[')[-1].split(']')[0]
            method = informationlist[5][1:]
            action = informationlist[6]
            try:
                website = informationlist[10]
            except:
                website = '-'
            statuscode = informationlist[8]
            try:
                useragent = ''
                for index in range(11,25):
                    useragent += informationlist[index] + ' '
            except:
                pass
            string = """
            ***************************************************************************************************
            访问源IP地址:%s
            访问时间:%s
            请求方法:%s
            访问行为:%s
            响应状态:%s
            站点信息:%s
            客户端:%s
            ***************************************************************************************************
            """%(ip,accesstime,method,action,statuscode,website,useragent[0:-2])
            print string

def GetAccessLogDetailByIP(filename,ipaddress):
    print "文件:%s"%filename
    with open(filename,'r') as fr:
        while True:
            line = fr.readline()
            if line in ["","\r\n",'\n',None]:
                break
            if ipaddress not in line.split(" ")[0]:
                    continue
            informationlist = line.split(" ")
            accesstime = informationlist[3].split('[')[-1].split(']')[0]
            method = informationlist[5][1:]
            action = informationlist[6]
            try:
                website = informationlist[10]
            except:
                website = '-'
            statuscode = informationlist[8]
            try:
                useragent = ''
                for index in range(11,25):
                    useragent += informationlist[index] + ' '
            except:
                pass
            string = """
            ***************************************************************************************************
            访问源IP地址:%s
            访问时间:%s
            请求方法:%s
            访问行为:%s
            响应状态:%s
            站点信息:%s
            客户端:%s
            ***************************************************************************************************
            """%(ipaddress,accesstime,method,action,statuscode,website,useragent[0:-2])
            print string

def GetAccessLogDetailByIPANDTime(filename,ipaddress,acstime):
    print "文件:%s"%filename
    acstime = TimeFormat(acstime)
    with open(filename,'r') as fr:
        while True:
            line = fr.readline()
            if line in ["","\r\n",'\n',None]:
                break
            if ipaddress not in line.split(" ")[0] or acstime not in line:
                    continue
            informationlist = line.split(" ")
            ip = informationlist[0]
            accesstime = informationlist[3].split('[')[-1].split(']')[0]
            method = informationlist[5][1:]
            action = informationlist[6]
            try:
                website = informationlist[10]
            except:
                website = '-'
            statuscode = informationlist[8]
            try:
                useragent = ''
                for index in range(11,25):
                    useragent += informationlist[index] + ' '
            except:
                pass
            string = """
            ***************************************************************************************************
            访问源IP地址:%s
            访问时间:%s
            请求方法:%s
            访问行为:%s
            响应状态:%s
            站点信息:%s
            客户端:%s
            ***************************************************************************************************
            """%(ip,accesstime,method,action,statuscode,website,useragent[0:-2])
            print string

def GetAccessLogDetailByIPANDDate(filename,ipaddress,date):
    print "文件:%s"%filename
    date= TimeFormat(date).split(":")[0]
    with open(filename,'r') as fr:
        while True:
            line = fr.readline()
            if line in ["","\r\n",'\n',None]:
                break
            if ipaddress not in line.split(" ")[0] or date not in line:
                continue
            informationlist = line.split(" ")
            ip = informationlist[0]
            accesstime = informationlist[3].split('[')[-1].split(']')[0]
            method = informationlist[5][1:]
            action = informationlist[6]
            try:
                website = informationlist[10]
            except:
                website = '-'
            statuscode = informationlist[8]
            try:
                useragent = ''
                for index in range(11,25):
                    useragent += informationlist[index] + ' '
            except:
                pass
            string = """
            ***************************************************************************************************
            访问源IP地址:%s
            访问时间:%s
            请求方法:%s
            访问行为:%s
            响应状态:%s
            站点信息:%s
            客户端:%s
            ***************************************************************************************************
            """%(ip,accesstime,method,action,statuscode,website,useragent[0:-2])
            print string
