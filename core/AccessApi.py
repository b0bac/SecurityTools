# -*- coding:utf-8 -*-

import os

#定义全局变量和函数
AccessLogFileList = []

def GetWorkPath():
    return str(os.getcwd())+'/'

def GetAllAccessLogFile(filepath=None,filename="access"):
    global AccessLogFileList
    if filepath == None:
        rootdir = GetWorkPath()
    else:
        rootdir = filepath
    for parents,dirs,filenames in os.walk(rootdir):
        for logfilename in filenames:
            if filename in logfilename.lower() and 'py' not in logfilename:
                AccessLogFileList.append(rootdir+logfilename)

def TimeFormat(accesstime,timezone=None):
    monthlist = {"01":"Jan","02":"Feb","03":"Mar","04":"Apr","05":"May","06":"Jun","07":"Jul","08":"Aug","09":"Sep","10":"Oct","11":"Nov","12":"Dec"}
    accesstimelist = accesstime.split("-")
    year = accesstimelist[0]
    month = accesstimelist[1]
    day = accesstimelist[2]
    try:
        timedetail = accesstimelist[3]
    except:
        timedetail = ''
    if timezone != None:
        if 'e' in timezone:
            timezone = '+%s00'
        elif 'w' in timezone:
            timezone = '-%s00'
        else:
            timezone = None
    if timezone != None:
        return '%s/%s/%s:%s %s'%(day,monthlist[str(month)],year,timedetail,timezone)
    else:
        return '%s/%s/%s:%s'%(day,monthlist[str(month)],year,timedetail)
