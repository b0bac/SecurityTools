# -*- coding:utf-8 -*-

import os
import sys
from AccessApi import *
sys.path.append("../")
from settings.settings import *

def GetPageAccessModel(filename):
    accessModel = {}
    with open(filename,'r') as fr:
        while True:
            line = fr.readline()
            informationlist = line.split(" ")
            if line in ["","\r\n",'\n',None]:
                break
            accesspage= informationlist[6]
            if accesspage not in accessModel:
                accessModel[accesspage] = {}
            ip = informationlist[0]
            if ip not in accessModel:
                accessModel[accesspage][ip] = 1
            accessModel[accesspage][ip] += 1
    return accessModel

def GetSuspiciousPage(accessModel):
    PageAccessModel = []
    for key in accessModel:
        ipcount = len(accessModel[key].keys())
        accesscount = 0
        for ip in accessModel[key]:
            accesscount += accessModel[key][ip]
        PageAccessModel.append({"page":key,"ipcount":ipcount,"accesscount":accesscount})
    resultlist = sorted(PageAccessModel ,key = lambda x:(x['ipcount'],x['accesscount']),reverse=False)
    for index,item in enumerate(resultlist):
        if index > 49 or item["ipcount"] > WebShellScanAccessIPCount or item["accesscount"] > WebShellScanAccessCount:
            break
        print "可疑排序:%s  页面:%s  访问IP地址数量:%s  访问总次数:%s"%((index+1),item["page"],str(item["ipcount"]),str(item["accesscount"]))


def WebShellScan(filename):
    ret = GetPageAccessModel(filename)
    GetSuspiciousPage(ret)
