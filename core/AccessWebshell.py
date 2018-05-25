# -*- coding:utf-8 -*-

import os
import sys
from AccessApi import *
sys.path.append("../")
from settings.settings import *


keywords = [
    "ghost",
    "gh0st",
    "=eval",
    "evil",
    "asp;",
    "php;",
    "jsp;",
    "aspx;",
    "jspx;",
    "php3;",
    "php4;",
    "php5;",
    ".asp/",
    ".aspx/",
    ".jsp/",
    ".jspx/",
    ".php/",
    "jpg/",
    "jpeg/",
    "png/",
    "php%00",
    "asp%00",
    "jsp%00",
    "aspx%00",
    "jspx%00",
    "php ",
    "asp ",
    "jsp ",
    "aspx ",
    "jspx ",
    ".txt/",
    "=system(",
    ".jsp.",
    ".php.",
    ".php3.",
    ".php4.",
    ".php5.",
    ".jspx.",
    ".asp.",
    ".aspx.",
    "cmd",
    "phpinfo",
    "=whoami",
    "=id",
    "=bash",
    "=ls",

]

def KeywordCheck(string):
    for word in keywords:
        if word in string.lower():
            return (True,word)
    return (False,None)

def GetPageAccessModel(filename):
    accessModel = {}
    keywordPage = []
    with open(filename,'r') as fr:
        while True:
            line = fr.readline()
            informationlist = line.split(" ")
            if line in ["","\r\n",'\n',None]:
                break
            accesspage= informationlist[6]
            ret = KeywordCheck(accesspage)
            if ret[0]:
                keywordPage.append((accesspage,ret[1]))
            if accesspage not in accessModel:
                accessModel[accesspage] = {}
            ip = informationlist[0]
            if ip not in accessModel:
                accessModel[accesspage][ip] = 1
            accessModel[accesspage][ip] += 1
    return accessModel,keywordPage

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
        if int(index) > 10 or item["ipcount"] > WebShellScanAccessIPCount or item["accesscount"] > WebShellScanAccessCount:
            break
        print "可疑页面:%s"%item["page"],"可疑原因:访问率低"


def WebShellScan(filename):
    ret1,ret2 = GetPageAccessModel(filename)
    for page in ret2:
        print "可疑页面:",page[0]," 可疑原因:",page[1]
    GetSuspiciousPage(ret1)
