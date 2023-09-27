# -*- coding:utf-8 -*-

from core.AccessApi import *
from core.AccessCount import *
from core.AccessDetail import *
from core.AccessFreeze import *
from core.AccessWebshell import *
from optparse import OptionParser


__author__ = "wechat:cr1914518025"
__version__ = """
    AccessLogAnylast V1.0.1
    python AccessLogAnylast.py -parameter-key [parameter-value]
"""

if __name__ == "__main__":
    parser = OptionParser()
    parser.add_option("-f", "--floder",dest="filepath",help="access log file path")
    parser.add_option("-t", "--time",dest="accesstime",help="set search time")
    parser.add_option("-d", "--date",dest="accessdate",help="set search date")
    parser.add_option("-c", "--count",action='store_true',dest="count",help="show count information")
    parser.add_option("-p", "--payload",dest="payload",help="set search payload")
    parser.add_option("-a","--address",dest="ipaddress",help="set search ipaddress")
    parser.add_option("-v", "--version",action='store_true',dest="version",help="show document")
    parser.add_option("-i","--detail",action='store_true',dest="detail",help="show detail")
    parser.add_option("-s","--shell",action='store_true',dest="webshell",help="show suspicious webshell")
    parser.add_option("-g","--ipflag",dest="ipposition",help="ip position in logfile")
    parser.add_option("-n","--name",dest="filename",help="filename flag")
    (options, args) = parser.parse_args()
    if options.version:
        print __version__
        exit(0)
    if options.filename == None:
        options.filename == "access"
    if options.ipposition == None:
        options.ipposition = "1"
    if options.filepath == None:
        GetAllAccessLogFile(filepath=None,filename=options.filename)
    else:
        GetAllAccessLogFile(filepath=options.filepath,filename=options.filename)
    mylogfilelist = AccessLogFileList
    if options.count:
        if options.accesstime != None:
            for filename in mylogfilelist:
                GetAccessIPListByTime(filename,accesstime=options.accesstime,ipflag=options.ipposition)
        elif options.accessdate != None:
            for filename in mylogfilelist:
                GetAccessIPListByDate(filename,date=options.accessdate,ipflag=options.ipposition)
        else:
            for filename in mylogfilelist:
                #print options.ipposition
                GetAccessIPList(filename,ipflag=options.ipposition)
        exit(0)
    if options.detail:
        if options.ipaddress != None:
            if options.accesstime != None:
                for filename in mylogfilelist:
                    GetAccessLogDetailByIPANDTime(filename,ipaddress=options.ipaddress,acstime=options.accesstime)
            elif options.accessdate != None:
                for filename in mylogfilelist:
                    GetAccessLogDetailByIPANDDate(filename,ipaddress=options.ipaddress,date=options.accessdate)
            else:
                for filename in mylogfilelist:
                    GetAccessLogDetailByIP(filename,ipaddress=options.ipaddress)
        else:
            for filename in mylogfilelist:
                GetAccessLogDetail(filename)
        exit(0)
    if options.webshell:
        for filename in mylogfilelist:
            WebShellScan(filename)
        exit(0)
    if options.payload != None:
        for filename in mylogfilelist:
            GetFreezeWebAttack(filename,options.payload)
            exit(0)
