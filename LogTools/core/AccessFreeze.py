# -*- coding:utf-8 -*-

import os
from AccessApi import *

def GetFreezeWebAttack(filename,payload):
    command = "cat %s | grep %s | sort -r | uniq -c| sort -n"%(filename,payload)
    result = os.popen(command)
    print result.read()
