# -*- coding:utf-8 -*-

'''
传输层包解析
'''

import dpkt


#定义包解析类
class IcmpAnylast(object):
    '''数据报文传输层分解'''
    def __init__(self,packet):
        '''初始化传输层数据'''
        self.packet = packet

    def getCode(self):
        '''返回ICMP Code'''
        return self.packet.code

    def getType(self):
        '''返回目的端口'''
        return self.packet.type

    def getData(self):
        '''获取传输层数据'''
        return self.packet.data
