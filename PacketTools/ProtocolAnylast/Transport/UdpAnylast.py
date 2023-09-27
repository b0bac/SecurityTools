# -*- coding:utf-8 -*-

'''
传输层包解析
'''

import dpkt


#定义包解析类
class UdpAnylast(object):
    '''数据报文传输层分解'''
    def __init__(self,packet):
        '''初始化传输层数据'''
        self.packet = packet

    def getSrc(self):
        '''返回源端口'''
        return self.packet.sport

    def getDst(self):
        '''返回目的端口'''
        return self.packet.dport

    def getSize(self):
        '''获取数据包大小'''
        return self.packet.ulen

    def getData(self):
        '''获取传输层数据'''
        return self.packet.data
