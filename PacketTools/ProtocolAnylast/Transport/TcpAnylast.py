# -*- coding:utf-8 -*-

'''
传输层包解析
'''

import dpkt


#定义包解析类
class TcpAnylast(object):
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

    def getAckNumber(self):
        '''返回确认号'''
        return self.packet.ack

    def getSequence(self):
        return self.packet.seq

    def getFlags(self):
        '''返回TCP标志位'''
        flags = str(bin(self.packet.flags)).split("b")[-1]
        size = 12 - len(flags)
        flags = list("%s%s"%('0'*size,str(flags)))
        urg = flags[6]
        ack = flags[7]
        psh = flags[8]
        rst = flags[9]
        syn = flags[10]
        fin = flags[11]
        return (urg,ack,psh,rst,syn,fin)

    def getWindows(self):
        '''返回窗口值'''
        return self.packet.win

    def getUrgentPointer(slef):
        '''返回报文的ID'''
        return self.packet.urp

    def getSize(self):
        '''获取数据包大小'''
        return self.packet.len

    def getData(self):
        '''获取传输层数据'''
        return self.packet.data
