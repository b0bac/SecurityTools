# -*- coding:utf-8 -*-


# 定义TCP流解析的存储结构
class StreamStruct(object):
    '''TCP流解析实例存储结构'''
    def __init__(self):
        '''结构初始化'''
        self._stream = {}
        self.size = 0

    def addStream(self,streamhash,stream):
        '''添加流实例'''
        self._stream[streamhash] = stream
        self.size += 1

    def getStream(self,streamhash):
        '''获取流实例'''
        return self._stream.get(streamhash,"None")

    def getHashs(self):
        return self._stream.keys()

    def getStreams(self):
        return self._stream
