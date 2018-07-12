#coding=utf-8
#TCP服务端

import socket, SocketServer
import select
import ssl_proxy_main
from ssl_proxy_main import *


g_messageHost = ""
g_messagePort = ""
gSecretKey = ""
gIpFromSocket = {}


class ProxyGetData(SocketServer.ThreadingMixIn, SocketServer.TCPServer):
    def __init__(self, addr, port ):
        self.tcpServerSocket=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        self.tcpServerSocket.bind((addr, port))
        self.tcpServerSocket.listen(5)
        sys.stdout.write( "the ssl_proxy_main is %s" % gIpFromSocket)

        self.run()
        
    def getHostFromData(self, s, recvData):
        if not recvData:
            return None
        global g_messageHost
        global g_messagePort
        global gSecretKey
        recvKeyList = recvData.split(":")
        if "key:" in recvData:
            if len(recvKeyList) < 1:
                return None
            gSecretKey = recvKeyList[1]

        elif "isip:" in recvData:
            recvIpList = recvData.split(":")
            if len(recvIpList) < 1:
                return None

            
            if (recvIpList[1] in gIpFromSocket) and (gIpFromSocket[recvIpList[1]] == recvIpList[2]): 
                sys.stdout.write( "the recvIpList is %s and the send 1" % recvIpList)
                s.sendall("1") 
            else:
                sys.stdout.write( "the recvIpList is %s and the send 0" % recvIpList)
                s.sendall("0")
        else:
            recvList = recvData.split(":")
            g_messageHost = recvList[0]
            g_messagePort = recvList[1]
            sys.stdout.write( "recv new ip = %s:%s" % ( g_messageHost, g_messagePort ))
            
        
        

        
    def getDataFromSocket(self, newSocket) :
        input_list = [newSocket]
        while True:
            stdinput, stdoutput, stderr = select.select(input_list, [], [])
            for input_one in stdinput:
                if input_one:
                    newrecv = newSocket.recv(1024)
                    if not newrecv:
                        sys.stdout.write( "not newrecv!!!")
                        newSocket.close()
                        input_list.remove(newSocket)
                        return
                    else:
                        sys.stdout.write( "the new recv is %s" % newrecv)
                        self.getHostFromData(newSocket, newrecv)

    def run(self):
        while True:
            newSocket,clientAddr = self.tcpServerSocket.accept()   
            self.getDataFromSocket(newSocket)
        self.tcpServerSocket.close()



if __name__=='__main__':
    gIpFromSocket = {}
   
    server = ProxyGetData(('127.0.0.1', 9998))
    server.run()

 