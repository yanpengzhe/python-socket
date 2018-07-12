#coding=utf-8
#TCP服务端

from ssl_proxy_data import *
import socket, SocketServer
import threading
import thread
import select
import ssl_proxy_data
import win32gui
import win32con
import ctypes.wintypes
import re
import sys


BUFLEN=8192
threadHostDict = {}
gAppSecOri = ""
gPublicKeyOwn = ""
gPrivateKeyOwn = ""


#用来发送给client的数据结构
class COPYDATASTRUCT(ctypes.Structure):
    _fields_ = [
        ('dwData', ctypes.wintypes.LPARAM),
        ('cbData', ctypes.wintypes.DWORD),
        ('lpData', ctypes.c_wchar_p) 
        #formally lpData is c_void_p, but we do it this way for convenience
    ]

class Proxy(SocketServer.StreamRequestHandler):
    
    def __init__(self, conn,addr):
        self.clientsocket = conn
        self.addr = addr
        self.port = 80
        #MFC 窗体的handler
        self.winHandler = "{37089816-6FF0-47e2-8218-4CEB31037E41}"
        self.run()
        
    #从收到的数据中获取对应的HOST
    def getMultiHost(self, data):
        if not data:
            return []
        if 'HTTP' not in data or '200' not in data:
            return []
        dataList = data.split("\r\n")
        threadHostDictTmp = {}
        for oneData in dataList:
            if not oneData:
                continue
            reip = re.compile(r'(?<![\.\d])(?:\d{1,3}\.){3}\d{1,3}(?![\.\d])')
            ipList = reip.findall(oneData)
            if not ipList:
                continue
            for oneIp in ipList:
                if not oneIp:
                    continue
                ipPortList = oneData.split(",")
                for oneIpPort in ipPortList:
                    if oneIp in oneIpPort:
                        threadHostDictTmp[oneIp] = oneIpPort.split(":")[1]
                
        sys.stdout.write("the threadHostDictTmp is %s" % threadHostDictTmp)
        ssl_proxy_data.gIpFromSocket = threadHostDictTmp

    #从接收的消息中获取对应的发送人以及发送内容
    def getMessageAndSender(self, data):
        if not data or 'X\T' not in data or 'wx@' not in data:
            return None
        try:
            dataList = data.split("X\T")
            orirecv =  dataList[-1]
            messageData = orirecv.split("")[0]
            sender = orirecv.split("realFromId")[1].split("realToId")[0].split("")[0].replace(" ","")
            recver = orirecv.split("realToId")[1].split("")[1].replace(" ","")
            sys.stdout.write( "------------------print message ---------------")
            sys.stdout.write( "the sender is %s" % sender)
            sys.stdout.write( "the recver is %s" % recver)
            sys.stdout.write( "the messageData is %s" % messageData)
            try:
                messageData = messageData.decode('utf8')
            except:
                messageData.decode('latin-1').encode("utf-8")

            sender = sender.decode("utf8").replace("\x00","").replace("\r", "")
            recver = recver.decode("utf8").replace("\x00","").replace("\r", "")
            jsondata = {"sender":sender, "recver":recver, "message":messageData}
            self.buildWindow(jsondata)
            return jsondata
        except Exception,e:
            sys.stdout.write( "function getMessageAndSender ERROR!!! the error is %s" % e)
            return None
    
    def buildWindow(self, strSend):
        try:
            #将json拆解成一个string，发送给MFC窗体
            strSendFormat = strSend
            if isinstance(strSend, dict):
                strSendFormat = "{"
                for key in strSend:
                    strSendFormat += "\"%s\":\"%s\"" % (key, strSend[key]) 
                strSendFormat += "}"    
                
            win = win32gui.FindWindow(None, self.winHandler)
            copyDataCmd = COPYDATASTRUCT()
            copyDataCmd.dwData = 1
            copyDataCmd.lpData = strSendFormat
            copyDataCmd.cbData =  (len(strSendFormat)+1) * 2            
            win32gui.SendMessage(win, win32con.WM_COPYDATA, None, copyDataCmd);
            return True
        except Exception,e:
            sys.stdout.write( "function buildWindow ERROR and the err_msg is %s" % e)
            return False
         
        
    def run(self):
        #链接服务端
        self.taobaosocket = None
        inputs = [self.clientsocket]
        localData = ""

        while inputs:
            #最后一个参数是超时时间，此处省略,select函数阻塞进程，
            #直到inputs中的套接字被触发（在此例中，套接字接收到客户端发来的握手信号，从而变得可读，满足select函数的“可读”条件），rlist返回被触发的套接字（服务器套接字）；
            rlist, wlist, elist = select.select(inputs, [], [])
            if not (rlist or wlist or elist) :
                break;
            #判断当前来源是server还是client
            if rlist[0] == self.taobaosocket:
                threadId = thread.get_ident()  
                try:
                    data = self.taobaosocket.recv(BUFLEN)
                    sys.stdout.write( "the self.taobaosocket data is %s" % data)
                except Exception,e:
                    sys.stdout.write( "the self.taobaosocket recv error and the error is %s" % e)
        
                #获取对应的发送消息体和发送人
                jsonBuild = self.getMessageAndSender(data)
                self.getMultiHost(data)
                self.clientsocket.sendall(data)
                #如果data不存在，关闭所有socket并退出
                if not data:
                    self.clientsocket.shutdown(2)
                    self.clientsocket.close()
                    self.taobaosocket.close()
                    inputs.remove(self.taobaosocket)
                    inputs.remove(self.clientsocket)
                    break  
            elif rlist[0] == self.clientsocket: 
                data = self.clientsocket.recv(BUFLEN)
                sys.stdout.write( "the clientsocket data is %s" % data)
                #如果这里data返回None说明当前的链接已中断
                if not data:
                    if self.taobaosocket:
                        self.taobaosocket.shutdown(2)
                        self.taobaosocket.close()
                        inputs.remove(self.taobaosocket)
                    self.clientsocket.close()
                    inputs.remove(self.clientsocket)
                    break

                if self.taobaosocket == None :
                    hostSplit = self.get_headers(data)
                    hostPort = self.port
                    if not hostSplit: 
                        hostSplit = ssl_proxy_data.g_messageHost  
                        hostPort = ssl_proxy_data.g_messagePort                
                        if not hostSplit :
                            continue
                    self.taobaosocket = socket.socket()                 
                    self.taobaosocket.connect((hostSplit, int(hostPort))) 
                    if self.taobaosocket not in inputs:
                        inputs.append(self.taobaosocket)
                self.taobaosocket.sendall(data)
                
                   
            else:
                sys.stdout.write( "nothing socket matched!!!\n")
            #处理异常
            for s in elist:
                inputs.remove(s)
                s.shutdown(2)
                s.close()
                break
        #进程结束，退出
        thread.exit()



    #获取data中的host，使用字符串切分的方法  
    def get_headers(self, data):
        if not data:
            return None
        host_res = None
        data_list = data.split("\n");
        if not data_list or len(data_list) == 0:
            return None
        for one_data in data_list:
            if 'Host' in one_data:
                one_cell = one_data.split('Host:')
                if not one_cell:
                    continue
                if len(one_cell) > 1:
                    host_res = one_cell[1].strip(" ").strip("\r")  
                    break       
        return host_res

class Server(SocketServer.ThreadingMixIn, SocketServer.TCPServer):
    def __init__(self, addr, port ):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_address = (addr, port)
        #服务器绑定，被构造器调用
        self.server_bind()
        #服务器激活
        self.server_activate()
        self.start()

    def shutdown_request(self, request):
        request.shutdown(2)

    def start(self):
        while True:
            try:
                #获取对应的request以及客户端访问地址端口
                conn,addr = self.get_request()
                thread.start_new_thread(Proxy,(conn, addr))
            except Exception,e:
                sys.stdout.write( "the exception is %s" % e)
                thread.exit()
                pass


if __name__=='__main__':
    thread.start_new_thread(ProxyGetData,('127.0.0.1', 9998))
    server = Server('127.0.0.1', 9980)
    server.start()

 