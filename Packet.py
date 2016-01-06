import sys
import time
import socket
import struct
import binascii
import platform
from ctypes import *

class MySocketError(Exception):
    """any socket error"""
    def __init__(self,e,msg=''):
        if msg:
            self.args = (e,msg)
            self.code = e
            self.msg  = msg
        elif type(e) is int:
            self.args = (e,socket.errorTab[e])
            self.code = e
            self.msg  = socket.errorTab[e]

        else:
            args = e.args
            print(locals())
            try:
                msg = socket.errorTab[e.errno]
            except:
                msg = ''
            self.args = (e.errno,msg)
            self.code = e.errno
            self.msg  = msg

class Packet():

    MAC_Src = '123456778899'
    MAC_Dst = '123456abcdef'
    Eth_Typ = '0800'

    IP_Ver = 0
    IP_TOS = 0
    IP_Len = 0
    IP_IDE = 11671
    IP_Flg = 0x0040
    IP_TTL = 64
    IP_PRO = 0
    IP_CHK = 0
    IP_Src = '127.0.0.1'
    IP_Dst = '127.0.0.1'

    UDP_Scp = 4000
    UDP_Dtp = 8000
    UDP_Len = 0
    UDP_CHK = 0

    TCP_Scp = 62857
    TCP_Dtp = 8080
    TCP_Seq = 0x21763e4f
    TCP_Ack = 0x8b39b7c1
    TCP_Len = 0
    TCP_Flg = 0x18
    TCP_Win = 65523
    TCP_CHK = 0
    TCP_Opt = '0101080a0111470b09ef276f'

    Adapter = None
    Buffer  = None
    Socket  = None
    Pcap_t  = None
    ErrBuf  = None
    usPcap  = False
    PyVer2  = False

    def __init__(self, usePcap = False):
        self.Buffer = ''
        self.usPcap = usePcap
        self.PyVer2 = platform.python_version()[0]=='2'
        if not self.usPcap:
            try:
                self.Socket = socket.socket(socket.AF_INET,socket.SOCK_RAW)#,socket.IPPROTO_ICMP)
                self.Socket.setsockopt(socket.IPPROTO_IP,socket.IP_HDRINCL,1)
                self.Socket.setsockopt(socket.SOL_SOCKET,socket.SO_SNDTIMEO,1000)
            except socket.error as e:
                #self.Socket.close()
                raise MySocketError(e)
        else:
            from winpcapy import pcap_t,PCAP_ERRBUF_SIZE,pcap_open_live,PCAP_OPENFLAG_PROMISCUOUS
            self.Adapter = b'rpcap://\Device\NPF_{C224DE63-2D6E-4812-A601-827B3BF2E962}'
            self.Pcap_t = pcap_t
            self.ErrBuf = create_string_buffer(PCAP_ERRBUF_SIZE)
            self.Pcap_t = pcap_open_live(self.Adapter,65536,PCAP_OPENFLAG_PROMISCUOUS,1000,self.ErrBuf)
            if not bool(self.Pcap_t):
                print("Unable to open the adapter. It is not supported by WinPcap")
        print("__init__ OK !!!")

    def FindAdapter(self):
        from winpcapy import pcap_if_t,pcap_findalldevs,pcap_freealldevs
        alldevs = POINTER(pcap_if_t)()
        if pcap_findalldevs(byref(alldevs),self.ErrBuf) == -1:
            print("Error in pcap_findalldevs: %s\n" % self.ErrBuf.value)
        i=0
        try:
            d = alldevs.contents
        except:
            print("Error in pcap_findalldevs: %s" % self.ErrBuf.value)
        while d:
            i = i + 1
            print("%d. %s" % (i, d.name))
            if(d.description):
                print("  (%s)\n" % (d.description))
            else:
                print("  (No description available)\n")
            if d.next:
                d = d.next.contents
            else:
                d = False
        if i == 0:
            print("No interfaces found! Make sure WinPcap is installed.")
        else:
            pcap_freealldevs(alldevs)

    def CheckSum(self, buffer = None):
        if buffer is None:
            return False
        if len(buffer)%2:
            buffer += b'\x00'
        if self.PyVer2:
            cksum = sum( (ord(buffer[n+1])<<8)+ord(buffer[n]) for n in range(0,len(buffer),2) ) & 0xffffffff
        else:
            cksum = sum( (buffer[n+1]<<8)+buffer[n] for n in range(0,len(buffer),2) ) & 0xffffffff
        cksum = (cksum >> 16) + (cksum & 0xffff)
        cksum += (cksum >>16)
        return (~cksum) & 0xffff

    def BuildIP(self,Len):
        buffer = b''
        IP_Version = 4
        IP_Header_Length = 20
        self.IP_Ver = ( 4 << 4 | int( IP_Header_Length / 4 ) )
        self.IP_Len = Len + 20
        Lenth = socket.htons(self.IP_Len)
        Ident = socket.htons(self.IP_IDE)
        Src = struct.unpack("L",socket.inet_aton(self.IP_Src))[0]
        Dst = struct.unpack("L",socket.inet_aton(self.IP_Dst))[0]
        buffer = struct.pack("BBHHHBBHLL",self.IP_Ver,self.IP_TOS,Lenth,Ident,self.IP_Flg,self.IP_TTL,self.IP_PRO,0,Src,Dst)
        self.IP_CHK = self.CheckSum(buffer)
        buffer = buffer[:10] + struct.pack("H",self.IP_CHK) + buffer[12:]
        print(binascii.b2a_hex(buffer))
        return buffer

    def BuildUDP(self,data): #data is bytes
        buffer = b''
        self.UDP_Len = 8 + len(data)
        self.IP_PRO  = socket.IPPROTO_UDP
        Src = struct.unpack("L",socket.inet_aton(self.IP_Src))[0]
        Dst = struct.unpack("L",socket.inet_aton(self.IP_Dst))[0]
        Sport = socket.htons(self.UDP_Scp)
        Dport = socket.htons(self.UDP_Dtp)
        Lenth = socket.htons(self.UDP_Len)
        buffer = struct.pack("LLBBHHHHH",Src,Dst,0,self.IP_PRO,Lenth,Sport,Dport,Lenth,0) + data
        self.UDP_CHK = self.CheckSum(buffer)
        buffer = buffer[12:18] + struct.pack("H",self.UDP_CHK) + buffer[20:]
        print(binascii.b2a_hex(buffer))
        return buffer

    def BuildTCP(self,data): #data is bytes
        buffer = b''
        Src = struct.unpack("L",socket.inet_aton(self.IP_Src))[0]
        Dst = struct.unpack("L",socket.inet_aton(self.IP_Dst))[0]
        Opt = binascii.a2b_hex(self.TCP_Opt)
        self.TCP_Len = 20 + len(Opt) + len(data)
        self.IP_PRO  = socket.IPPROTO_TCP
        Lenth = socket.htons(self.TCP_Len)
        Sport = socket.htons(self.TCP_Scp)
        Dport = socket.htons(self.TCP_Dtp)
        Winsz = socket.htons(self.TCP_Win)
        Seque = socket.htonl(self.TCP_Seq)
        Acknw = socket.htonl(self.TCP_Ack)
        Lenrs = ( int(self.TCP_Len/4)<<4 | 0 ) & 0xff
        buffer = struct.pack("LLBBHHHLLBBHHH",Src,Dst,0,self.IP_PRO,Lenth,Sport,Dport,Seque,Acknw,Lenrs,self.TCP_Flg,Winsz,0,0)
        buffer = buffer + Opt + data
        self.TCP_CHK = self.CheckSum(buffer)
        buffer = buffer[12:28] + struct.pack("H",self.TCP_CHK) + buffer[30:]
        print(binascii.b2a_hex(buffer))
        return buffer

    def Build(self,Data=b''):  #data is bytes
        #self.Buffer = self.BuildUDP(Data)
        #self.Buffer = self.BuildIP(self.UDP_Len) + self.Buffer
        self.Buffer = self.BuildTCP(Data)
        self.Buffer = self.BuildIP(self.TCP_Len) + self.Buffer
        print(binascii.b2a_hex(self.Buffer))

    def Send(self):
        if self.Buffer is None:
            return False
        if self.usPcap:
            return self.PcapSend()
        if not self.Socket:
            return False
        try:
            print(binascii.b2a_hex(self.Buffer))
            self.Socket.sendto(self.Buffer,0,(self.IP_Dst,self.TCP_Dtp))
        except socket.error as e:
            #self.Socket.close()
            raise MySocketError(e)
            return False
        return True

    def PcapSend(self):
        from winpcapy import pcap_sendpacket,pcap_geterr
        self.Buffer = binascii.a2b_hex(self.MAC_Dst+self.MAC_Src+self.Eth_Typ) + self.Buffer
        print(binascii.b2a_hex(self.Buffer))
        if pcap_sendpacket(self.Pcap_t,cast(self.Buffer,POINTER(c_ubyte)),len(self.Buffer)) == 0:
            return True
        else:
            print ("Error sending the packet: %s" % pcap_geterr(self.Pcap_t))
            return False

    def Close(self):
        time.sleep(1)
        if self.usPcap:
            from winpcapy import pcap_close
            pcap_close(self.Pcap_t)
        else:
            self.Socket.close()

def Main():
    cmd = "Command:\r\nL: %d\r\n\r\n"
    msg = "1234567890"
    pkg = Packet(usePcap = True)
    pkg.Build((cmd%len(msg)+msg).encode("utf-8"))
    pkg.Send()
    pkg.Close()

if __name__ == "__main__":
    sys.exit(Main())
