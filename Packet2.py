import sys
import time
import socket
import struct
import random
import binascii
import platform
import threading

def checksum(data):
    s = 0
    n = len(data) % 2
    for i in range(0, len(data)-n, 2):
        s+= ord(data[i]) + (ord(data[i+1]) << 8)
    if n:
        s+= ord(data[i+1])
    while (s >> 16):
        s = (s & 0xFFFF) + (s >> 16)
    s = ~s & 0xffff
    return s
        
class layer():
    pass

class ETHER(object):
    def __init__(self, src, dst, Type=0x0800): # ETH_P_IP = 0x0800, Internet Protocol Packet
        self.src = src
        self.dst = dst
        self.typ = Type
    def pack(self):
        ethernet = struct.pack('!6s6sH', self.dst, self.src, self.typ)
        return ethernet

class IP(object):
    def __init__(self, src='127.0.0.1', dst='127.0.0.1', data='', proto=socket.IPPROTO_TCP):
        self.IP_Version     = 4                             #  4bit
        self.IP_HeadLen     = 20                            #  4bit
        self.IP_SvcType     = 0 # Type of Service           #  8bit
        self.IP_TotalLen    = self.IP_HeadLen + len( data ) # 16bit
        self.IP_Identify    = 27290#0 # random.randint(0, 65535)  # 16bit
        self.IP_Flags       = 0x02 # Don't fragment         #  3bit
        self.IP_FgOffset    = 0                             # 13bit
        self.IP_TTL         = 64                            #  8bit
        self.IP_Protocol    = proto                         #  8bit
        self.IP_CheckSum    = 0 # will be filled by kernel  # 16bit
        self.IP_Src         = socket.inet_aton( src )       # 32bit
        self.IP_Dst         = socket.inet_aton( dst )       # 32bit
    def __str__(self):
        return '''
Version\t\t: {0.IP_Version}
Header Length\t: {0.IP_HeadLen} bytes
Type of Service\t: {0.IP_SvcType}
Total Length\t: {0.IP_TotalLen}
Identification\t: 0x{0.IP_Identify:08X}({0.IP_Identify})
Flags\t\t: {0.IP_Flags}
Fragment offset\t: {0.IP_FgOffset}
Time to live\t: {0.IP_TTL}
Protocol\t: {0.IP_Protocol}
Header checksum\t: 0x{1:04X}
Source\t\t: {2}
Destination\t: {3}
'''.strip().format(self, socket.htons(self.IP_CheckSum), socket.inet_ntoa(self.IP_Src), socket.inet_ntoa(self.IP_Dst))
    def pack(self):
        Header = struct.pack("!BBHHHBBH4s4s",
                             ( self.IP_Version << 4 | int( self.IP_HeadLen / 4 ) ),
                             self.IP_SvcType,
                             self.IP_TotalLen,
                             self.IP_Identify,
                             ( (self.IP_Flags << 13) + self.IP_FgOffset ),
                             self.IP_TTL,
                             self.IP_Protocol,
                             self.IP_CheckSum,
                             self.IP_Src,
                             self.IP_Dst)
        self.IP_CheckSum    = checksum( Header )
        self.IP_Header      = Header[:10] + struct.pack("H", self.IP_CheckSum) + Header[12:]
        return self.IP_Header
    def unpack(self, packet):
        self.IP_HeadLen     = (ord(packet[0]) & 0xf) * 4
        self.IP_Header      = packet[:self.IP_HeadLen]
        Unpack = struct.unpack("!BBHHHBBH4s4s", self.IP_Header)
        self.IP_Version     = Unpack[0] >> 4
        self.IP_SvcType     = Unpack[1]
        self.IP_TotalLen    = Unpack[2]
        self.IP_Identify    = Unpack[3]
        self.IP_Flags       = Unpack[4] >> 13
        self.IP_FgOffset    = Unpack[4] & 0x1FFF
        self.IP_TTL         = Unpack[5]
        self.IP_Protocol    = Unpack[6]
        self.IP_CheckSum    = socket.htons( Unpack[7] )
        self.IP_Src         = Unpack[8]
        self.IP_Dst         = Unpack[9]
        
class TCP(object):
    def __init__(self, sip='127.0.0.1', spt=62857, dip='127.0.0.1', dpt=8080, data=b'', opt=b''):
        self.TCP_SrcPort    = spt                           # 16bit
        self.TCP_DstPort    = dpt                           # 16bit
        self.TCP_SeqNum     = 0x21763e4f                    # 32bit
        self.TCP_AckNum     = 0x8b39b7c1                    # 32bit
        self.TCP_Offset     = 5                             #  4bit
        self.TCP_Reserve    = 0                             #  4bit
        self.TCP_CWR        = 0                             #  1bit
        self.TCP_ECE        = 0                             #  1bit
        self.TCP_URG        = 0                             #  1bit
        self.TCP_ACK        = 1                             #  1bit
        self.TCP_PSH        = 0                             #  1bit
        self.TCP_RST        = 0                             #  1bit
        self.TCP_SYN        = 0                             #  1bit
        self.TCP_FIN        = 0                             #  1bit
        self.TCP_Window     = 65523                         # 16bit
        self.TCP_CheckSum   = 0                             # 16bit
        self.TCP_Urgent     = 0                             # 16bit
        self.TCP_Option     = opt
        self.TCP_Data       = data
        self.IP_Header      = IP(sip, dip, self.TCP_Data, socket.IPPROTO_TCP)
    def __str__(self):
        return '''
Source Port\t\t: {0.TCP_SrcPort}
Destination Port\t: {0.TCP_DstPort}
Sequence Number\t\t: 0x{0.TCP_SeqNum:08X}
Acknowledgment Number\t: 0x{0.TCP_AckNum:08X}
Header Length\t\t: {1}
Window Size\t\t: {0.TCP_Window}
Checksum\t\t: 0x{2:04X}
Urgent pointer\t\t: 0x{0.TCP_Urgent:04X}
NS\tCWR\tECE\tURG\tACK\tPSH\tRST\tSYN\tFIN
0\t{0.TCP_CWR}\t{0.TCP_ECE}\t{0.TCP_URG}\t{0.TCP_ACK}\t{0.TCP_PSH}\t{0.TCP_RST}\t{0.TCP_SYN}\t{0.TCP_FIN}
'''.strip().format(self, (self.TCP_Offset>>4) * 4, socket.htons(self.TCP_CheckSum))
    def pack(self):
        TCPHeaderLen        = 20
        self.TCP_Length     = TCPHeaderLen + len(self.TCP_Option) + len(self.TCP_Data)
        self.TCP_Offset     = ( int(self.TCP_Length/4)<<4 | 0 ) & 0xff
        self.TCP_Flags      = (self.TCP_CWR<<7) + (self.TCP_ECE<<6) + (self.TCP_URG<<5) + (self.TCP_ACK<<4) + (self.TCP_PSH<<3) + (self.TCP_RST<<2) + (self.TCP_SYN<<1) + self.TCP_FIN
        Header              = struct.pack("!4s4sBBHHHLLBBHHH",
                                          self.IP_Header.IP_Src,
                                          self.IP_Header.IP_Dst,
                                          0,
                                          self.IP_Header.IP_Protocol,
                                          self.TCP_Length,
                                          self.TCP_SrcPort,
                                          self.TCP_DstPort,
                                          self.TCP_SeqNum,
                                          self.TCP_AckNum,
                                          self.TCP_Offset,
                                          self.TCP_Flags,
                                          self.TCP_Window,
                                          self.TCP_CheckSum,
                                          self.TCP_Urgent)
        self.TCP_CheckSum   = checksum( Header + self.TCP_Option + self.TCP_Data )
        self.TCP_Header     = Header[12:28] + struct.pack("H", self.TCP_CheckSum) + Header[30:]
        return self.TCP_Header
    def unpack(self, packet):
        self.TCP_Length     = ( ord(packet[12]) >> 4 ) * 4
        self.TCP_Header     = packet[:20]
        self.TCP_Option     = packet[20:self.TCP_Length]
        self.TCP_Data       = packet[self.TCP_Length:]
        Unpack = struct.unpack("!HHLLBBHHH", self.TCP_Header)
        self.TCP_SrcPort    = Unpack[0]
        self.TCP_DstPort    = Unpack[1]
        self.TCP_SeqNum     = Unpack[2]
        self.TCP_AckNum     = Unpack[3]
        self.TCP_Offset     = Unpack[4] & 0xf0
        self.TCP_Reserve    = Unpack[4] & 0x0f
        self.TCP_CWR        = Unpack[5]>>7 & 0x01
        self.TCP_ECE        = Unpack[5]>>6 & 0x01
        self.TCP_URG        = Unpack[5]>>5 & 0x01
        self.TCP_ACK        = Unpack[5]>>4 & 0x01
        self.TCP_PSH        = Unpack[5]>>3 & 0x01
        self.TCP_RST        = Unpack[5]>>2 & 0x01
        self.TCP_SYN        = Unpack[5]>>1 & 0x01
        self.TCP_FIN        = Unpack[5]>>0 & 0x01
        self.TCP_Window     = Unpack[6]
        self.TCP_CheckSum   = socket.htons( Unpack[7] )
        self.TCP_Urgent     = Unpack[8]

class UDP(object):
    def __init__(self, sip='127.0.0.1', spt=62857, dip='127.0.0.1', dpt=8080, data=b''):
        self.UDP_Data       = data
        self.UDP_SrcPort    = spt                           # 16bit
        self.UDP_DstPort    = dpt                           # 16bit
        self.UDP_Length     = 8 + len( self.UDP_Data )      # 16bit
        self.UDP_CheckSum   = 0                             # 16bit
        self.IP_Header      = IP(sip, dip, self.UDP_Data, socket.IPPROTO_UDP)
    def __str__(self):
        return '''
Source Port\t\t: {0.UDP_SrcPort}
Destination Port\t: {0.UDP_DstPort}
Header Length\t\t: {0.UDP_Length}
Checksum\t\t: 0x{1:04X}
'''.strip().format(self, socket.htons(self.UDP_CheckSum))
    def pack(self):
        Header = struct.pack('!4s4sBBHHHHH',
                             self.IP_Header.IP_Src,
                             self.IP_Header.IP_Dst,
                             0,
                             self.IP_Header.IP_Protocol,
                             self.UDP_Length,
                             self.UDP_SrcPort,
                             self.UDP_DstPort,
                             self.UDP_Length,
                             self.UDP_CheckSum)
        self.UDP_CheckSum   = checksum( Header + self.UDP_Data )
        self.UDP_Header     = Header[12:18] + struct.pack("H", self.UDP_CheckSum) + Header[20:]
        return self.UDP_Header
    def unpack(self, packet):
        self.UDP_Header     = packet[:8]
        self.UDP_Data       = packet[8:]
        Unpack = struct.unpack("!HHHH", self.UDP_Header)
        self.UDP_SrcPort    = Unpack[0]
        self.UDP_DstPort    = Unpack[1]
        self.UDP_Length     = Unpack[2]
        self.UDP_CheckSum   = socket.htons( Unpack[3] )

def Main():
    ip = IP()
    tcp = TCP()
    udp = UDP()
    Socket = socket.socket(socket.AF_INET,socket.SOCK_RAW)#,socket.IPPROTO_ICMP)
    Socket.setsockopt(socket.IPPROTO_IP,socket.IP_HDRINCL,1)
    Socket.setsockopt(socket.SOL_SOCKET,socket.SO_SNDTIMEO,1000)
    Socket.bind( ('192.168.56.1', 80) )
    while True:
        (data, addr) = Socket.recvfrom(4096)
        ip.unpack( data )
        if ip.IP_Protocol == socket.IPPROTO_TCP:
            tcp.unpack( data[20:] )
            print('{}\n{}\n{}'.format(addr, ip, tcp))
        elif ip.IP_Protocol == socket.IPPROTO_UDP:
            udp.unpack( data[20:] )
            print('{}\n{}\n{}'.format(addr, ip, udp))
        else:
            print('{}\n{}'.format(addr, ip))
    Socket.close()

if __name__=="__main__":
    Main()
    h = UDP('10.18.25.38',49896,'224.0.0.252',5355,binascii.a2b_hex('a5eb000000010000000000000a756a7a68726b74756b750000010001'))
    #h.unpack(binascii.a2b_hex(                      'c2e814eb00244a6da5eb000000010000000000000a756a7a68726b74756b750000010001'))
    print binascii.b2a_hex(h.pack())
    print(str(h))
    #main()
