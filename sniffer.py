import pcap
import dpkt
import time
from PySide6.QtCore import QThread,Signal

# 数据链路层协议映射
DATALINK_TYPES = {
    1: "Ethernet(1)",
    105: "IEEE 802.11",
}

# 网络层协议映射
NETWORK_LAYER_PROTOCOLS = {
    0x0800: 'IPv4',
    0x86DD: 'IPv6',
    0x0806: 'ARP',
    0x8035: 'RARP'
}

# 传输层协议映射
TRANSPORT_LAYER_PROTOCOLS = {
    dpkt.ip.IP_PROTO_TCP: 'TCP',
    dpkt.ip.IP_PROTO_UDP: 'UDP',
    dpkt.ip.IP_PROTO_ICMP: 'ICMP', #网络传输层之间
    dpkt.ip.IP_PROTO_IGMP: 'IGMP',  #网络传输层之间
    dpkt.ip.IP_PROTO_ICMP6: 'ICMPv6'
}

# 应用层协议端口映射
APP_LAYER_PORTS = {
    80: 'HTTP',           # 超文本传输协议
    443: 'HTTPS',         # HTTPS 安全超文本传输协议
    53: 'DNS',            # 域名系统
    21: 'FTP',            # 文件传输协议
    22: 'SSH',            # 安全外壳协议
    25: 'SMTP',           # 简单邮件传输协议
    110: 'POP3',          # 邮局协议3
    143: 'IMAP',          # 互联网消息访问协议
    161: 'SNMP',          # 简单网络管理协议
    69: 'TFTP',           # 简单文件传输协议
    123: 'NTP',           # 网络时间协议
    389: 'LDAP',          # 轻量目录访问协议
    1883: 'MQTT',         # 消息队列遥测传输协议
    3306: 'MySQL',        # MySQL 数据库
    5432: 'PostgreSQL',   # PostgreSQL 数据库
    1521: 'Oracle DB',    # Oracle 数据库
    27017: 'MongoDB',     # MongoDB 数据库
    # 可扩展其他常见应用层协议端口
}


class PcapThread(QThread):
    pkg_get=Signal(bytes,str,str,str,str,str,str)#raw_buf,time,src,dst,proto,len,info
    
    def __init__(self,parent=None):
        super().__init__(parent)
        self.running=False #start/stop pcap
        self.captured_packets=[{}]
        self.parsepacket=PacketParser()
    
    def start(self):
        self.running=True
        super().start()
              
    def stop(self):
        self.running=False
        self.wait()
        # 支持协议类型
            
    def run(self):
        """
        获取数据包
        """
        # todo. filtercapture和capture-筛选和不筛选  
        # todo.设备筛选
        devs=pcap.findalldevs()
        # print("设备",devs,sep='\n')
        devnum='en0'
        getpkg=pcap.pcap(name='en0',promisc=True,immediate=True,timeout_ms=50)
        for timestamp, raw_buf in getpkg:
            eth = dpkt.ethernet.Ethernet(raw_buf)#解析后的以太网帧
            print("Raw Buffer Length (capture length):", len(raw_buf))  # 原始数据包长度
            print("Ethernet Parsed Length:", len(bytes(eth)))  # 解析后以太网帧长度
            
            raw_buf_hex=raw_buf.hex()
            # eth_hex=eth.__bytes__()
            print("raw:",raw_buf_hex,"\n",raw_buf)
            # print("eth:",eth_hex,"\n")
            
            protocol_type="Unknown"
            src_ip,dst_ip,info="N/A","N,A","No Additional Info"
            
            # Frame
            encapsulation_type = getpkg.datalink()
            encapsulation_type=self.parsepacket.DATALINK_TYPES.get(encapsulation_type)
            
            time_str=time.strftime('%H:%M:%S',time.localtime(timestamp))
            
            protocols=self.parsepacket.get_protocols(raw_buf)
            protocols_level=":".join(protocols)
              
            Frame={
                "帧序号":"row",
                "帧大小":len(raw_buf),
                "通信接口":devnum,
                "帧类型":encapsulation_type,
                "到达时间":time_str,
                "协议层次":protocols_level
                
            }
            print(Frame)
            
            
            # Ethernet
            
            

            
            
            
            # # ARP/RARP
            # if isinstance(eth.data, dpkt.arp.ARP):
            #     protocol_type="ARP" if eth.data.op==dpkt.arp.ARP_OP_REQUEST else "RARP"
            #     src_ip='.'.join(map(str,eth.data.spa))
            #     dst_ip='.'.join(map(str,eth.data.tpa))
            #     info=f'{src_ip} -> {dst_ip} ARP/RARP Request'
                
            # elif isinstance(eth.data,dpkt.ip.IP):
            #     protocol_type="IPv4"
            #     src_ip='.'.join(map(str,eth.data.src))
            #     dst_ip='.'.join(map(str,eth.data.dst)) 
            #     protocal_name = self.PROTOCOLS.get(eth.data.p,'Unknown')            
                
            #     #TCP/UDP
            #     if protocal_name in ['TCP','UDP']:
            #         try:
            #             src_port,dst_port=eth.data.sport,eth.data.dport
            #             app_protocol=self.APP_LAYER_PORTS.get(dst_port,protocal_name)
            #             info=f"{src_port} -> {dst_port} {app_protocol}"
            #             protocol_type = app_protocol if app_protocol != protocal_name else protocal_name
            #         except AttributeError:
            #             info = "No Port Info"
                        
            #     #ICMP/IGMP
            #     elif protocal_name in ['ICMP','IGMP']:
            #         protocol_type=protocal_name
            #         info=f"{protocal_name} Packet"
                    
            # elif isinstance(eth.data,dpkt.ip6.IP6):
            #     protocol_type="IPv6"
            #     src_ip=':'.join(f"{eth.data.src[i]:x}" for i in range(0,16,2))
            #     dst_ip=':'.join(f"{eth.data.dst[i]:x}" for i in range(0,16,2))
            #     info="IPv6 Packet"
            




            
            
            # self.captured_packets.append({
            #         "time":time_str,
            #         "raw_buf":raw_buf
            #         })
            
            # output={
            #     '时间':time_str,
            #     '源地址':src_ip,
            #     '目的地址':dst_ip,
            #     '协议类型':protocol_type,
            #     '长度':len(raw_buf),
            #     '信息':info
            # }
            # print(output)                    
            # print("\n")
            # len_str = str(len(raw_buf)) 
            # self.pkg_get.emit(raw_buf,time_str,src_ip, dst_ip, protocol_type,len_str,info)           
            
            
    def parsepkg(self,row):
        """
        解析数据包
        """
        parse_detail={}
        Frame={}
        Ethernet={}
        
        raw_buf=self.captured_packets[row]
        print(raw_buf.hex())
        raw_buf_hex=raw_buf.hex()
        eth = dpkt.ethernet.Ethernet(raw_buf)
        eth_hex=eth.hex()
        print()
    
    
    def save(self):
        """
        保存
        """ 
        
        
        
class PacketParser:
    def __init__(self):
        self.DATALINK_TYPES = DATALINK_TYPES
        self.NETWORK_LAYER_PROTOCOLS = NETWORK_LAYER_PROTOCOLS
        self.TRANSPORT_LAYER_PROTOCOLS = TRANSPORT_LAYER_PROTOCOLS
        self.APP_LAYER_PORTS = APP_LAYER_PORTS

    def get_protocols(self, raw_data):
        """
        获取数据包中包含的协议栈
        """
        protocols = []
        try:
            # 数据链路层
            protocols.append("eth") #未进行其他种类的抓包
            eth = dpkt.ethernet.Ethernet(raw_data)
            datalink_type = eth.type
            
            # 网络层
            # network_protocol = self.NETWORK_LAYER_PROTOCOLS.get(datalink_type, "unknown_ethertype")
            # protocols.append(network_protocol.lower())

            # 如果是 IPv4
            ip = eth.data
            if isinstance(ip, dpkt.ip.IP):
                protocols.append("ip")

                # 传输层协议识别
                transport_protocol = self.TRANSPORT_LAYER_PROTOCOLS.get(ip.p, "unknown_transport")
                protocols.append(transport_protocol.lower())

                # TCP 或 UDP 应用层协议识别
                if ip.p == dpkt.ip.IP_PROTO_TCP:
                    tcp = ip.data
                    if isinstance(tcp, dpkt.tcp.TCP):
                        print("tcp",tcp,tcp.dport,tcp.sport)
                        app_protocol = self.APP_LAYER_PORTS.get(tcp.dport) or self.APP_LAYER_PORTS.get(tcp.sport)
                        if app_protocol:
                            protocols.append(app_protocol.lower())

                elif ip.p == dpkt.ip.IP_PROTO_UDP:
                    udp = ip.data
                    if isinstance(udp, dpkt.udp.UDP):
                        app_protocol = self.APP_LAYER_PORTS.get(udp.dport) or self.APP_LAYER_PORTS.get(udp.sport)
                        if app_protocol:
                            protocols.append(app_protocol.lower())

            # 如果是 IPv6
            elif isinstance(ip, dpkt.ip6.IP6):
                protocols.append("ipv6")

                # 传输层协议识别
                transport_protocol = self.TRANSPORT_LAYER_PROTOCOLS.get(ip.nxt, "unknown_transport")
                protocols.append(transport_protocol.lower())

                # IPv6 的 TCP 或 UDP 应用层协议识别
                if ip.nxt == dpkt.ip.IP_PROTO_TCP:
                    tcp = ip.data
                    if isinstance(tcp, dpkt.tcp.TCP):
                        app_protocol = self.APP_LAYER_PORTS.get(tcp.dport) or self.APP_LAYER_PORTS.get(tcp.sport)
                        if app_protocol:
                            protocols.append(app_protocol.lower())

                elif ip.nxt == dpkt.ip.IP_PROTO_UDP:
                    udp = ip.data
                    if isinstance(udp, dpkt.udp.UDP):
                        app_protocol = self.APP_LAYER_PORTS.get(udp.dport) or self.APP_LAYER_PORTS.get(udp.sport)
                        if app_protocol:
                            protocols.append(app_protocol.lower())

            # 如果是 ARP 协议
            elif datalink_type == 0x0806:
                protocols.append("arp")

            # 如果是 RARP 协议
            elif datalink_type == 0x8035:
                protocols.append("rarp")

        except Exception as e:
            protocols.append("unknown_format")

        return protocols   


if __name__ == "__main__":
    try:
        import pcap
        print("pcap 模块已成功导入。")
        
        test = PcapThread()
        test.start()

        # 让程序运行一段时间，然后停止线程
        input("按回车键停止抓包...\n")
        test.stop()
    except ImportError:
        print("pcap 模块未安装。请先安装该模块后再运行程序。")