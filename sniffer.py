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
            # print("Raw Buffer Length (capture length):", len(raw_buf))  # 原始数据包长度
            # print("Ethernet Parsed Length:", len(bytes(eth)))  # 解析后以太网帧长度
            
            raw_buf_hex=raw_buf.hex()
            # eth_hex=eth.__bytes__()
            print("raw:",raw_buf_hex,"\n",raw_buf)
            # print("eth:",eth_hex,"\n")
            
            protocol_type="Unknown"
            src_ip,dst_ip,info="N/A","N,A","No Additional Info"
            
            parsepacket=PacketParser()
            

            time_str=time.strftime('%H:%M:%S',time.localtime(timestamp))
            
            # Frame
            encapsulation_type = getpkg.datalink()
            encapsulation_type=parsepacket.DATALINK_TYPES.get(encapsulation_type)
            
            
            
            parsedetails,protocols=parsepacket.get_protocols(raw_buf)
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
            # 0x0800: 'IPv4',
            # 0x86DD: 'IPv6',
            # 0x0806: 'ARP',
            # 0x8035: 'RARP'
            # 最后一个是帧的类型
            parsepacket.eth_parse(raw_buf)

            
            
            
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
        self.parsedetails={
            "raw_buf":b'',
            "Ethernet II":[],
            
        }
        
        
    def parse(self):
        """
        数据包整体解析,根据parsedetails字典中包含的项,分别调用不同的协议解析函数，进行解析
        """
        self.parsedetails={
            "raw_buf":b'',
            "datalinker":[],
            "networklayer":[],
            
        }
        return self.parsedetails
      
    def eth_parse(self,raw_data):
        """
        数据链路层
        """
        
        eth = dpkt.ethernet.Ethernet(raw_data)
        src_mac = ':'.join('%02x' % b for b in eth.src)
        dst_mac = ':'.join('%02x' % b for b in eth.dst)
        eth_type = eth.type
        eth_type=self.NETWORK_LAYER_PROTOCOLS.get(eth_type, "unknown_ethertype")
        self.parsedetails["raw_buf"]=raw_data.hex()
        
        dst_lg_bit = f".... ..{int((eth.dst[0] & 0x02) == 0)} .... .... ...."
        dst_ig_bit = f".... ...{int((eth.dst[0] & 0x01) == 0)} .... .... ...."   
        self.parsedetails["datalinker"].append({
            "label": "Destination MAC Address",
            "content": dst_mac,
            "hex": eth.dst.hex(),
            "details": {
                "lg_bit": f"{dst_lg_bit} = LG bit: {'Globally unique address (factory default)' if (eth.dst[0] & 0x02) == 0 else 'Locally administered address'}",
                "ig_bit": f"{dst_ig_bit} = IG bit: {'Individual address (unicast)' if (eth.dst[0] & 0x01) == 0 else 'Group address (multicast)'}"
            }
        })

        src_lg_bit = f".... ..{int((eth.src[0] & 0x02) == 0)} .... .... ...."
        src_ig_bit = f".... ...{int((eth.src[0] & 0x01) == 0)} .... .... ...."
        self.parsedetails["datalinker"].append({
            "label": "Source MAC Address",
            "content": src_mac,
            "hex": eth.src.hex(),
            "details": {
                "lg_bit": f"{src_lg_bit} = LG bit: {'Globally unique address (factory default)' if (eth.src[0] & 0x02) == 0 else 'Locally administered address'}",
                "ig_bit": f"{src_ig_bit} = IG bit: {'Individual address (unicast)' if (eth.src[0] & 0x01) == 0 else 'Group address (multicast)'}"
            }  
        })

        self.parsedetails["datalinker"].append({
            "label": "Type",
            "content": eth_type,
            "hex": hex(eth.type),
            "details": {}
        })
                 
        print(self.parsedetails,"\n\n")
        return self.parsedetails
        
     
    def networklayer(self,raw_data):
        eth = dpkt.ethernet.Ethernet(raw_data)
        eth_type = eth.type
        # 网络层解析
        if eth_type == dpkt.ethernet.ETH_TYPE_IP:
            self.ip_parse(eth.data)
        elif eth_type == dpkt.ethernet.ETH_TYPE_IP6:
            self.ipv6_parse(eth.data)
        elif eth_type == dpkt.ethernet.ETH_TYPE_ARP:
            self.arp_parse(eth.data)
        elif eth_type == dpkt.ethernet.ETH_TYPE_RARP:
            self.rarp_parse(eth.data)
        else:
            self.parsedetails["networklayer"].append({
                "label": "networklayer",
                "content": "Unknown",
                "hex": hex(eth_type)
            })
       
       
    def ip_parse(self, ip_data):
        """
        解析 IPv4 协议
        """
        ip = dpkt.ip.IP(ip_data)

        # 版本
        version_binary = f"{ip.v:04b} ...."
        self.parsedetails["networklayer"].append({
            "label": "Version",
            "content": f"{version_binary} = Version: {ip.v}",
            "hex": hex(ip.v),
            "details":{}
        })

        # 头部长度
        header_length = ip.hl * 4
        header_length_binary = f".... {ip.hl:04b}"
        self.parsedetails["networklayer"].append({
            "label": "Header Length",
            "content": f"{header_length_binary} = Header Length: {header_length} bytes ({ip.hl})",
            "hex": hex(ip.hl),
            "details": {}
        })

        # 区分服务
        # 区分服务字段 (Differentiated Services Field)
        dscp = (ip.tos & 0xfc) >> 2  # 前6位
        ecn = ip.tos & 0x03         # 后2位
        dscp_binary = f"{dscp:06b} .."
        ecn_binary = f".... ..{ecn:02b}"
        self.parsedetails["networklayer"].append({
            "label": "Differentiated Services Field",
            "content": f"0x{ip.tos:02x} (DSCP: {ip.tos >> 2}, ECN: {ip.tos & 0x3})",
            "hex": hex(ip.tos),
            "details": {
                "dscp": f"{dscp_binary} = Differentiated Services Codepoint: Default ({dscp})",
                "ecn": f"{ecn_binary} = Explicit Congestion Notification: {'Not ECN-Capable Transport (0)' if ecn == 0 else f'ECN ({ecn})'}"
            }
        })

        # 总长度
        self.parsedetails["networklayer"].append({
            "label": "Total Length",
            "content": f"Total Length: {ip.len:016b}",
            "hex": hex(ip.len),
            "details": {}
        })

        # 标识符
        self.parsedetails["networklayer"].append({
            "label": "Identification",
            "content": f"Identification: {ip.id:016b}",
            "hex": hex(ip.id),
            "details": {}
        })

        # 标志和片段偏移 (Flags and Fragment Offset)
        flags = (ip.off & 0xe000) >> 13
        fragment_offset = ip.off & 0x1fff
        # Flags: 分解为各个位
        reserved_bit = (flags & 0x4) >> 2
        dont_fragment = (flags & 0x2) >> 1
        more_fragments = flags & 0x1
        flags_binary = f"{reserved_bit:01b}{dont_fragment:01b}{more_fragments:01b} ...."
        
        self.parsedetails["networklayer"].append({
            "label": "Flags",
            "content": f"0x{flags:02x}, {'Don\'t fragment' if dont_fragment else ''}",
            "hex": hex(flags),
            "details": {
                "reserved_bit": f"{flags_binary} = Reserved bit: {'Set' if reserved_bit else 'Not set'}",
                "dont_fragment": f".{dont_fragment:1b} .... = Don't fragment: {'Set' if dont_fragment else 'Not set'}",
                "more_fragments": f"..{more_fragments:1b} .... = More fragments: {'Set' if more_fragments else 'Not set'}",
                "binary": flags_binary
            }
        })
        
        # 片段偏移
        fragment_offset_binary = f"... {fragment_offset:013b}"
        self.parsedetails["networklayer"].append({
            "label": "Fragment Offset",
            "content": f"{fragment_offset_binary} = Fragment Offset: {fragment_offset}",
            "hex": hex(fragment_offset),
            "details": {}
        })

        # 生存时间 (TTL)
        self.parsedetails["networklayer"].append({
            "label": "Time to Live",
            "content": f"Time to Live: {ip.ttl:08b}",
            "hex": hex(ip.ttl),
            "details": {}
        })

        # 协议
        protocol_name = self.TRANSPORT_LAYER_PROTOCOLS.get(ip.p, f"Protocol ({ip.p})")
        self.parsedetails["networklayer"].append({
            "label": "Protocol",
            "content": f"{protocol_name} ({ip.p})",
            "hex": hex(ip.p),
            "details": {}
        })

        # 头部校验和 (Header Checksum)
        checksum_hex = f"0x{ip.sum:04x}"
        self.parsedetails["networklayer"].append({
            "label": "Header Checksum",
            "content": f"Header Checksum: {checksum_hex}",
            "hex": checksum_hex,
            "details": {}
        })
        # 源地址
        src_ip_decimal = f"{ip.src[0]}.{ip.src[1]}.{ip.src[2]}.{ip.src[3]}"
        src_ip_binary = '.'.join(f"{octet:08b}" for octet in ip.src)

        self.parsedetails["networklayer"].append({
            "label": "Source Address",
            "content": f"{src_ip_decimal} ({src_ip_binary})",
            "hex": ip.src.hex(),
            "details": {}
        })

        # 目的地址
        dst_ip_decimal = f"{ip.dst[0]}.{ip.dst[1]}.{ip.dst[2]}.{ip.dst[3]}"
        dst_ip_binary = '.'.join(f"{octet:08b}" for octet in ip.dst)

        self.parsedetails["networklayer"].append({
            "label": "Destination Address",
            "content": f"{dst_ip_decimal} ({dst_ip_binary})",
            "hex": ip.dst.hex(),
            "details": {}
        })

        return self.parsedetails  
        
    def ipv6_parse(self, ipv6_data):
        """
        解析 IPv6 协议
        """
        ip6 = dpkt.ip6.IP6(ipv6_data)

        # 版本
        version_binary = f"{ip6.v:04b} ...."
        self.parsedetails["networklayer"].append({
            "label": "Version",
            "content": f"{version_binary} = Version: {ip6.v}",
            "hex": hex(ip6.v),
            "details": {}
        })

        # 流量类别 (Traffic Class)
        traffic_class = (ip6.fc & 0xff00) >> 4
        traffic_class_hex = f"0x{traffic_class:02x}"
        dscp = (traffic_class & 0xfc) >> 2
        ecn = traffic_class & 0x3
        traffic_class_binary = f".... {traffic_class:08b} .... .... ...."
        self.parsedetails["networklayer"].append({
            "label": "Traffic Class",
            "content": f"{traffic_class_binary} = Traffic Class: {traffic_class_hex} (DSCP: CS{dscp}, ECN: {'Not-ECT' if ecn == 0 else f'ECT({ecn})'})",
            "hex": traffic_class_hex,
            "details": {}
        })

        # 流标签 (Flow Label)
        flow_label = ip6.flow & 0x000fffff
        flow_label_binary = f".... {flow_label:020b}"
        self.parsedetails["networklayer"].append({
            "label": "Flow Label",
            "content": f"{flow_label_binary} = Flow Label: 0x{flow_label:05x}",
            "hex": hex(flow_label),
            "details": {}
        })

        # 载荷长度 (Payload Length)
        self.parsedetails["networklayer"].append({
            "label": "Payload Length",
            "content": f"Payload Length: {ip6.plen}",
            "hex": hex(ip6.plen),
            "details": {}
        })

        # 下一头部 (Next Header)
        next_header = ip6.nxt
        next_header_name = self.TRANSPORT_LAYER_PROTOCOLS.get(next_header, f"Protocol ({next_header})")
        self.parsedetails["networklayer"].append({
            "label": "Next Header",
            "content": f"Next Header: {next_header_name} ({next_header})",
            "hex": hex(next_header),
            "details": {}
        })

        # 跳限制 (Hop Limit)
        self.parsedetails["networklayer"].append({
            "label": "Hop Limit",
            "content": f"Hop Limit: {ip6.hlim}",
            "hex": hex(ip6.hlim),
            "details": {}
        })

        # 源地址 (Source Address)
        src_ip6 = ':'.join(f"{ip6.src[i]:02x}{ip6.src[i+1]:02x}" for i in range(0, len(ip6.src), 2))
        self.parsedetails["networklayer"].append({
            "label": "Source Address",
            "content": src_ip6,
            "hex": ip6.src.hex(),
            "details": {}
        })

        # 目的地址 (Destination Address)
        dst_ip6 = ':'.join(f"{ip6.dst[i]:02x}{ip6.dst[i+1]:02x}" for i in range(0, len(ip6.dst), 2))
        self.parsedetails["networklayer"].append({
            "label": "Destination Address",
            "content": dst_ip6,
            "hex": ip6.dst.hex(),
            "details": {}
        })
        return self.parsedetails

    def arp_parse(self, arp_data):
        """
        解析 ARP 协议
        """
        arp = dpkt.arp.ARP(arp_data)

        # 硬件类型 (Hardware Type)
        hardware_type = arp.hrd
        hardware_type_str = "Ethernet" if hardware_type == 1 else f"Unknown ({hardware_type})"
        self.parsedetails["networklayer"].append({
            "label": "Hardware Type",
            "content": f"{hardware_type_str} ({hardware_type})",
            "hex": hex(hardware_type),
            "details": {}
        })

        # 协议类型 (Protocol Type)
        protocol_type = arp.pro
        protocol_type_str = "IPv4" if protocol_type == 0x0800 else f"Unknown (0x{protocol_type:04x})"
        self.parsedetails["networklayer"].append({
            "label": "Protocol Type",
            "content": f"{protocol_type_str} (0x{protocol_type:04x})",
            "hex": hex(protocol_type),
            "details": {}
        })

        # 硬件大小 (Hardware Size)
        hardware_size = arp.hln
        self.parsedetails["networklayer"].append({
            "label": "Hardware Size",
            "content": str(hardware_size),
            "hex": hex(hardware_size),
            "details": {}
        })

        # 协议大小 (Protocol Size)
        protocol_size = arp.pln
        self.parsedetails["networklayer"].append({
            "label": "Protocol Size",
            "content": str(protocol_size),
            "hex": hex(protocol_size),
            "details": {}
        })

        # 操作码 (Opcode)
        opcode = arp.op
        opcode_str = "request" if opcode == 1 else "reply" if opcode == 2 else f"Unknown ({opcode})"
        self.parsedetails["networklayer"].append({
            "label": "Opcode",
            "content": f"{opcode_str} ({opcode})",
            "hex": hex(opcode),
            "details": {}
        })

        # 发送方 MAC 地址 (Sender MAC Address)
        sender_mac = ':'.join(f"{b:02x}" for b in arp.sha)
        self.parsedetails["networklayer"].append({
            "label": "Sender MAC Address",
            "content": f"Sender MAC Address: {sender_mac}",
            "hex": arp.sha.hex(),
            "details": {}
        })

        # 发送方 IP 地址 (Sender IP Address)
        sender_ip = '.'.join(str(b) for b in arp.spa)
        self.parsedetails["networklayer"].append({
            "label": "Sender IP Address",
            "content": f"Sender IP Address: {sender_ip}",
            "hex": arp.spa.hex(),
            "details": {}
        })

        # 目标 MAC 地址 (Target MAC Address)
        target_mac = ':'.join(f"{b:02x}" for b in arp.tha)
        self.parsedetails["networklayer"].append({
            "label": "Target MAC Address",
            "content": f"Target MAC Address: {target_mac}",
            "hex": arp.tha.hex(),
            "details": {}
        })

        # 目标 IP 地址 (Target IP Address)
        target_ip = '.'.join(str(b) for b in arp.tpa)
        self.parsedetails["networklayer"].append({
            "label": "Target IP Address",
            "content": "Target IP Address: {target_ip}",
            "hex": arp.tpa.hex(),
            "details": {}
        })

        return self.parsedetails

    def rarp_parse(self, rarp_data):
        """
        解析 RARP 协议 (与 ARP 类似)
        """
        rarp = dpkt.arp.ARP(rarp_data)

        # 硬件类型 (Hardware Type)
        hardware_type = rarp.hrd
        hardware_type_str = "Ethernet" if hardware_type == 1 else f"Unknown ({hardware_type})"
        self.parsedetails["networklayer"].append({
            "label": "Hardware Type",
            "content": f"{hardware_type_str} ({hardware_type})",
            "hex": hex(hardware_type),
            "details": {}
        })

        # 协议类型 (Protocol Type)
        protocol_type = rarp.pro
        protocol_type_str = "IPv4" if protocol_type == 0x0800 else f"Unknown (0x{protocol_type:04x})"
        self.parsedetails["networklayer"].append({
            "label": "Protocol Type",
            "content": f"{protocol_type_str} (0x{protocol_type:04x})",
            "hex": hex(protocol_type),
            "details": {}
        })

        # 硬件大小 (Hardware Size)
        hardware_size = rarp.hln
        self.parsedetails["networklayer"].append({
            "label": "Hardware Size",
            "content": str(hardware_size),
            "hex": hex(hardware_size),
            "details": {}
        })

        # 协议大小 (Protocol Size)
        protocol_size = rarp.pln
        self.parsedetails["networklayer"].append({
            "label": "Protocol Size",
            "content": str(protocol_size),
            "hex": hex(protocol_size),
            "details": {}
        })

        # 操作码 (Opcode)
        opcode = rarp.op
        opcode_str = "request" if opcode == 3 else "reply" if opcode == 4 else f"Unknown ({opcode})"
        self.parsedetails["networklayer"].append({
            "label": "Opcode",
            "content": f"{opcode_str} ({opcode})",
            "hex": hex(opcode),
            "details": {}
        })

        # 发送方 MAC 地址 (Sender MAC Address)
        sender_mac = ':'.join(f"{b:02x}" for b in rarp.sha)
        self.parsedetails["networklayer"].append({
            "label": "Sender MAC Address",
            "content": f"Sender MAC Address: {sender_mac}",
            "hex": rarp.sha.hex(),
            "details": {}
        })

        # 发送方 IP 地址 (Sender IP Address)
        sender_ip = '.'.join(str(b) for b in rarp.spa)
        self.parsedetails["networklayer"].append({
            "label": "Sender IP Address",
            "content": f"Sender IP Address: {sender_ip}",
            "hex": rarp.spa.hex(),
            "details": {}
        })

        # 目标 MAC 地址 (Target MAC Address)
        target_mac = ':'.join(f"{b:02x}" for b in rarp.tha)
        self.parsedetails["networklayer"].append({
            "label": "Target MAC Address",
            "content": f"Target MAC Address: {target_mac}",
            "hex": rarp.tha.hex(),
            "details": {}
        })

        # 目标 IP 地址 (Target IP Address)
        target_ip = '.'.join(str(b) for b in rarp.tpa)
        self.parsedetails["networklayer"].append({
            "label": "Target IP Address",
            "content": "Target IP Address: {target_ip}",
            "hex": rarp.tpa.hex(),
            "details": {}
        })

        return self.parsedetails
        




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

        
        #根据不同的路径得到解析
        parsedetails={
            "raw_buf":b'',
            "以太网帧(Ethernet II)":[],
            
        }
        
        return parsedetails,protocols
   


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