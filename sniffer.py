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
    dpkt.ip.IP_PROTO_ICMP6: 'ICMPv6'
}

# 应用层协议端口映射
APP_LAYER_PORTS = {
    80: 'HTTP',           # 超文本传输协议
    53: 'DNS',            # 域名系统
    # 可扩展其他常见应用层协议端口
}


class PcapThread(QThread):
    pkg_get=Signal(bytes,str,str,str,str,str,str)#raw_buf,time,src,dst,proto,len,info
    
    def __init__(self,parent=None):
        super().__init__(parent)
        self.running=False          # 开始/停止抓包
        self.captured_packets=[]    # 数据包记录
        self.protocol_filter = None # 协议过滤
        self.host_filter = None     # IP地址过滤
        self.port_filter = None     # 端口过滤
        self.logic_operator = "and" # 
       
    def set_filter(self, protocol=None, host=None, port=None, logic=("and", "and")):
        """设置过滤条件"""
        self.protocol_filter = protocol
        self.host_filter = host
        self.port_filter = port
        self.logic_operators = logic  # 逻辑运算符元组，(logic_1, logic_2)

    def should_filter(self):
        """检查是否需要过滤"""
        return any([self.protocol_filter, self.host_filter, self.port_filter])
    
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
        devs=pcap.findalldevs()
        # print("设备",devs,sep='\n')
        devnum='en0'
        getpkg=pcap.pcap(name=devnum,promisc=True,immediate=True,timeout_ms=50)
        for timestamp, raw_buf in getpkg:   
            if not self.running:
                break    
             
            # raw_buf_hex=raw_buf.hex()
            # print("raw:",raw_buf_hex,"\n",raw_buf)  
            
            time_str=time.strftime('%H:%M:%S',time.localtime(timestamp))
            
            if not self.should_filter() or self.apply_filters(raw_buf):  
                parsepacket=PacketParser()
                parsepacket=parsepacket.parse(raw_buf,0)
                # print(parsepacket)
                # 表格简单parse展示
                simpleparse=self.simple_parse(raw_buf,time_str)
                self.pkg_get.emit(
                    raw_buf,
                    simpleparse["Time"],        # 时间
                    simpleparse["Source"],      # 源地址
                    simpleparse["Destination"], # 目的地址
                    simpleparse["Protocol"],    # 协议
                    str(simpleparse["Length"]), # 长度
                    simpleparse["Info"]         # 数据包内容摘要
                    ) 
            # 细节parse
            # parsepacket.parse(raw_buf)
    
    def apply_filters(self, raw_buf):
        """
        检查数据包是否满足过滤条件。
        """
        eth = dpkt.ethernet.Ethernet(raw_buf)
        
        # 应用协议过滤
        protocol_match = self._filter_by_protocol(eth) if self.protocol_filter else True

        # 应用主机过滤
        host_match = self._filter_by_host(eth) if self.host_filter else True

        # 应用端口过滤
        port_match = self._filter_by_port(eth) if self.port_filter else True

        # 使用第一个逻辑运算符将协议和主机条件组合
        logic_1 = self.logic_operators[0]
        if logic_1 == "or":
            basic_match = protocol_match or host_match
        else:  # 默认为 "or"
            basic_match = protocol_match and host_match

        # 使用第二个逻辑运算符将 basic_match 和端口条件组合
        logic_2 = self.logic_operators[1]
        if logic_2 == "or":
            final_match = basic_match or port_match
        else:  # 默认为 "or"
            final_match = basic_match and port_match

        print(final_match)
        return final_match

    def _filter_by_protocol(self, packet):
        """协议过滤"""
        if isinstance(packet.data, (dpkt.ip.IP, dpkt.ip6.IP6)):
            for protocol in self.protocol_filter:
                protocol = protocol.lower()
                if protocol == "tcp" and isinstance(packet.data.data, dpkt.tcp.TCP):
                    return True
                elif protocol == "udp" and isinstance(packet.data.data, dpkt.udp.UDP):
                    return True
                elif protocol == "icmp" and isinstance(packet.data, dpkt.icmp.ICMP):
                    return True
                elif protocol == "icmpv6" and isinstance(packet.data, dpkt.icmp6.ICMP6):
                    return True
                elif protocol == "arp" and isinstance(packet, dpkt.arp.ARP):
                    return True
                elif protocol == "ipv4" and isinstance(packet.data, dpkt.ip.IP):
                    return True
                elif protocol == "ipv6" and isinstance(packet.data, dpkt.ip6.IP6):
                    return True
        return False  
    
    def _filter_by_host(self, packet):
        
        """
        过滤主机IP 地址。
        """
        # 确保 packet 包含 IPv4 或 IPv6 数据
        if not isinstance(packet.data, (dpkt.ip.IP, dpkt.ip6.IP6)):
            return False

        # 获取源和目标 IP 地址
        ip_src = (
            ".".join(map(str, packet.data.src))
            if isinstance(packet.data, dpkt.ip.IP)
            else ":".join(f"{packet.data.src[i]:02x}{packet.data.src[i+1]:02x}" for i in range(0, 16, 2))
        )
        ip_dst = (
            ".".join(map(str, packet.data.dst))
            if isinstance(packet.data, dpkt.ip.IP)
            else ":".join(f"{packet.data.dst[i]:02x}{packet.data.dst[i+1]:02x}" for i in range(0, 16, 2))
        )

                # 仅当源或目标 IP 地址与 host_filter 完全匹配时才通过
        
        if isinstance(self.host_filter, (list, set)):
            # 如果 host_filter 是一个列表或集合，检查源或目标 IP 是否在 host_filter 中
            print(self.host_filter,ip_src,ip_dst,ip_src in self.host_filter or ip_dst in self.host_filter)
            return ip_src in self.host_filter or ip_dst in self.host_filter
        else:
            # 如果 host_filter 是一个字符串，检查源或目标 IP 是否与 host_filter 匹配
            print(self.host_filter,ip_src,ip_dst,ip_src in self.host_filter or ip_dst in self.host_filter)
            return self.host_filter == ip_src or self.host_filter == ip_dst

    def _filter_by_port(self, packet):
        """
        过滤端口号
        """
        # 获取源和目标端口号（仅适用于 TCP/UDP）
        src_port = dst_port = None
        if isinstance(packet.data, (dpkt.ip.IP, dpkt.ip6.IP6)) and isinstance(packet.data.data, (dpkt.tcp.TCP, dpkt.udp.UDP)):
            src_port = packet.data.data.sport
            dst_port = packet.data.data.dport

        # 端口匹配
        if isinstance(self.port_filter, (list, set)):
            return any(port in [src_port, dst_port] for port in self.port_filter)
        else:
            return self.port_filter in [src_port, dst_port] if self.port_filter else True                      
    
    def simple_parse(self,raw_buf,time_str):
        protocol_type="Unknown"
        src,dst,info="N/A","N/A","No Additional Info"
        eth = dpkt.ethernet.Ethernet(raw_buf)
        # ARP/RARP
        if isinstance(eth.data, dpkt.arp.ARP):
            src_ip = '.'.join(map(str, eth.data.spa))  # 源 IP 地址
            dst_ip = '.'.join(map(str, eth.data.tpa))  # 目标 IP 地址
            src_mac = ':'.join(f'{b:02x}' for b in eth.data.sha)  # 源 MAC 地址
            dst_mac = ':'.join(f'{b:02x}' for b in eth.data.tha)  # 目标 MAC 地址
            src=src_mac
            dst=dst_mac
            protocol_type="ARP"
            # 根据操作码区分 ARP 和 RARP 类型
            if eth.data.op == dpkt.arp.ARP_OP_REQUEST:
                info = f"{src_ip} is asking for {dst_ip}"  # 格式化 ARP 请求的信息
            elif eth.data.op == dpkt.arp.ARP_OP_REPLY:
                info = f"{src_ip} is at {src_mac}"  # 格式化 ARP 响应的信息
            elif eth.data.op == dpkt.arp.ARP_OP_REVREQUEST:
                info = f"Reverse ARP request from {src_mac} for IP of {dst_mac}"  # 格式化 RARP 请求的信息
            elif eth.data.op == dpkt.arp.ARP_OP_REVREPLY:
                info = f"Reverse ARP reply: {src_mac} has IP {src_ip}"  # 格式化 RARP 响应的信息

        # IP,ICMP---->TCP,UDP  
        elif isinstance(eth.data,dpkt.ip.IP):
            protocol_type="IPv4"
            src='.'.join(map(str,eth.data.src))
            dst='.'.join(map(str,eth.data.dst)) 
            protocal_name = TRANSPORT_LAYER_PROTOCOLS.get(eth.data.p,'Unknown')            
            
            # TCP/UDP
            if protocal_name in ['TCP', 'UDP']: 
                src_port, dst_port = eth.data.data.sport, eth.data.data.dport  
                app_protocol = APP_LAYER_PORTS.get(dst_port,protocal_name)  # 获取应用层协议（如 HTTP, DNS）
                # print(app_protocol)
                if protocal_name == "TCP":  # 处理 TCP 数据
                    protocol_type = protocal_name
                    tcp = eth.data.data  # 获取 TCP 对象（从 IP 数据中提取）
                    # 提取 TCP 标志位
                    flags = tcp.flags
                    flag_names = {
                        0x01: "FIN",
                        0x02: "SYN",
                        0x04: "RST",
                        0x08: "PSH",
                        0x10: "ACK",
                        0x20: "URG",
                        0x40: "ECE",
                        0x80: "CWR"
                    }
                    # 获取已设置的标志位
                    flag_str = ''.join(f"[{name}]" for bit, name in flag_names.items() if flags & bit)
                    s_protocol = APP_LAYER_PORTS.get(src_port,"")  # 获取应用层协议（如 HTTP, DNS）
                    d_protocol = APP_LAYER_PORTS.get(dst_port,"")  # 获取应用层协议（如 HTTP, DNS）
                    # TCP协议，生成 info 字段
                    info = (f"{s_protocol.lower()}({src_port}) -> {d_protocol.lower()}({dst_port}) "
                            f"{flag_str} Seq={tcp.seq} Ack={tcp.ack} Win={tcp.win} Len={len(tcp.data)}")

                else:
                    # 如果是 UDP，则只生成基本的 src_port -> dst_port 以及应用层协议信息
                    info = f"{src_port} -> {dst_port} {app_protocol}"
                    protocol_type = app_protocol if app_protocol != protocal_name else protocal_name

                
                # 应用层：判断并进一步解析 HTTP 和 DNS 协议
                if app_protocol == "HTTP" and len(eth.data.data.data) > 0:
                    protocol_type = "HTTP"
                    tcp_data = eth.data.data.data
                    try:
                        http = dpkt.http.Request(tcp_data)  # 解析 HTTP 请求
                        info = f"HTTP {http.method} {http.uri} Host: {http.headers.get('host', 'N/A')}"
                    except dpkt.dpkt.NeedData:
                        info = "Incomplete HTTP data"
                    except (dpkt.UnpackError, dpkt.dpkt.Error):
                        info = "Malformed HTTP data"

                elif app_protocol == "DNS" and len(eth.data.data.data) > 0:
                    protocol_type = "DNS"
                    udp_data = eth.data.data.data
                    try:
                        dns = dpkt.dns.DNS(udp_data)  # 解析 DNS 数据
                        if dns.qr == dpkt.dns.DNS_Q:
                            # DNS 查询请求
                            questions = ', '.join(q.name for q in dns.qd if q.name)
                            info = f"DNS Query: {questions}"
                        elif dns.qr == dpkt.dns.DNS_R:
                            # DNS 响应
                            answers = ', '.join(a.name for a in dns.an if a.name)
                            info = f"DNS Response: {answers}"
                    except dpkt.dpkt.NeedData:
                        info = "Incomplete DNS data"
                    except (dpkt.UnpackError, dpkt.dpkt.Error):
                        info = "Malformed DNS data"      
                    
            #ICMP
            elif protocal_name == 'ICMP':
                protocol_type = protocal_name
                icmp_data = eth.data.data  # 获取 ICMP 数据包

                # 检查 ICMP 的 Type 和 Code，生成相应的描述
                icmp_type = icmp_data.type
                icmp_code = icmp_data.code

                # 常见的 ICMP Type 和 Code 对应的描述
                icmp_messages = {
                    (3, 0): "Destination unreachable (Network unreachable)",
                    (3, 1): "Destination unreachable (Host unreachable)",
                    (3, 2): "Destination unreachable (Protocol unreachable)",
                    (3, 3): "Destination unreachable (Port unreachable)",
                    (8, 0): "Echo request (ping request)",
                    (0, 0): "Echo reply (ping reply)",
                    (11, 0): "Time exceeded (TTL expired)",
                }

                # 根据 Type 和 Code 获取描述信息
                info = icmp_messages.get((icmp_type, icmp_code), f"ICMP Type={icmp_type} Code={icmp_code}")
                
        # IPv6 数据包解析
        elif isinstance(eth.data, dpkt.ip6.IP6):
            protocol_type = "IPv6"
            src = ':'.join(f"{eth.data.src[i]:x}{eth.data.src[i+1]:x}" for i in range(0, 16, 2))
            dst = ':'.join(f"{eth.data.dst[i]:x}{eth.data.dst[i+1]:x}" for i in range(0, 16, 2))
            
            # 获取 IPv6 的 Next Header 字段以判断传输层协议
            next_header = eth.data.nxt
            
            # 根据 Next Header 字段解析传输层协议
            if next_header == 6:  # TCP
                protocol_type = "TCP"
                tcp = eth.data.data
                src_port, dst_port = tcp.sport, tcp.dport
                info = f"TCP {src_port} -> {dst_port}"
                # 这里可以继续解析 TCP 数据，如标志位、序列号、确认号等

            elif next_header == 17:  # UDP
                protocol_type = "UDP"
                udp = eth.data.data
                src_port, dst_port = udp.sport, udp.dport
                info = f"UDP {src_port} -> {dst_port}"
                # 这里可以继续解析 UDP 数据的内容

            elif next_header == 58:  # ICMPv6
                protocol_type = "ICMPv6"
                icmp6 = eth.data.data
                icmp_type = icmp6.type
                icmp_code = icmp6.code
                # 针对 ICMPv6 类型和代码生成详细信息
                info = f"ICMPv6 Type={icmp_type} Code={icmp_code}"
                icmp6_messages = {
                    (1, 0): "Destination Unreachable (No route to destination)",
                    (1, 3): "Destination Unreachable (Port unreachable)",
                    (128, 0): "Echo Request (ping request)",
                    (129, 0): "Echo Reply (ping reply)",
                }
                info = icmp6_messages.get((icmp_type, icmp_code)) 
                if icmp_type == 133:  # Router Solicitation
                    info = "Router Solicitation"
                elif icmp_type == 134:  # Router Advertisement
                    src_mac = ':'.join(f"{b:02x}" for b in eth.src)  # 获取源 MAC 地址
                    info = f"Router Advertisement from {src_mac}"
                elif icmp_type == 135:  # Neighbor Solicitation
                    target_ip = ':'.join(f"{icmp6.data[i]:02x}{icmp6.data[i+1]:02x}" for i in range(0, 16, 2))
                    info = f"Neighbor Solicitation for {target_ip}"
                elif icmp_type == 136:  # Neighbor Advertisement
                    target_ip = ':'.join(f"{icmp6.data[i]:02x}{icmp6.data[i+1]:02x}" for i in range(0, 16, 2))
                    info = f"Neighbor Advertisement {target_ip}"
                else:
                    info = f"ICMPv6 Type={icmp_type} Code={icmp_code}"
                
 
            else:
                # 如果 Next Header 是其他协议
                info = f"IPv6 Packet with Next Header={next_header}"
        
        self.captured_packets.append({
                "raw_buf":raw_buf,
                'Time':time_str,
                'Source':src,
                'Destination':dst,
                'Protocol':protocol_type,
                'Length':len(raw_buf),
                'Info':info
                })
        
        output={
            'Time':time_str,
            'Source':src,
            'Destination':dst,
            'Protocol':protocol_type,
            'Length':len(raw_buf),
            'Info':info
        }   
        print(output)               
        return output                     
            
        
        
        
class PacketParser:
    def __init__(self):
        self.DATALINK_TYPES = DATALINK_TYPES                        # 支持的数据链路层协议
        self.NETWORK_LAYER_PROTOCOLS = NETWORK_LAYER_PROTOCOLS      # 支持的网络层协议
        self.TRANSPORT_LAYER_PROTOCOLS = TRANSPORT_LAYER_PROTOCOLS  # 支持的传输层协议
        self.APP_LAYER_PORTS = APP_LAYER_PORTS                      # 支持的应用层协议
        self.parsedetails={}                                        # 数据包解析出的细节记录
        
      
    def parse(self,raw_data,row):
        """
        数据包整体解析,根据parsedetails字典中包含的项,分别调用不同的协议解析函数，进行解析
        """
        self.parsedetails={
            "raw_buf":b'',
            "frame":[],
            "datalinker":[],
            "networklayer": {
                "IP": [],         
                "ICMP": []   #icmp若有的话     
            },
            "transportlayer":[],
            "applicationlayer":[],
        }
        # 整体frame
        self.frame_parse(raw_data,row)
        
        # 解析数据链路层
        self.eth_parse(raw_data)
        # 
        # 网络层解析
        self.networklayer(raw_data)
        
        # print(self.parsedetails)
        
        return self.parsedetails
    
    def frame_parse(self,raw_data,row):
        self.parsedetails["frame"].append({
            "label": f"Frame {row+1}",
            "content": f"{len(raw_data)} bytes on interface en0",
            "hex": raw_data.hex(),
            "details": {}
        })
        return self.parsedetails   
    # eth
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
                 
        # print(self.parsedetails,"\n\n")
        return self.parsedetails
             
    # ip （icmp） arp
    def networklayer(self,raw_data):
        eth = dpkt.ethernet.Ethernet(raw_data)
        eth_type = eth.type
        # 网络层解析
        # print(hex(eth_type))
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
         
    def ip_parse(self, ipdata):
        """
        解析 IPv4 协议
        """
        ip = ipdata

        # 版本
        version_binary = f"{ip.v:04b} ...."
        self.parsedetails["networklayer"]["IP"].append({
            "label": "Name",
            "content": f"Internet Protocol Version 4",
            "hex": "",
            "details":{}            
        })
        
        
        self.parsedetails["networklayer"]["IP"].append({
            "label": "Version",
            "content": f"{version_binary} = Version: {ip.v}",
            "hex": hex(ip.v),
            "details":{}
        })

        # 头部长度
        header_length = ip.hl * 4
        header_length_binary = f".... {ip.hl:04b}"
        self.parsedetails["networklayer"]["IP"].append({
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
        self.parsedetails["networklayer"]["IP"].append({
            "label": "Differentiated Services Field",
            "content": f"0x{ip.tos:02x} (DSCP: {ip.tos >> 2}, ECN: {ip.tos & 0x3})",
            "hex": hex(ip.tos),
            "details": {
                "dscp": f"{dscp_binary} = Differentiated Services Codepoint: Default ({dscp})",
                "ecn": f"{ecn_binary} = Explicit Congestion Notification: {'Not ECN-Capable Transport (0)' if ecn == 0 else f'ECN ({ecn})'}"
            }
        })

        # 总长度
        self.parsedetails["networklayer"]["IP"].append({
            "label": "Total Length",
            "content": f"Total Length: {ip.len}",
            "hex": hex(ip.len),
            "details": {}
        })

        # 标识符
        self.parsedetails["networklayer"]["IP"].append({
            "label": "Identification",
            "content": f"Identification: 0x{hex(ip.id)}",
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
        
        self.parsedetails["networklayer"]["IP"].append({
            "label": "Flags",
            "content": f"Flags: 0x{flags:02x}",
            "hex": hex(flags),
            "details": {
                "reserved_bit": f"{reserved_bit}... .... = Reserved bit: {'Set' if reserved_bit else 'Not set'}",
                "dont_fragment": f".{dont_fragment:1b}.. .... = Don't fragment: {'Set' if dont_fragment else 'Not set'}",
                "more_fragments": f"..{more_fragments:1b}. .... = More fragments: {'Set' if more_fragments else 'Not set'}",
            }
        })
        
        # 片段偏移
        fragment_offset_binary = f"... {fragment_offset:013b}"
        self.parsedetails["networklayer"]["IP"].append({
            "label": "Fragment Offset",
            "content": f"{fragment_offset_binary} = Fragment Offset: {fragment_offset}",
            "hex": hex(fragment_offset),
            "details": {}
        })

        # 生存时间 (TTL)
        self.parsedetails["networklayer"]["IP"].append({
            "label": "Time to Live",
            "content": f"Time to Live: {ip.ttl}",
            "hex": hex(ip.ttl),
            "details": {}
        })

        # 协议
        protocol_name = self.TRANSPORT_LAYER_PROTOCOLS.get(ip.p, f"Protocol ({ip.p})")
        self.parsedetails["networklayer"]["IP"].append({
            "label": "Protocol",
            "content": f"Protocol: {protocol_name} ({ip.p})",
            "hex": hex(ip.p),
            "details": {}
        })

        # 头部校验和 (Header Checksum)
        checksum_hex = f"0x{ip.sum:04x}"
        self.parsedetails["networklayer"]["IP"].append({
            "label": "Header Checksum",
            "content": f"Header Checksum: {checksum_hex}",
            "hex": checksum_hex,
            "details": {}
        })
        # 源地址
        src_ip_decimal = f"{ip.src[0]}.{ip.src[1]}.{ip.src[2]}.{ip.src[3]}"
        # src_ip_binary = '.'.join(f"{octet:08b}" for octet in ip.src)

        self.parsedetails["networklayer"]["IP"].append({
            "label": "Source Address",
            "content": f"Source Address: {src_ip_decimal}",
            "hex": ip.src.hex(),
            "details": {}
        })

        # 目的地址
        dst_ip_decimal = f"{ip.dst[0]}.{ip.dst[1]}.{ip.dst[2]}.{ip.dst[3]}"
        # dst_ip_binary = '.'.join(f"{octet:08b}" for octet in ip.dst)

        self.parsedetails["networklayer"]["IP"].append({
            "label": "Destination Address",
            "content": f"Destination Address: {dst_ip_decimal}",
            "hex": ip.dst.hex(),
            "details": {}
        })


        # 根据协议调用对应的传输层解析函数
        if ip.p == dpkt.ip.IP_PROTO_TCP:
            self.tcp_parse(ip.data)
        elif ip.p == dpkt.ip.IP_PROTO_UDP:
            self.udp_parse(ip.data)
        elif ip.p == dpkt.ip.IP_PROTO_ICMP:
            self.icmp_parse(ip.data)  

        return self.parsedetails  
        
    def ipv6_parse(self, ipv6_data):
        """
        解析 IPv6 协议
        """
        ip6 = ipv6_data
        
        self.parsedetails["networklayer"]["IP"].append({
            "label": "Name",
            "content": f"Internet Protocol Version 6",
            "hex": "",
            "details":{}            
        })
        # 版本
        version_binary = f"{ip6.v:04b} ...."
        self.parsedetails["networklayer"]["IP"].append({
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
        self.parsedetails["networklayer"]["IP"].append({
            "label": "Traffic Class",
            "content": f"{traffic_class_binary} = Traffic Class: {traffic_class_hex} (DSCP: CS{dscp}, ECN: {'Not-ECT' if ecn == 0 else f'ECT({ecn})'})",
            "hex": traffic_class_hex,
            "details": {}
        })

        # 流标签 (Flow Label)
        flow_label = ip6.flow & 0x000fffff
        flow_label_binary = f".... {flow_label:020b}"
        self.parsedetails["networklayer"]["IP"].append({
            "label": "Flow Label",
            "content": f"{flow_label_binary} = Flow Label: 0x{flow_label:05x}",
            "hex": hex(flow_label),
            "details": {}
        })

        # 载荷长度 (Payload Length)
        self.parsedetails["networklayer"]["IP"].append({
            "label": "Payload Length",
            "content": f"Payload Length: {ip6.plen}",
            "hex": hex(ip6.plen),
            "details": {}
        })

        # 下一头部 (Next Header)
        next_header = ip6.nxt
        next_header_name = self.TRANSPORT_LAYER_PROTOCOLS.get(next_header, f"Protocol ({next_header})")
        self.parsedetails["networklayer"]["IP"].append({
            "label": "Next Header",
            "content": f"Next Header: {next_header_name} ({next_header})",
            "hex": hex(next_header),
            "details": {}
        })

        # 跳限制 (Hop Limit)
        self.parsedetails["networklayer"]["IP"].append({
            "label": "Hop Limit",
            "content": f"Hop Limit: {ip6.hlim}",
            "hex": hex(ip6.hlim),
            "details": {}
        })

        # 源地址 (Source Address)
        src_ip6 = ':'.join(f"{ip6.src[i]:02x}{ip6.src[i+1]:02x}" for i in range(0, len(ip6.src), 2))
        self.parsedetails["networklayer"]["IP"].append({
            "label": "Source Address",
            "content": src_ip6,
            "hex": ip6.src.hex(),
            "details": {}
        })

        # 目的地址 (Destination Address)
        dst_ip6 = ':'.join(f"{ip6.dst[i]:02x}{ip6.dst[i+1]:02x}" for i in range(0, len(ip6.dst), 2))
        self.parsedetails["networklayer"]["IP"].append({
            "label": "Destination Address",
            "content": dst_ip6,
            "hex": ip6.dst.hex(),
            "details": {}
        })
        
        # 在解析 IPv6 时，根据传输层协议调用对应的解析函数
        if ip6.nxt == dpkt.ip.IP_PROTO_TCP:
            self.tcp_parse(ip6.data)
        elif ip6.nxt == dpkt.ip.IP_PROTO_UDP:
            self.udp_parse(ip6.data)
        elif ip6.nxt == dpkt.ip.IP_PROTO_ICMP6:
            self.icmpv6_parse(ip6.data) 
        
        
        return self.parsedetails

    def arp_parse(self, arp_data):
        """
        解析 ARP 协议
        """
        arp = arp_data
        self.parsedetails["networklayer"]["IP"].append({
            "label": "Name",
            "content": f"Address Resolution Protocol",
            "hex": "",
            "details":{}            
        })

        # 硬件类型 (Hardware Type)
        hardware_type = arp.hrd
        hardware_type_str = "Ethernet" if hardware_type == 1 else f"Unknown ({hardware_type})"
        self.parsedetails["networklayer"]["IP"].append({
            "label": "Hardware Type",
            "content": f"{hardware_type_str} ({hardware_type})",
            "hex": hex(hardware_type),
            "details": {}
        })

        # 协议类型 (Protocol Type)
        protocol_type = arp.pro
        protocol_type_str = "IPv4" if protocol_type == 0x0800 else f"Unknown (0x{protocol_type:04x})"
        self.parsedetails["networklayer"]["IP"].append({
            "label": "Protocol Type",
            "content": f"{protocol_type_str} (0x{protocol_type:04x})",
            "hex": hex(protocol_type),
            "details": {}
        })

        # 硬件大小 (Hardware Size)
        hardware_size = arp.hln
        self.parsedetails["networklayer"]["IP"].append({
            "label": "Hardware Size",
            "content": f"Hardware Size: {str(hardware_size)}",
            "hex": hex(hardware_size),
            "details": {}
        })

        # 协议大小 (Protocol Size)
        protocol_size = arp.pln
        self.parsedetails["networklayer"]["IP"].append({
            "label": "Protocol Size",
            "content": f"Protocol Size: {str(protocol_size)}",
            "hex": hex(protocol_size),
            "details": {}
        })

        # 操作码 (Opcode)
        opcode = arp.op
        opcode_str = "request" if opcode == 1 else "reply" if opcode == 2 else f"Unknown ({opcode})"
        self.parsedetails["networklayer"]["IP"].append({
            "label": "Opcode",
            "content": f"Opcode: {opcode_str} ({opcode})",
            "hex": hex(opcode),
            "details": {}
        })

        # 发送方 MAC 地址 (Sender MAC Address)
        sender_mac = ':'.join(f"{b:02x}" for b in arp.sha)
        self.parsedetails["networklayer"]["IP"].append({
            "label": "Sender MAC Address",
            "content": f"Sender MAC Address: {sender_mac}",
            "hex": arp.sha.hex(),
            "details": {}
        })

        # 发送方 IP 地址 (Sender IP Address)
        sender_ip = '.'.join(str(b) for b in arp.spa)
        self.parsedetails["networklayer"]["IP"].append({
            "label": "Sender IP Address",
            "content": f"Sender IP Address: {sender_ip}",
            "hex": arp.spa.hex(),
            "details": {}
        })

        # 目标 MAC 地址 (Target MAC Address)
        target_mac = ':'.join(f"{b:02x}" for b in arp.tha)
        self.parsedetails["networklayer"]["IP"].append({
            "label": "Target MAC Address",
            "content": f"Target MAC Address: {target_mac}",
            "hex": arp.tha.hex(),
            "details": {}
        })

        # 目标 IP 地址 (Target IP Address)
        target_ip = '.'.join(str(b) for b in arp.tpa)
        self.parsedetails["networklayer"]["IP"].append({
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
        rarp = rarp_data

        # 硬件类型 (Hardware Type)
        hardware_type = rarp.hrd
        hardware_type_str = "Ethernet" if hardware_type == 1 else f"Unknown ({hardware_type})"
        self.parsedetails["networklayer"]["IP"].append({
            "label": "Hardware Type",
            "content": f"{hardware_type_str} ({hardware_type})",
            "hex": hex(hardware_type),
            "details": {}
        })

        # 协议类型 (Protocol Type)
        protocol_type = rarp.pro
        protocol_type_str = "IPv4" if protocol_type == 0x0800 else f"Unknown (0x{protocol_type:04x})"
        self.parsedetails["networklayer"]["IP"].append({
            "label": "Protocol Type",
            "content": f"{protocol_type_str} (0x{protocol_type:04x})",
            "hex": hex(protocol_type),
            "details": {}
        })

        # 硬件大小 (Hardware Size)
        hardware_size = rarp.hln
        self.parsedetails["networklayer"]["IP"].append({
            "label": "Hardware Size",
            "content": str(hardware_size),
            "hex": hex(hardware_size),
            "details": {}
        })

        # 协议大小 (Protocol Size)
        protocol_size = rarp.pln
        self.parsedetails["networklayer"]["IP"].append({
            "label": "Protocol Size",
            "content": str(protocol_size),
            "hex": hex(protocol_size),
            "details": {}
        })

        # 操作码 (Opcode)
        opcode = rarp.op
        opcode_str = "request" if opcode == 3 else "reply" if opcode == 4 else f"Unknown ({opcode})"
        self.parsedetails["networklayer"]["IP"].append({
            "label": "Opcode",
            "content": f"{opcode_str} ({opcode})",
            "hex": hex(opcode),
            "details": {}
        })

        # 发送方 MAC 地址 (Sender MAC Address)
        sender_mac = ':'.join(f"{b:02x}" for b in rarp.sha)
        self.parsedetails["networklayer"]["IP"].append({
            "label": "Sender MAC Address",
            "content": f"Sender MAC Address: {sender_mac}",
            "hex": rarp.sha.hex(),
            "details": {}
        })

        # 发送方 IP 地址 (Sender IP Address)
        sender_ip = '.'.join(str(b) for b in rarp.spa)
        self.parsedetails["networklayer"]["IP"].append({
            "label": "Sender IP Address",
            "content": f"Sender IP Address: {sender_ip}",
            "hex": rarp.spa.hex(),
            "details": {}
        })

        # 目标 MAC 地址 (Target MAC Address)
        target_mac = ':'.join(f"{b:02x}" for b in rarp.tha)
        self.parsedetails["networklayer"]["IP"].append({
            "label": "Target MAC Address",
            "content": f"Target MAC Address: {target_mac}",
            "hex": rarp.tha.hex(),
            "details": {}
        })

        # 目标 IP 地址 (Target IP Address)
        target_ip = '.'.join(str(b) for b in rarp.tpa)
        self.parsedetails["networklayer"]["IP"].append({
            "label": "Target IP Address",
            "content": "Target IP Address: {target_ip}",
            "hex": rarp.tpa.hex(),
            "details": {}
        })

        return self.parsedetails      
      
    # icmp, icmpv6
    def icmp_parse(self, icmp_data):
        """
        解析 ICMP 协议
        """
        icmp = icmp_data
        self.parsedetails["networklayer"]["ICMP"].append({
            "label": "Name",
            "content": f"Internet Control Message Protocol",
            "hex": "",
            "details": {}
        })  
        
        # ICMP 类型 (Type)
        icmp_type = icmp.type
        type_description = {
            0: "Echo Reply",
            3: "Destination Unreachable",
            8: "Echo Request",
            # 可以根据需求扩展其他类型的描述
        }.get(icmp_type, f"Unknown ({icmp_type})")
        
        self.parsedetails["networklayer"]["ICMP"].append({
            "label": "ICMP Type",
            "content": f"{type_description} ({icmp_type})",
            "hex": hex(icmp_type),
            "details": {}
        })

        # ICMP 代码 (Code)
        icmp_code = icmp.code
        code_description = {
            0: "Net Unreachable",
            1: "Host Unreachable",
            2: "Protocol Unreachable",
            3: "Port Unreachable",
            # 可以根据需求扩展其他代码的描述
        }.get(icmp_code, f"Unknown ({icmp_code})")
        
        self.parsedetails["networklayer"]["ICMP"].append({
            "label": "ICMP Code",
            "content": f"{code_description} ({icmp_code})",
            "hex": hex(icmp_code),
            "details": {}
        })

        # 校验和 (Checksum)
        checksum_hex = f"0x{icmp.sum:04x}"
        self.parsedetails["networklayer"]["ICMP"].append({
            "label": "Checksum",
            "content": f"Checksum: {checksum_hex}",
            "hex": checksum_hex,
            "details": {}
        })

        # 未使用字段 (Unused) — 一般用于 ICMP Destination Unreachable 消息
        if icmp_type == 3:  # Destination Unreachable
            unused_field = "00000000"  # 固定的未使用字段
            self.parsedetails["networklayer"]["ICMP"].append({
                "label": "Unused",
                "content": unused_field,
                "details": {}
            })

        return self.parsedetails 
        
    def icmpv6_parse(self, icmpv6_data):
        """
        解析 ICMPv6 协议（例如 Router Advertisement 类型）
        """
        icmpv6 = icmpv6_data

        self.parsedetails["networklayer"]["ICMP"].append({
            "label": "Name",
            "content": f"Internet Control Message Protocol version 6",
            "hex": "",
            "details": {}
        }) 

        # ICMPv6 类型
        icmpv6_type = icmpv6.type
        type_description = {
            134: "Router Advertisement",
            133: "Router Solicitation",
            # 可以根据需求添加其他类型的描述
        }.get(icmpv6_type, f"Unknown ({icmpv6_type})")
        self.parsedetails["networklayer"]["ICMP"].append({
            "label": "ICMPv6 Type",
            "content": f"{type_description} ({icmpv6_type})",
            "hex": hex(icmpv6_type),
            "details": {}
        })

        # ICMPv6 代码
        icmpv6_code = icmpv6.code
        self.parsedetails["networklayer"]["ICMP"].append({
            "label": "ICMPv6 Code",
            "content": f"Code: {icmpv6_code}",
            "hex": hex(icmpv6_code),
            "details": {}
        })

        # 校验和
        checksum_hex = f"0x{icmpv6.sum:04x}"
        self.parsedetails["networklayer"]["ICMP"].append({
            "label": "Checksum",
            "content": f"Checksum: {checksum_hex} [correct]",
            "hex": checksum_hex,
            "details": {}
        })

        # 跳数限制 (Cur hop limit)
        cur_hop_limit = icmpv6.data[0]
        self.parsedetails["networklayer"]["ICMP"].append({
            "label": "Cur hop limit",
            "content": f"Cur hop limit: {cur_hop_limit}",
            "hex": hex(cur_hop_limit),
            "details": {}
        })

        # 标志 (Flags)
        flags = icmpv6.data[1]
        prf = (flags & 0x18) >> 3  # Router preference (prf) 2 bits
        prf_description = {0: "Low", 1: "Medium", 2: "High"}.get(prf, "Reserved")
        self.parsedetails["networklayer"]["ICMP"].append({
            "label": "Flags",
            "content": f"Flags: 0x{flags:02x}, Prf (Default Router Preference): {prf_description}",
            "hex": hex(flags),
            "details": {}
        })

        # 路由器生存时间 (Router Lifetime)
        router_lifetime = int.from_bytes(icmpv6.data[2:4], byteorder="big")
        self.parsedetails["networklayer"]["ICMP"].append({
            "label": "Router lifetime",
            "content": f"Router lifetime (s): {router_lifetime}",
            "hex": hex(router_lifetime),
            "details": {}
        })

        # 可达时间 (Reachable Time)
        reachable_time = int.from_bytes(icmpv6.data[4:8], byteorder="big")
        self.parsedetails["networklayer"]["ICMP"].append({
            "label": "Reachable time",
            "content": f"Reachable time (ms): {reachable_time}",
            "hex": hex(reachable_time),
            "details": {}
        })

        # 重传计时器 (Retrans Timer)
        retrans_timer = int.from_bytes(icmpv6.data[8:12], byteorder="big")
        self.parsedetails["networklayer"]["ICMP"].append({
            "label": "Retrans timer",
            "content": f"Retrans timer (ms): {retrans_timer}",
            "hex": hex(retrans_timer),
            "details": {}
        })

        # ICMPv6 选项解析（例如源链路层地址、MTU、前缀信息等）
        options = icmpv6.data[12:]
        offset = 0
        while offset < len(options):
            option_type = options[offset]
            option_length = options[offset + 1] * 8  # Option length is in units of 8 bytes
            if option_type == 1:  # Source link-layer address
                link_layer_address = ':'.join(f"{b:02x}" for b in options[offset + 2:offset + 2 + 6])
                self.parsedetails["networklayer"]["ICMP"].append({
                    "label": "ICMPv6 Option (Source link-layer address)",
                    "content": f"Source link-layer address: {link_layer_address}",
                    "hex": options[offset + 2:offset + 2 + 6].hex(),
                    "details": {}
                })
            elif option_type == 5:  # MTU
                mtu = int.from_bytes(options[offset + 4:offset + 8], byteorder="big")
                self.parsedetails["networklayer"]["ICMP"].append({
                    "label": "ICMPv6 Option (MTU)",
                    "content": f"MTU: {mtu}",
                    "hex": hex(mtu),
                    "details": {}
                })
            elif option_type == 3:  # Prefix Information
                prefix_length = options[offset + 2]
                prefix_flags = options[offset + 3]
                prefix_valid_lifetime = int.from_bytes(options[offset + 4:offset + 8], byteorder="big")
                prefix_preferred_lifetime = int.from_bytes(options[offset + 8:offset + 12], byteorder="big")
                prefix = ':'.join(f"{options[offset + 16 + i]:02x}" for i in range(16))
                self.parsedetails["networklayer"]["ICMP"].append({
                    "label": "ICMPv6 Option (Prefix Information)",
                    "content": f"Prefix: {prefix}/{prefix_length}, Valid Lifetime: {prefix_valid_lifetime}s, Preferred Lifetime: {prefix_preferred_lifetime}s",
                    "hex": options[offset + 16:offset + 32].hex(),
                    "details": {}
                })

            offset += option_length

        return self.parsedetails      
        
    # tcp udp 
    def tcp_parse(self, tcp_data):
        """
        解析 TCP 协议
        """
        tcp = tcp_data
        TH_FIN = 0x01
        TH_SYN = 0x02
        TH_RST = 0x04
        TH_PUSH = 0x08
        TH_ACK = 0x10
        TH_URG = 0x20
        TH_ECE = 0x40
        TH_CWR = 0x80
        TH_NS = 0x100

        self.parsedetails["transportlayer"].append({
            "label": "Name",
            "content": f"Transmission Control Protocol",
            "hex": "",
            "details": {}
        })
        
        # 源端口 (Source Port)
        source_port = tcp.sport
        self.parsedetails["transportlayer"].append({
            "label": "Source Port",
            "content": f"Source Port: {str(source_port)}",
            "hex": hex(source_port),
            "details": {}
        })

        # 目标端口 (Destination Port)
        destination_port = tcp.dport
        self.parsedetails["transportlayer"].append({
            "label": "Destination Port",
            "content": f"Destination Port: {str(destination_port)}",
            "hex": hex(destination_port),
            "details": {}
        })

        # 序列号 (Sequence Number)
        sequence_number = tcp.seq
        self.parsedetails["transportlayer"].append({
            "label": "Sequence Number",
            "content": f"Sequence Number: {sequence_number}",
            "hex": hex(sequence_number),
            "details": {}
        })

        # 确认号 (Acknowledgment Number)
        acknowledgment_number = tcp.ack
        self.parsedetails["transportlayer"].append({
            "label": "Acknowledgment Number",
            "content": f"Acknowledgment Number: {acknowledgment_number}",
            "hex": hex(acknowledgment_number),
            "details": {}
        })

        # Header Length (Header Length)
        header_length = tcp.off
        self.parsedetails["transportlayer"].append({
            "label": "Header Length",
            "content": f"Header Length: {header_length * 4} bytes",  # Header length is in 4-byte words
            "hex": hex(header_length),
            "details": {}
        })

        # 标志 (Flags) 逐个解析并构造描述
        flags = tcp.flags

        # 定义 TCP 标志位及其在二进制字符串中的位置
        flag_details = [
            ("NS", 8),   # NS 是第 9 位
            ("CWR", 7),  # CWR 是第 8 位
            ("ECE", 6),  # ECE 是第 7 位
            ("URG", 5),  # URG 是第 6 位
            ("ACK", 4),  # ACK 是第 5 位
            ("PSH", 3),  # PSH 是第 4 位
            ("RST", 2),  # RST 是第 3 位
            ("SYN", 1),  # SYN 是第 2 位
            ("FIN", 0)   # FIN 是第 1 位
        ]

        # 生成 flags_description 列表
        flags_str = [name for name, bit in flag_details if flags & (1 << bit)]
        flags_description = " | ".join(flags_str) if flags_str else "No flags set"

        # 构造详细标志位解析，按图中的格式显示
        details = {}
        for name, bit in flag_details:
            # 创建一个二进制布局字符串
            bit_pattern = list("........")  # 初始化为全点的占位符
            bit_pattern[7 - bit] = "1" if flags & (1 << bit) else "0"  # 根据标志位设置为1或0
            bit_pattern_str = "".join(bit_pattern[:4]) + " " + "".join(bit_pattern[4:])  # 格式化为 ".... ...."
            
            # 加入details字典，格式化为图中显示的样式
            details[name] = f"{bit_pattern_str} = {name}: {'Set' if flags & (1 << bit) else 'Not set'}"

        # 将解析后的 flags 信息加入 parsedetails
        self.parsedetails["transportlayer"].append({
            "label": "Flags",
            "content": flags_description,
            "hex": hex(flags),
            "details": details
        })

        # 窗口大小 (Window Size)
        window_size = tcp.win
        self.parsedetails["transportlayer"].append({
            "label": "Window Size",
            "content": f"Window: {window_size}",
            "hex": hex(window_size),
            "details": {}
        })

        # 校验和 (Checksum)
        checksum = tcp.sum
        self.parsedetails["transportlayer"].append({
            "label": "Checksum",
            "content": f"Checksum: (0x{checksum:04x})",
            "hex": hex(checksum),
            "details": {}
        })

        # 紧急指针 (Urgent Pointer)
        urgent_p = tcp.urp
        self.parsedetails["transportlayer"].append({
            "label": "Urgent Pointer",
            "content": f"Urgent Pointer:{urgent_p}",
            "hex": hex(urgent_p),
            "details": {}
        })


        # 源端口 (Source Port)
        source_port = tcp_data.sport
        # 目标端口 (Destination Port)
        destination_port = tcp_data.dport

        # 判断是否是 HTTP，若是则调用 http_parse
        if destination_port == 80 or source_port == 80:
            # HTTP 解析调用
            if tcp_data.data:  # 检查是否有有效的应用层数据
                self.http_parse(tcp_data.data)

        
        return self.parsedetails
        
    def udp_parse(self, udp_data):
        """
        解析 UDP 协议
        """
        udp = udp_data
        self.parsedetails["transportlayer"].append({
            "label": "Name",
            "content": f"User Datagram Protocol",
            "hex": "",
            "details": {}
        })  

        # 源端口 (Source Port)
        source_port = udp.sport
        self.parsedetails["transportlayer"].append({
            "label": "Source Port",
            "content": f"Source Port: {source_port}",
            "hex": hex(source_port),
            "details": {}
        })

        # 目标端口 (Destination Port)
        destination_port = udp.dport
        self.parsedetails["transportlayer"].append({
            "label": "Destination Port",
            "content": f"Destination Port: {destination_port}",
            "hex": hex(destination_port),
            "details": {}
        })

        # UDP 长度 (Length)
        length = udp.ulen
        self.parsedetails["transportlayer"].append({
            "label": "Length",
            "content": f"Length: {length}",
            "hex": hex(length),
            "details": {}
        })

        # 校验和 (Checksum)
        checksum = udp.sum
        checksum_status = "Unverified"  # UDP 校验和一般不验证，状态为未验证
        self.parsedetails["transportlayer"].append({
            "label": "Checksum",
            "content": f"Checksum: 0x{checksum:04x} [{checksum_status}]",
            "hex": hex(checksum),
            "details": {
                "Checksum Status": checksum_status
            }
        })

        # 解析 UDP 负载 (Payload)
        payload_length = len(udp.data)  # 获取负载的字节数
        self.parsedetails["transportlayer"].append({
            "label": "UDP payload",
            "content": f"UDP payload: {payload_length} bytes",
            "details": {}
        })
        
        # 源端口 (Source Port)
        source_port = udp_data.sport
        # 目标端口 (Destination Port)
        destination_port = udp_data.dport

        # 判断是否是 DNS，若是则调用 dns_parse
        if destination_port == 53 or source_port == 53:
            # DNS 解析调用
            if udp_data.data:  # 检查是否有有效的应用层数据
                self.dns_parse(udp_data.data)

        return self.parsedetails
    
    
    def dns_parse(self, dns_data):
        """
        使用 dpkt 解析 DNS 协议
        """
        # dns = dns_data
        dns = dpkt.dns.DNS(dns_data)

        self.parsedetails["applicationlayer"].append({
            "label": "Name",
            "content": f"Domain Name System",
            "hex": "",
            "details": {}
        })  
          
        transaction_id = dns.id
        self.parsedetails["applicationlayer"].append({
            "label": "Transaction ID",
            "content": f"Transaction ID: 0x{transaction_id:04x}",
            "hex": hex(transaction_id),
            "details": {}
        })

        # 操作码 (Opcode)
        opcode = dns.op  # 操作码字段，直接访问 `op` 属性
        self.parsedetails["applicationlayer"].append({
            "label": "Opcode",
            "content": f"Opcode: {opcode}",
            "details": {}
        })

        # 解析 DNS 查询记录 (Questions)
        questions = [{"name": q.name, "type": q.type, "class": q.cls} for q in dns.qd]
        self.parsedetails["applicationlayer"].append({
            "label": "Questions",
            "content": f"{len(questions)} Questions",
            "details": questions
        })

        # 解析 DNS 回答记录 (Answers)
        answers = [{"name": ans.name, "type": ans.type, "class": ans.cls, "ttl": ans.ttl, "data": str(ans.rdata)} for ans in dns.an]
        self.parsedetails["applicationlayer"].append({
            "label": "Answers",
            "content": f"{len(answers)} Answers",
            "details": answers
        })

        # 解析 DNS 权威记录 (Authority Records)
        authority_records = [{"name": auth.name, "type": auth.type, "class": auth.cls, "ttl": auth.ttl, "data": str(auth.rdata)} for auth in dns.ns]
        self.parsedetails["applicationlayer"].append({
            "label": "Authority Records",
            "content": f"{len(authority_records)} Authority Records",
            "details": authority_records
        })

        # 解析 DNS 附加记录 (Additional Records)
        additional_records = [{"name": add.name, "type": add.type, "class": add.cls, "ttl": add.ttl, "data": str(add.rdata)} for add in dns.ar]
        self.parsedetails["applicationlayer"].append({
            "label": "Additional Records",
            "content": f"{len(additional_records)} Additional Records",
            "details": additional_records
        })

        return self.parsedetails

    def http_parse(self, http_data):
        """
        使用 dpkt 解析 HTTP 协议
        """
        is_request = None  # 初始化 is_request 变量


        self.parsedetails["applicationlayer"].append({
            "label": "Name",
            "content": f"Hypertext Transfer Protocol",
            "hex": "",
            "details": {}
        })  

        try:
            # 尝试将数据解析为 HTTP 请求
            http = dpkt.http.Request(http_data)
            is_request = True
        except (dpkt.dpkt.NeedData, dpkt.dpkt.UnpackError):
            try:
                # 如果解析失败，则尝试解析为 HTTP 响应
                http = dpkt.http.Response(http_data)
                is_request = False
            except (dpkt.dpkt.NeedData, dpkt.dpkt.UnpackError):
                return self.parsedetails

        if is_request is True:
            # 解析 HTTP 请求信息
            self.parsedetails["applicationlayer"].append({
                "label": "HTTP Request",
                "content": f"Method: {http.method}, URI: {http.uri}, Version: {http.version}",
                "details": {}
            })
        elif is_request is False:
            # 解析 HTTP 响应信息
            self.parsedetails["applicationlayer"].append({
                "label": "HTTP Response",
                "content": f"Version: HTTP/{http.version}, Status: {http.status}, Reason: {http.reason}",
                "details": {}
            })

        # 解析 HTTP 头部信息
        headers = {k: v for k, v in http.headers.items()}
        self.parsedetails["applicationlayer"].append({
            "label": "HTTP Headers",
            "content": f"Headers: {len(headers)} headers",
            "details": headers
        })

        # 解析 HTTP 主体内容（如果存在）
        body_length = len(http.body)
        self.parsedetails["applicationlayer"].append({
            "label": "HTTP Body",
            "content": f"Body Length: {body_length} bytes",
            "details": {}
        })

        return self.parsedetails



if __name__ == "__main__":
    import pcap
    
    test = PcapThread()
    test.start()

    # 让程序运行一段时间，然后停止线程
    input("按回车键停止抓包...\n")
    test.stop()

