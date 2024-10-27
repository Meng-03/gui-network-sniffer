import pcap
import dpkt
import time
from PySide6.QtCore import QThread,Signal


class PcapThread(QThread):
    pkg_get=Signal(str,str,str,str,str,str)#time,src,dst,proto,len,info
    # 支持协议类型
    PROTOCOLS = {
        dpkt.ip.IP_PROTO_TCP: 'TCP',
        dpkt.ip.IP_PROTO_UDP: 'UDP',
        dpkt.ip.IP_PROTO_ICMP: 'ICMP',
        dpkt.ip.IP_PROTO_IGMP: 'IGMP',
        0x0800: 'IPv4',    
        0x86DD: 'IPv6',       
        0x0806: 'ARP',       
        0x8035: 'RARP'        
    }

    # 支持应用层协议端口
    APP_LAYER_PORTS = {
        80: 'HTTP',
        443: 'HTTPS',
        53: 'DNS'
    }
    
    def __init__(self,parent=None):
        super().__init__(parent)
        self.running=False #start/stop pcap
    
    def start(self):
        self.running=True
        super().start()
              
    def stop(self):
        self.running=False
        self.wait()
        
    def run(self):
        """
        获取数据包
        """
        # todo. filtercapture和capture-筛选和不筛选
        
        # todo.设备筛选
        devs=pcap.findalldevs()
        print("设备",devs,sep='\n')
        getpkg=pcap.pcap(name='en0',promisc=True,immediate=True,timeout_ms=50)
        
        for timestamp, raw_buf in getpkg:
            # 解析以太网帧
            eth = dpkt.ethernet.Ethernet(raw_buf)
            protocol_type="Unknown"
            src_ip,dst_ip,info="N/A","N,A","No Additional Info"
            
            # ARP/RARP
            if isinstance(eth.data, dpkt.arp.ARP):
                protocol_type="ARP" if eth.data.op==dpkt.arp.ARP_OP_REQUEST else "RARP"
                src_ip='.'.join(map(str,eth.data.spa))
                dst_ip='.'.join(map(str,eth.data.tpa))
                info=f'{src_ip} -> {dst_ip} ARP/RARP Request'
                
            elif isinstance(eth.data,dpkt.ip.IP):
                protocol_type="IPv4"
                src_ip='.'.join(map(str,eth.data.src))
                dst_ip='.'.join(map(str,eth.data.dst)) 
                protocal_name = self.PROTOCOLS.get(eth.data.p,'Unknown')            
                
                #TCP/UDP
                if protocal_name in ['TCP','UDP']:
                    try:
                        src_port,dst_port=eth.data.sport,eth.data.dport
                        app_protocol=self.APP_LAYER_PORTS.get(dst_port,protocal_name)
                        info=f"{src_port} -> {dst_port} {app_protocol}"
                        protocol_type = app_protocol if app_protocol != protocal_name else protocal_name
                    except AttributeError:
                        info = "No Port Info"
                        
                #ICMP/IGMP
                elif protocal_name in ['ICMP','IGMP']:
                    protocol_type=protocal_name
                    info=f"{protocal_name} Packet"
                    
            elif isinstance(eth.data,dpkt.ip6.IP6):
                protocol_type="IPv6"
                src_ip=':'.join(f"{eth.data.src[i]:x}" for i in range(0,16,2))
                dst_ip=':'.join(f"{eth.data.dst[i]:x}" for i in range(0,16,2))
                info="IPv6 Packet"
            
            time_str=time.strftime('%H:%M:%S',time.localtime(timestamp))
            output={
                '时间':time_str,
                '源地址':src_ip,
                '目的地址':dst_ip,
                '协议类型':protocol_type,
                '长度':len(raw_buf),
                '备注':info
            }
            print(output)                    

            len_str = str(len(raw_buf)) 
            self.pkg_get.emit(time_str,src_ip, dst_ip, protocol_type,len_str,info)           
            
            
    def parsepkg(self):
        """
        解析数据包
        """
    
    def save(self):
        """
        保存
        """    
