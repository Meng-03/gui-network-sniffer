import pcap
import dpkt
import time
from PySide6.QtCore import QThread,Signal

class PcapThread(QThread):
    pkg_get=Signal(str,str,str)#src,dst,proto
    
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
        devs=pcap.findalldevs()
        print("设备",devs,sep='\n')

        getpkg=pcap.pcap(name='en0',promisc=True,immediate=True,timeout_ms=50)

        for timestamp, raw_buf in getpkg:
            # 解析以太网帧
            eth = dpkt.ethernet.Ethernet(raw_buf)
            if not isinstance(eth.data,dpkt.ip.IP):
                print("non ip pkg type not supported",eth.data.__class__.__name__)
                continue
            
            pkg=eth.data
            
            df=bool(pkg.off & dpkt.ip.IP_DF)
            mf=bool(pkg.off & dpkt.ip.IP_MF)
            offset=pkg.off & dpkt.ip.IP_OFFMASK
            
            
            # 输出数据包信息：time,src,dst,protocol,length,ttl,df,mf,offset,checksum
            output1 = {'time':time.strftime('%Y-%m-%d %H:%M:%S',(time.localtime(timestamp)))}
            output2 = {'src':'%d.%d.%d.%d'%tuple(pkg.src) , 'dst':'%d.%d.%d.%d'%tuple(pkg.dst)}
            output3 = {'protocol':pkg.p, 'len':pkg.len, 'ttl':pkg.ttl}
            output4 = {'df':df, 'mf':mf, 'offset':offset, 'checksum':pkg.sum}

            # 发送信号
            src_ip = '.'.join(map(str, pkg.src))
            dst_ip = '.'.join(map(str, pkg.dst))
            proto = str(pkg.p)
            print(src_ip,dst_ip,proto,"/n")
            self.pkg_get.emit(src_ip, dst_ip, proto)           
            
            
    def parsepkg(self):
        """
        解析数据包
        """
