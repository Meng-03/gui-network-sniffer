import pcap
import dpkt
import time

devs=pcap.findalldevs()
print("设备",devs,sep='\n')

print("before")
# 抓包
getpkg=pcap.pcap(name='en0',promisc=True,immediate=True)
print("after")

for timestamp, raw_buf in getpkg:
    # 解析以太网帧
    print("test")
    eth = dpkt.ethernet.Ethernet(raw_buf)
    print("test")
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
    print()
    print(output1)
    print(output2)
    print(output3)
    print(output4)
