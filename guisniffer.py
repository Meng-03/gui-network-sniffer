from sniffer import PcapThread
from ui_ui import Ui_MainWindow
from PySide6.QtWidgets import QMainWindow,QTableWidgetItem,QApplication,QTreeWidgetItem,QTreeWidget
import sys

class MainWindow(QMainWindow,Ui_MainWindow):
    def __init__(self):
        super().__init__()
        self.setupUi(self)
        
        # 抓包线程
        self.pcapthread=PcapThread()
        self.pcapthread.pkg_get.connect(self.display_capture)
        
        # 按钮槽函数连接
        self.ButtonStart.clicked.connect(self.start_capture)
        self.ButtonStop.clicked.connect(self.stop_capture)
        
        
        # test
        details_text = {
            "Ethernet Frame": {
                "Src MAC": "00:1A:2B:3C:4D:5E",
                "Dst MAC": "5E:4D:3C:2B:1A:00",
                "Type": "0x0800"
            },
            "IP Protocol": {
                "Version": "4",
                "Header Length": "20 bytes",
                "TTL": "64",
                "Protocol": "TCP",
                "Src IP": "192.168.1.1",
                "Dst IP": "192.168.1.2",
                "Total Length": "60",
                "Header Checksum": "0x1c46"
            },
            "TCP Segment": {
                "Src Port": "443",
                "Dst Port": "64293",
                "Sequence Number": "1",
                "Acknowledgment Number": "1",
                "Header Length": "20 bytes",
                "Flags": "0x18",
                "Window Size": "4096",
                "Checksum": "0x1f90",
                "Urgent Pointer": "0"
            }
        }
        
        self.parse_selected_packet(details_text,0)
        
    def start_capture(self):
        """
        开始抓包线程
        """
        if not self.pcapthread.isRunning():
            self.pcapthread.start()
            
    def stop_capture(self):
        """
        停止抓包线程
        """
        self.pcapthread.stop()
        
    def display_capture(self,raw_buf,time_str,src_ip, dst_ip, protocol_type,len_str,info):
        """
        展示抓包信息
        """
        print("display",raw_buf,time_str,src_ip, dst_ip, protocol_type,len_str,info,"\n")
        
        row_position = self.PacketTable.rowCount()
        self.PacketTable.insertRow(row_position)
        self.PacketTable.setItem(row_position, 0, QTableWidgetItem(time_str))
        self.PacketTable.setItem(row_position, 1, QTableWidgetItem(src_ip))
        self.PacketTable.setItem(row_position, 2, QTableWidgetItem(dst_ip))
        self.PacketTable.setItem(row_position, 3, QTableWidgetItem(protocol_type))
        self.PacketTable.setItem(row_position, 4, QTableWidgetItem(len_str))
        self.PacketTable.setItem(row_position, 5, QTableWidgetItem(info))
       
       
    def parse_selected_packet(self,packet_details,row):
        """
        展示所选择的需要解析的数据包
        """
        # raw_buf=self.pcapthread.captured_packets[row]
        # packet_details=self.pcapthread.parsepkg(row)

        for layer, fields in packet_details.items():
            layer_item = QTreeWidgetItem(self.PacketTree)
            layer_item.setText(0, layer)
            self.PacketTree.addTopLevelItem(layer_item)
            
            for field, value in fields.items():
                field_item = QTreeWidgetItem(layer_item)
                field_item.setText(0, field)
                field_item.setText(1, value)
                
            layer_item.setExpanded(False)
        
        # 使每一列自适应内容宽度
        self.PacketTree.resizeColumnToContents(0)
        self.PacketTree.resizeColumnToContents(1)

        
        
if __name__=="__main__":
    guisniffer=QApplication(sys.argv)
    mainwindow=MainWindow()
    mainwindow.show()
    sys.exit(guisniffer.exec())
    