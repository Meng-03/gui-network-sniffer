from sniffer import PcapThread
from ui_ui import Ui_MainWindow
from PySide6.QtWidgets import QMainWindow,QTableWidgetItem,QApplication,QTreeWidgetItem
from PySide6.QtGui import QColor
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
        
        # 设置列宽
        self.PacketTable.setColumnWidth(0, 80)  # Time 列宽度
        self.PacketTable.setColumnWidth(1, 180)  # Source 列宽度
        self.PacketTable.setColumnWidth(2, 180)  # Destination 列宽度
        self.PacketTable.setColumnWidth(3, 80)  # Protocol 列宽度
        self.PacketTable.setColumnWidth(4, 60)   # Length 列宽度
        # 设置最后一列自动填充剩余空间
        header = self.PacketTable.horizontalHeader()
        header.setStretchLastSection(True)  # 最后一列设为可伸缩列
        # 自动调整每行高度（可选）
        self.PacketTable.resizeRowsToContents()
        
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
        # 设置行的背景颜色，基于协议类型
        color = QColor(255, 255, 255)  # 默认白色
        if protocol_type == "Unknown":
            color = QColor(211, 211, 211)# 浅灰色
        elif protocol_type == "ARP":
            color = QColor(222,184,135)  # 浅棕
        elif protocol_type == "IPv4":
            color = QColor(255,250,205)  # 浅黄
        elif protocol_type == "IPv6":
            color = QColor(255,228,181)  # 浅橘
        elif protocol_type == "ICMP":
            color = QColor(255,192,203)  # 粉红
        elif protocol_type == "ICMPv6":
            color = QColor(255,182,193)  # 浅粉红
        elif protocol_type == "TCP":
            color = QColor(225,255,255)  # 浅蓝
        elif protocol_type == "UDP":
            color = QColor(230,230,250)  # 浅紫色
        elif protocol_type == "HTTP":
            color = QColor(152,251,152)  # 绿1
        elif protocol_type == "DNS":
            color = QColor(173,255,47)   # 绿2

        # 为当前行的所有单元格设置背景颜色
        for col in range(self.PacketTable.columnCount()):
            item = self.PacketTable.item(row_position, col)
            if item is not None:
                item.setBackground(color)

       
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
    