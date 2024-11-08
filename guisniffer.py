from sniffer import PcapThread,PacketParser
from ui_ui import Ui_MainWindow
from PySide6.QtWidgets import QMainWindow,QTableWidgetItem,QApplication,QTreeWidgetItem
from PySide6.QtGui import QColor
import sys

class MainWindow(QMainWindow,Ui_MainWindow):
    def __init__(self):
        super().__init__()
        self.setupUi(self)
        
        
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
        
        
        # 槽函数连接
        self.ButtonStart.clicked.connect(self.start_capture)
        self.ButtonStop.clicked.connect(self.stop_capture)
        self.PacketTable.cellClicked.connect(self. on_row_clicked)
        
        
        # 抓包线程
        self.pcapthread=PcapThread()
        self.pcapthread.pkg_get.connect(self.display_capture)
        # 细节解析
        self.packetdetail=PacketParser()
        self.show_first_packet_details()#默认展示第一行
        
        
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
        
        # self.parse_selected_packet(details_text,0)
        
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
        
    def closeEvent(self, event):
        """
        当用户点击关闭按钮时停止抓包并关闭窗口
        """
        # 停止抓包线程
        self.stop_capture()
        # 继续关闭窗口
        event.accept()
        
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

    def show_first_packet_details(self):
        """
        检查是否有数据包，如果有则默认展示第一行数据包的细节
        """
        if len(self.pcapthread.captured_packets) > 0:
            # 获取第一行的数据包
            raw_buf = self.pcapthread.captured_packets[0]["raw_buf"]
            # 解析并展示第一行数据包细节
            packet_details = self.packetdetail.parse(raw_buf)
            self.display_packet_details(packet_details)
            self.display_packet_hex(raw_buf)

    def on_row_clicked(self, row, column):
        """
        当点击表格的某行时，获取该行的数据包并展示其解析细节
        """
        if row < len(self.pcapthread.captured_packets):
            raw_buf = self.pcapthread.captured_packets[row]["raw_buf"]  # 获取点击行的数据包
            packet_details = self.packetdetail.parse(raw_buf,row)  # 解析数据包
            self.display_packet_details(packet_details)  # 展示解析细节
            self.display_packet_hex(raw_buf)
    
      
    def display_packet_details(self,packet_details):
        # 清空现有内容
        self.PacketTree.clear()
        print(packet_details)

        # 处理 Frame 
        frame_item = QTreeWidgetItem(self.PacketTree)
        frame_data=packet_details["frame"][0]
        label = frame_data["label"]
        content = frame_data["content"]
        frame_item.setText(0, f"{label}: {content}")
        self.PacketTree.addTopLevelItem(frame_item)

        # 处理 Data Linker 层
        datalink_item = QTreeWidgetItem(self.PacketTree)
        
        self.PacketTree.addTopLevelItem(datalink_item)

        # 依次处理 datalinker 列表的每一项
        for datalink_field in packet_details.get("datalinker", []):
            # 为每个 datalink_field 创建一个子项
            field_label = datalink_field.get("label", "")
            field_content = datalink_field.get("content", "")
            details = datalink_field.get("details", {})

            # 设置 label 和 content 为主要显示内容
            data_item = QTreeWidgetItem(datalink_item)
            data_item.setText(0, f"{field_label}: {field_content}")
            if field_label=="Destination MAC Address":
                src=field_content
            if field_label=="Source MAC Address":
                des=field_content
                
            # 添加 details 子项（如果存在）
            if details:
                for detail_key, detail_value in details.items():
                    print(detail_key,detail_value)
                    detail_item = QTreeWidgetItem(data_item)
                    detail_item.setText(0, detail_value)
                    data_item.addChild(detail_item)
        datalink_item.setText(0, f"Ethernet: Src: {src}, Des: {des}")  # 设置 Data Link Layer 的顶层项名称

        
        # 处理 Network Layer 层
        # 处理 IP 子项----【todo】details展示
        ip_item = QTreeWidgetItem(self.PacketTree) 
        self.PacketTree.addTopLevelItem(ip_item)  
            
        for ip_field in packet_details.get("networklayer", {}).get("IP", []):
            # 为每个 ip_field 创建一个子项
            field_label = ip_field.get("label", "")
            field_content = ip_field.get("content", "")
            details = ip_field.get("details", {})

            # 设置 label 和 content 为主要显示内容
            data_item = QTreeWidgetItem(ip_item)
            if field_label=="Source Address":
                src=field_content
                data_item.setText(0, f"{field_label}: {field_content}")
            elif field_label=="Destination Address":
                des=field_content
                data_item.setText(0, f"{field_label}: {field_content}")
            else:
                data_item.setText(0, f"{field_content}")
                
            # 添加 details 子项（如果存在）
            if details:
                for detail_key, detail_value in details.items():
                    print(detail_key,detail_value)
                    detail_item = QTreeWidgetItem(data_item)
                    detail_item.setText(0, detail_value)
                    data_item.addChild(detail_item)
        ip_item.setText(0, f"Internet Protocol Version 4: Src: {src}, Des: {des}")
        

        # 仅当 ICMP 有内容时，添加 ICMP 子项
        icmp_fields = packet_details.get("networklayer", {}).get("ICMP", [])
        if icmp_fields:
            icmp_item = QTreeWidgetItem(self.PacketTree)
            icmp_item.setText(0, "ICMP")
            for icmp_field in icmp_fields:
                self.add_field_with_details(icmp_item, icmp_field)
            self.PacketTree.addChild(icmp_item)
            self.PacketTree.addTopLevelItem(icmp_item)

        # 处理 Transport Layer 层
        transport_item = QTreeWidgetItem(self.PacketTree)
        transport_item.setText(0, "Transport Layer")
        for transport_field in packet_details.get("transportlayer", []):
            self.add_field_with_details(transport_item, transport_field)
        self.PacketTree.addTopLevelItem(transport_item)

        # 处理 Application Layer 层
        application_item = QTreeWidgetItem(self.PacketTree)
        application_item.setText(0, "Application Layer")
        for application_field in packet_details.get("applicationlayer", []):
            self.add_field_with_details(application_item, application_field)
        self.PacketTree.addTopLevelItem(application_item)

        # 展开或折叠顶层项（可根据需求设置默认状态）
        self.PacketTree.expandAll()  # 展开所有项
        # 自动调整列宽
        self.PacketTree.resizeColumnToContents(0)
        self.PacketTree.resizeColumnToContents(1)

    def add_field_with_details(self, parent_item, field_data):
        """
        添加字段并检查是否有 details。如果 details 存在且有内容，则作为子项添加。
        """
        field_item = QTreeWidgetItem(parent_item)
        field_item.setText(0, field_data.get("label", ""))
        field_item.setText(1, field_data.get("value", ""))
        parent_item.addChild(field_item)

        # 检查 details 是否有内容
        details = field_data.get("details", {})
        if details:
            for detail_key, detail_value in details.items():
                detail_item = QTreeWidgetItem(field_item)
                detail_item.setText(0, detail_key)
                detail_item.setText(1, str(detail_value))
                field_item.addChild(detail_item)

      
    # def display_packet_details(self,packet_details):
    #     """
    #     展示所选择的需要解析的数据包
    #     """
    #     print(packet_details)
    #     self.PacketTree.clear() 

    #     for layer, fields in packet_details.items():
    #         layer_item = QTreeWidgetItem(self.PacketTree)
    #         layer_item.setText(0, layer)
    #         self.PacketTree.addTopLevelItem(layer_item)
            
    #         for field, value in fields.items():
    #             field_item = QTreeWidgetItem(layer_item)
    #             field_item.setText(0, field)
    #             field_item.setText(1, value)
                
    #         layer_item.setExpanded(False)
        
    #     # 使每一列自适应内容宽度
    #     self.PacketTree.resizeColumnToContents(0)
    #     self.PacketTree.resizeColumnToContents(1)

    def display_packet_hex(self, raw_buf):
        """
        在 PacketHex 窗口中以 16 进制格式展示 raw_buf
        """
        hex_output = []
        ascii_output = []
        result = ""

        # 将 raw_buf 按每 16 个字节分行
        for i in range(0, len(raw_buf), 16):
            hex_chunk = raw_buf[i:i+16]
            hex_str = ' '.join(f"{byte:02x}" for byte in hex_chunk)
            ascii_str = ''.join(chr(byte) if 32 <= byte <= 126 else '.' for byte in hex_chunk)

            # 格式化行，左侧显示偏移量
            line = f"{i:04x}  {hex_str:<48}  {ascii_str}\n"
            result += line

        # 在 PacketHex 窗口中显示结果
        self.PacketHex.setPlainText(result)
        
        
if __name__=="__main__":
    guisniffer=QApplication(sys.argv)
    mainwindow=MainWindow()
    mainwindow.show()
    
    parsedetails={
        "raw_buf": "307bac693802603e5f8572da86dd600a0400001406402400dd01103a4032cdc3a70ed79d32c024024e0014300249000096e0deeed689db5001bbf7802a01925f2d46501110003c2d0000",
        "frame": [
            {
                "label": "Frame",
                "content": "Frame 0: 74 bytes on interface en0",
                "hex": "307bac693802603e5f8572da86dd600a0400001406402400dd01103a4032cdc3a70ed79d32c024024e0014300249000096e0deeed689db5001bbf7802a01925f2d46501110003c2d0000",
                "details": {}
            }
        ],
        "datalinker": [
            {
                "label": "Destination MAC Address",
                "content": "30: 7b:ac: 69: 38: 02",
                "hex": "307bac693802",
                "details": {
                    "lg_bit": ".... ..1 .... .... .... = LG bit: Globally unique address (factory default)",
                    "ig_bit": ".... ...1 .... .... .... = IG bit: Individual address (unicast)"
                }
            },
            {
                "label": "Source MAC Address",
                "content": "60:3e: 5f: 85: 72:da",
                "hex": "603e5f8572da",
                "details": {
                    "lg_bit": ".... ..1 .... .... .... = LG bit: Globally unique address (factory default)",
                    "ig_bit": ".... ...1 .... .... .... = IG bit: Individual address (unicast)"
                }
            },
            {
                "label": "Type",
                "content": "IPv6",
                "hex": "0x86dd",
                "details": {}
            }
        ],
        "networklayer": {
            "IP": [
                {
                    "label": "Version",
                    "content": "0110 .... = Version: 6",
                    "hex": "0x6",
                    "details": {}
                },
                {
                    "label": "Traffic Class",
                    "content": ".... 00000000 .... .... .... = Traffic Class: 0x00 (DSCP: CS0, ECN: Not-ECT)",
                    "hex": "0x00",
                    "details": {}
                },
                {
                    "label": "Flow Label",
                    "content": ".... 10100000010000000000 = Flow Label: 0xa0400",
                    "hex": "0xa0400",
                    "details": {}
                },
                {
                    "label": "Payload Length",
                    "content": "Payload Length: 20",
                    "hex": "0x14",
                    "details": {}
                },
                {
                    "label": "Next Header",
                    "content": "Next Header: TCP (6)",
                    "hex": "0x6",
                    "details": {}
                },
                {
                    "label": "Hop Limit",
                    "content": "Hop Limit: 64",
                    "hex": "0x40",
                    "details": {}
                },
                {
                    "label": "Source Address",
                    "content": "2400:dd01: 103a: 4032:cdc3:a70e:d79d: 32c0",
                    "hex": "2400dd01103a4032cdc3a70ed79d32c0",
                    "details": {}
                },
                {
                    "label": "Destination Address",
                    "content": "2402: 4e00: 1430: 0249: 0000: 96e0:deee:d689",
                    "hex": "24024e0014300249000096e0deeed689",
                    "details": {}
                }
            ],
            "ICMP": []
        },
        "transportlayer": [
            {
                "label": "Source Port",
                "content": "Source Port: 56144",
                "hex": "0xdb50",
                "details": {}
            },
            {
                "label": "Destination Port",
                "content": "Destination Port: 443",
                "hex": "0x1bb",
                "details": {}
            },
            {
                "label": "Sequence Number",
                "content": "Sequence Number: 4152371713",
                "hex": "0xf7802a01",
                "details": {}
            },
            {
                "label": "Acknowledgment Number",
                "content": "Acknowledgment Number: 2455711046",
                "hex": "0x925f2d46",
                "details": {}
            },
            {
                "label": "Header Length",
                "content": "Header Length: 20 bytes",
                "hex": "0x5",
                "details": {}
            },
            {
                "label": "Flags",
                "content": "ACK | FIN",
                "hex": "0x11",
                "details": {
                    "NS": ".... ...0 = NS: Not set",
                    "CWR": "0... .... = CWR: Not set",
                    "ECE": ".0.. .... = ECE: Not set",
                    "URG": "..0. .... = URG: Not set",
                    "ACK": "...1 .... = ACK: Set",
                    "PSH": ".... 0... = PSH: Not set",
                    "RST": ".... .0.. = RST: Not set",
                    "SYN": ".... ..0. = SYN: Not set",
                    "FIN": ".... ...1 = FIN: Set"
                }
            },
            {
                "label": "Window Size",
                "content": "Window: 4096",
                "hex": "0x1000",
                "details": {}
            },
            {
                "label": "Checksum",
                "content": "Checksum: (0x3c2d)",
                "hex": "0x3c2d",
                "details": {}
            },
            {
                "label": "Urgent Pointer",
                "content": "Urgent Pointer: 0",
                "hex": "0x0",
                "details": {}
            }
        ],
        "applicationlayer": []
    }
    mainwindow.display_packet_details(parsedetails)
    sys.exit(guisniffer.exec())