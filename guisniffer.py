from sniffer import PcapThread
from ui_ui import Ui_MainWindow
from PySide6.QtWidgets import QMainWindow,QTableWidgetItem,QApplication
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
        
    def display_capture(self,time_str,src_ip, dst_ip, protocol_type,len_str,info):
        """
        table展示抓包信息
        """
        print("display",time_str,src_ip, dst_ip, protocol_type,len_str,info,"\n")
        
        row_position = self.pkgtable.rowCount()
        self.pkgtable.insertRow(row_position)
        self.pkgtable.setItem(row_position, 0, QTableWidgetItem(time_str))
        self.pkgtable.setItem(row_position, 1, QTableWidgetItem(src_ip))
        self.pkgtable.setItem(row_position, 2, QTableWidgetItem(dst_ip))
        self.pkgtable.setItem(row_position, 3, QTableWidgetItem(protocol_type))
        self.pkgtable.setItem(row_position, 4, QTableWidgetItem(len_str))
        self.pkgtable.setItem(row_position, 5, QTableWidgetItem(info))
        
        
if __name__=="__main__":
    guisniffer=QApplication(sys.argv)
    mainwindow=MainWindow()
    mainwindow.show()
    sys.exit(guisniffer.exec())
    