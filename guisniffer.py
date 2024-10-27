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
        
    def display_capture(self,src,dst,proto):
        """
        table展示抓包信息
        """
        print("display_capture",src,dst,proto,"\n")
        row_position = self.pkgtable.rowCount()
        self.pkgtable.insertRow(row_position)
        self.pkgtable.setItem(row_position, 0, QTableWidgetItem(src))
        self.pkgtable.setItem(row_position, 1, QTableWidgetItem(dst))
        self.pkgtable.setItem(row_position, 2, QTableWidgetItem(proto))
        print("table展示")
        
        
if __name__=="__main__":
    guisniffer=QApplication(sys.argv)
    mainwindow=MainWindow()
    mainwindow.show()
    sys.exit(guisniffer.exec())
    