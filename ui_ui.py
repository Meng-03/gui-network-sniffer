# -*- coding: utf-8 -*-

################################################################################
## Form generated from reading UI file 'ui.ui'
##
## Created by: Qt User Interface Compiler version 6.6.3
##
## WARNING! All changes made in this file will be lost when recompiling UI file!
################################################################################

from PySide6.QtCore import (QCoreApplication, QDate, QDateTime, QLocale,
    QMetaObject, QObject, QPoint, QRect,
    QSize, QTime, QUrl, Qt)
from PySide6.QtGui import (QBrush, QColor, QConicalGradient, QCursor,
    QFont, QFontDatabase, QGradient, QIcon,
    QImage, QKeySequence, QLinearGradient, QPainter,
    QPalette, QPixmap, QRadialGradient, QTransform)
from PySide6.QtWidgets import (QApplication, QComboBox, QHeaderView, QLabel,
    QLineEdit, QMainWindow, QPlainTextEdit, QPushButton,
    QSizePolicy, QStatusBar, QTableWidget, QTableWidgetItem,
    QTreeWidget, QTreeWidgetItem, QWidget)

class Ui_MainWindow(object):
    def setupUi(self, MainWindow):
        if not MainWindow.objectName():
            MainWindow.setObjectName(u"MainWindow")
        MainWindow.resize(1188, 816)
        self.centralwidget = QWidget(MainWindow)
        self.centralwidget.setObjectName(u"centralwidget")
        self.ButtonStart = QPushButton(self.centralwidget)
        self.ButtonStart.setObjectName(u"ButtonStart")
        self.ButtonStart.setGeometry(QRect(1060, 40, 51, 31))
        self.ButtonStart.setStyleSheet(u"")
        self.ButtonStop = QPushButton(self.centralwidget)
        self.ButtonStop.setObjectName(u"ButtonStop")
        self.ButtonStop.setGeometry(QRect(1120, 40, 51, 31))
        self.ButtonStop.setStyleSheet(u"")
        self.PacketTable = QTableWidget(self.centralwidget)
        if (self.PacketTable.columnCount() < 6):
            self.PacketTable.setColumnCount(6)
        __qtablewidgetitem = QTableWidgetItem()
        self.PacketTable.setHorizontalHeaderItem(0, __qtablewidgetitem)
        __qtablewidgetitem1 = QTableWidgetItem()
        self.PacketTable.setHorizontalHeaderItem(1, __qtablewidgetitem1)
        __qtablewidgetitem2 = QTableWidgetItem()
        self.PacketTable.setHorizontalHeaderItem(2, __qtablewidgetitem2)
        __qtablewidgetitem3 = QTableWidgetItem()
        self.PacketTable.setHorizontalHeaderItem(3, __qtablewidgetitem3)
        __qtablewidgetitem4 = QTableWidgetItem()
        self.PacketTable.setHorizontalHeaderItem(4, __qtablewidgetitem4)
        __qtablewidgetitem5 = QTableWidgetItem()
        self.PacketTable.setHorizontalHeaderItem(5, __qtablewidgetitem5)
        self.PacketTable.setObjectName(u"PacketTable")
        self.PacketTable.setGeometry(QRect(10, 80, 1171, 361))
        self.PacketTable.setAutoScroll(True)
        self.PacketTree = QTreeWidget(self.centralwidget)
        __qtreewidgetitem = QTreeWidgetItem()
        __qtreewidgetitem.setText(0, u"1");
        self.PacketTree.setHeaderItem(__qtreewidgetitem)
        self.PacketTree.setObjectName(u"PacketTree")
        self.PacketTree.setGeometry(QRect(10, 450, 581, 331))
        self.PacketTree.header().setVisible(False)
        self.PacketHex = QPlainTextEdit(self.centralwidget)
        self.PacketHex.setObjectName(u"PacketHex")
        self.PacketHex.setGeometry(QRect(600, 450, 581, 331))
        self.label = QLabel(self.centralwidget)
        self.label.setObjectName(u"label")
        self.label.setGeometry(QRect(50, 40, 31, 31))
        self.label.setStyleSheet(u"")
        self.protocol_input = QLineEdit(self.centralwidget)
        self.protocol_input.setObjectName(u"protocol_input")
        self.protocol_input.setGeometry(QRect(80, 40, 181, 31))
        self.label_2 = QLabel(self.centralwidget)
        self.label_2.setObjectName(u"label_2")
        self.label_2.setGeometry(QRect(328, 40, 41, 31))
        self.label_2.setStyleSheet(u"")
        self.host_input = QLineEdit(self.centralwidget)
        self.host_input.setObjectName(u"host_input")
        self.host_input.setGeometry(QRect(370, 40, 181, 31))
        self.label_3 = QLabel(self.centralwidget)
        self.label_3.setObjectName(u"label_3")
        self.label_3.setGeometry(QRect(620, 40, 31, 31))
        self.label_3.setStyleSheet(u"")
        self.port_input = QLineEdit(self.centralwidget)
        self.port_input.setObjectName(u"port_input")
        self.port_input.setGeometry(QRect(650, 40, 181, 31))
        self.logic_input1 = QComboBox(self.centralwidget)
        self.logic_input1.addItem("")
        self.logic_input1.addItem("")
        self.logic_input1.setObjectName(u"logic_input1")
        self.logic_input1.setGeometry(QRect(260, 40, 71, 32))
        self.logic_input2 = QComboBox(self.centralwidget)
        self.logic_input2.addItem("")
        self.logic_input2.addItem("")
        self.logic_input2.setObjectName(u"logic_input2")
        self.logic_input2.setGeometry(QRect(550, 40, 71, 32))
        self.label_4 = QLabel(self.centralwidget)
        self.label_4.setObjectName(u"label_4")
        self.label_4.setGeometry(QRect(1070, 0, 111, 20))
        self.label_4.setStyleSheet(u"")
        self.label_5 = QLabel(self.centralwidget)
        self.label_5.setObjectName(u"label_5")
        self.label_5.setGeometry(QRect(10, 0, 171, 16))
        self.label_5.setStyleSheet(u"")
        self.label_6 = QLabel(self.centralwidget)
        self.label_6.setObjectName(u"label_6")
        self.label_6.setGeometry(QRect(550, 0, 121, 31))
        self.label_6.setStyleSheet(u"font: 24pt \"PingFang SC\";")
        MainWindow.setCentralWidget(self.centralwidget)
        self.statusbar = QStatusBar(MainWindow)
        self.statusbar.setObjectName(u"statusbar")
        MainWindow.setStatusBar(self.statusbar)

        self.retranslateUi(MainWindow)

        QMetaObject.connectSlotsByName(MainWindow)
    # setupUi

    def retranslateUi(self, MainWindow):
        MainWindow.setWindowTitle(QCoreApplication.translate("MainWindow", u"MainWindow", None))
        self.ButtonStart.setText(QCoreApplication.translate("MainWindow", u"\u5f00\u59cb", None))
        self.ButtonStop.setText(QCoreApplication.translate("MainWindow", u"\u505c\u6b62", None))
        ___qtablewidgetitem = self.PacketTable.horizontalHeaderItem(0)
        ___qtablewidgetitem.setText(QCoreApplication.translate("MainWindow", u"Time", None));
        ___qtablewidgetitem1 = self.PacketTable.horizontalHeaderItem(1)
        ___qtablewidgetitem1.setText(QCoreApplication.translate("MainWindow", u"Source", None));
        ___qtablewidgetitem2 = self.PacketTable.horizontalHeaderItem(2)
        ___qtablewidgetitem2.setText(QCoreApplication.translate("MainWindow", u"Destination", None));
        ___qtablewidgetitem3 = self.PacketTable.horizontalHeaderItem(3)
        ___qtablewidgetitem3.setText(QCoreApplication.translate("MainWindow", u"Protocol", None));
        ___qtablewidgetitem4 = self.PacketTable.horizontalHeaderItem(4)
        ___qtablewidgetitem4.setText(QCoreApplication.translate("MainWindow", u"Length", None));
        ___qtablewidgetitem5 = self.PacketTable.horizontalHeaderItem(5)
        ___qtablewidgetitem5.setText(QCoreApplication.translate("MainWindow", u"Info", None));
        self.label.setText(QCoreApplication.translate("MainWindow", u"\u534f\u8bae", None))
        self.label_2.setText(QCoreApplication.translate("MainWindow", u"IP\u5730\u5740", None))
        self.label_3.setText(QCoreApplication.translate("MainWindow", u"\u7aef\u53e3", None))
        self.logic_input1.setItemText(0, QCoreApplication.translate("MainWindow", u"or", None))
        self.logic_input1.setItemText(1, QCoreApplication.translate("MainWindow", u"and", None))

        self.logic_input2.setItemText(0, QCoreApplication.translate("MainWindow", u"or", None))
        self.logic_input2.setItemText(1, QCoreApplication.translate("MainWindow", u"and", None))

        self.label_4.setText(QCoreApplication.translate("MainWindow", u"<html><head/><body><p><span style=\" font-size:14pt;\">[Tag]Meng\u7684\u6293\u5305</span></p></body></html>", None))
        self.label_5.setText(QCoreApplication.translate("MainWindow", u"<html><head/><body><p><span style=\" font-size:14pt;\">[Tag]202428015059013</span></p></body></html>", None))
        self.label_6.setText(QCoreApplication.translate("MainWindow", u"\u7f51\u7edc\u55c5\u63a2\u5668", None))
    # retranslateUi

