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
from PySide6.QtWidgets import (QApplication, QHeaderView, QMainWindow, QPushButton,
    QSizePolicy, QStatusBar, QTableView, QTableWidget,
    QTableWidgetItem, QTreeWidget, QTreeWidgetItem, QWidget)

class Ui_MainWindow(object):
    def setupUi(self, MainWindow):
        if not MainWindow.objectName():
            MainWindow.setObjectName(u"MainWindow")
        MainWindow.resize(808, 704)
        self.centralwidget = QWidget(MainWindow)
        self.centralwidget.setObjectName(u"centralwidget")
        self.ButtonStart = QPushButton(self.centralwidget)
        self.ButtonStart.setObjectName(u"ButtonStart")
        self.ButtonStart.setGeometry(QRect(670, 10, 51, 31))
        self.ButtonStop = QPushButton(self.centralwidget)
        self.ButtonStop.setObjectName(u"ButtonStop")
        self.ButtonStop.setGeometry(QRect(730, 10, 51, 31))
        self.tableView_3 = QTableView(self.centralwidget)
        self.tableView_3.setObjectName(u"tableView_3")
        self.tableView_3.setGeometry(QRect(400, 380, 401, 281))
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
        self.PacketTable.setGeometry(QRect(10, 50, 791, 321))
        self.PacketTable.setAutoScroll(True)
        self.PacketTree = QTreeWidget(self.centralwidget)
        __qtreewidgetitem = QTreeWidgetItem()
        __qtreewidgetitem.setText(0, u"1");
        self.PacketTree.setHeaderItem(__qtreewidgetitem)
        self.PacketTree.setObjectName(u"PacketTree")
        self.PacketTree.setGeometry(QRect(10, 380, 381, 281))
        self.PacketTree.header().setVisible(False)
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
        ___qtablewidgetitem.setText(QCoreApplication.translate("MainWindow", u"\u65f6\u95f4", None));
        ___qtablewidgetitem1 = self.PacketTable.horizontalHeaderItem(1)
        ___qtablewidgetitem1.setText(QCoreApplication.translate("MainWindow", u"\u6e90\u5730\u5740", None));
        ___qtablewidgetitem2 = self.PacketTable.horizontalHeaderItem(2)
        ___qtablewidgetitem2.setText(QCoreApplication.translate("MainWindow", u"\u76ee\u7684\u5730\u5740", None));
        ___qtablewidgetitem3 = self.PacketTable.horizontalHeaderItem(3)
        ___qtablewidgetitem3.setText(QCoreApplication.translate("MainWindow", u"\u534f\u8bae\u7c7b\u578b", None));
        ___qtablewidgetitem4 = self.PacketTable.horizontalHeaderItem(4)
        ___qtablewidgetitem4.setText(QCoreApplication.translate("MainWindow", u"\u957f\u5ea6", None));
        ___qtablewidgetitem5 = self.PacketTable.horizontalHeaderItem(5)
        ___qtablewidgetitem5.setText(QCoreApplication.translate("MainWindow", u"\u4fe1\u606f", None));
    # retranslateUi

