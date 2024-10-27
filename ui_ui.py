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
    QTableWidgetItem, QWidget)

class Ui_MainWindow(object):
    def setupUi(self, MainWindow):
        if not MainWindow.objectName():
            MainWindow.setObjectName(u"MainWindow")
        MainWindow.resize(669, 560)
        self.centralwidget = QWidget(MainWindow)
        self.centralwidget.setObjectName(u"centralwidget")
        self.ButtonStart = QPushButton(self.centralwidget)
        self.ButtonStart.setObjectName(u"ButtonStart")
        self.ButtonStart.setGeometry(QRect(520, 10, 51, 31))
        self.ButtonStop = QPushButton(self.centralwidget)
        self.ButtonStop.setObjectName(u"ButtonStop")
        self.ButtonStop.setGeometry(QRect(590, 10, 51, 31))
        self.tableView_2 = QTableView(self.centralwidget)
        self.tableView_2.setObjectName(u"tableView_2")
        self.tableView_2.setGeometry(QRect(10, 330, 321, 201))
        self.tableView_3 = QTableView(self.centralwidget)
        self.tableView_3.setObjectName(u"tableView_3")
        self.tableView_3.setGeometry(QRect(340, 330, 301, 201))
        self.pkgtable = QTableWidget(self.centralwidget)
        if (self.pkgtable.columnCount() < 3):
            self.pkgtable.setColumnCount(3)
        __qtablewidgetitem = QTableWidgetItem()
        self.pkgtable.setHorizontalHeaderItem(0, __qtablewidgetitem)
        __qtablewidgetitem1 = QTableWidgetItem()
        self.pkgtable.setHorizontalHeaderItem(1, __qtablewidgetitem1)
        __qtablewidgetitem2 = QTableWidgetItem()
        self.pkgtable.setHorizontalHeaderItem(2, __qtablewidgetitem2)
        self.pkgtable.setObjectName(u"pkgtable")
        self.pkgtable.setGeometry(QRect(10, 50, 631, 271))
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
        ___qtablewidgetitem = self.pkgtable.horizontalHeaderItem(0)
        ___qtablewidgetitem.setText(QCoreApplication.translate("MainWindow", u"\u539f\u5730\u5740", None));
        ___qtablewidgetitem1 = self.pkgtable.horizontalHeaderItem(1)
        ___qtablewidgetitem1.setText(QCoreApplication.translate("MainWindow", u"\u76ee\u7684\u5730\u5740", None));
        ___qtablewidgetitem2 = self.pkgtable.horizontalHeaderItem(2)
        ___qtablewidgetitem2.setText(QCoreApplication.translate("MainWindow", u"\u534f\u8bae", None));
    # retranslateUi

