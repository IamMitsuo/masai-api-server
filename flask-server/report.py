#!/usr/bin/python
# -*- coding: utf8 -*-

from io import BytesIO
from reportlab.lib.pagesizes import letter, A4
from reportlab.platypus import  Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_CENTER, TA_JUSTIFY
from reportlab.pdfgen import canvas
from reportlab.lib.units import inch
from reportlab.lib.formatters import DecimalFormatter
from reportlab.platypus import SimpleDocTemplate,PageBreak, Table, TableStyle, Image
from reportlab.graphics.shapes import Drawing
from reportlab.lib.pagesizes import letter

from reportlab.graphics.charts.barcharts import VerticalBarChart

import datetime
from reportlab.lib import colors
import json
import os

MASAI_LOGO = os.getenv('LOGO_PATH')
TABLE_IMG = os.getenv('TABLE_PATH')

class MyPrint:
    def __init__(self, buffer, pagesize):
        self.buffer = buffer
        if pagesize == 'A4':
            self.pagesize = A4
        elif pagesize == 'Letter':
            self.pagesize = letter
        self.width, self.height = self.pagesize

    @staticmethod
    def _header_footer(canvas, doc):
        # Save the state of our canvas so we can draw on it
        filename = MASAI_LOGO

        canvas.saveState()
        styles = getSampleStyleSheet()

        canvas.drawImage(filename, 20, 700, width=90, height=90, preserveAspectRatio=True)
        canvas.setStrokeColorRGB(0, 0.7, 1)
        canvas.line(140, 780, 140, 710)

        canvas.setFont('Times-Bold',10)  # choose your font type and font size
        canvas.drawString(160, 760, "A Mobile Application for Security Assessment towards IoT Devices")
        canvas.drawString(240, 730, 'Penetration Testing Report')
        canvas.line(475, 780, 475, 710)

        today = datetime.datetime.now()

        todayDate = today.strftime("%d-%m-%Y %H:%M:%S")
        #
        canvas.drawString(500, 745, todayDate)

        canvas.restoreState()

    def firstpage_print(styles,elements):

        Title = ' MASai Ltd.'
        Under = 'Penetration Testing Report'

        elements.append(Spacer(1, 100))
        title = Paragraph(Title, styles['Center'])
        elements.append(title)
        elements.append(Spacer(1, 100))
        under = Paragraph(Under, styles['under'])
        elements.append(under)

        elements.append(PageBreak())

    def Introduction_print(styles,elements):

        Intro_text = '	In this project, we develop a  mobile application for security assessment towards IoT Devices called “MASai” which provides two main functions which are IoT device penetration testing and mobile application penetration testing to analyse vulnerability of both targeted IoT devices and mobile application. After that, users can generate penetration testing reports from the list. Inside the report , it will show executive summary,  the record of penetration testing results and recommendation of each attack type. Our developer utilise OWASP IoT Top 10 Vulnerabilities 2014<font size=8>[1]</font>  and OWASP Mobile Top 10 2016<font size=8>[2]</font> as the guideline for this project. However, not all categories will be covered, so the list below shows the selected vulnerability categories of IoT and mobile  mapping with MASai function.'


        elements.append(Paragraph("Introduction", styles['toppic']))
        elements.append(Spacer(1, 50))
        elements.append(Paragraph(Intro_text, styles['Justify']))
        elements.append(Spacer(1, 20))

        elements.append(Image(TABLE_IMG, 5 * inch, 5 * inch))


        elements.append(PageBreak())


    def executive_summary_print(styles,elements,testingID,testingName):

        today = datetime.datetime.now()

        todayDate = today.strftime("%a, %b / %d / %Y")

        ExecuString = 'Executive Summary'
        Line1 = 'MASai Application  performed a penetration test on the following testing name <b>('+testingName+')</b>.  The target of this penetration test focuses on vulnerabilities on  IoT devices such as WiFi router and smart home devices including mobile applications that control those smart home devices.'
        Line2 = 'This report discusses the results from the assessment.'
        Line3 = 'This report was performed on <b>'+str(todayDate)+'</b> by testing ID : <b>'+str(testingID)+'</b>.'
        Line4 = 'The Explaination of the symbol have been labelled according to the following table: '

        elements.append(Paragraph(ExecuString, styles['toppic']))
        elements.append(Spacer(1, 50))
        elements.append(Paragraph(Line1, styles['Justify']))
        elements.append(Spacer(1, 20))
        elements.append(Paragraph(Line2, styles['Justify']))
        elements.append(Spacer(1, 20))
        elements.append(Paragraph(Line3, styles['Justify']))
        elements.append(Spacer(1, 20))
        elements.append(Paragraph(Line4, styles['Justify']))

        MarkTitle = Paragraph(''' <b>Mark</b>''',styles["centered"])

        DescriptionTitle = Paragraph(''' <b>Description</b>''',styles["centered"])


        data = [[MarkTitle, DescriptionTitle],
                ['✓', 'Your device is safe. '],
                ['x', 'Your device is insecure, and some vulnerabilities are discovered. ']]
        t = Table(data)
        t.setStyle(TableStyle([('TEXTCOLOR', (0, 1), (0, 1), colors.green),
                               ('TEXTCOLOR', (0, 2), (0, 2), colors.red),
                               ('VALIGN', (0, 0), (0, -1), 'TOP'),
                               ('BACKGROUND', (0, 0), (-1, 0), '#b3f0ff'),
                               ('BOX', (0, 0), (-1, -1), 0.25, colors.black),
                               ('INNERGRID', (0, 0), (-1, -1), 0.25, colors.black),
                               ('ALIGN', (0, 0), (1, 0), 'CENTER'),
                               ('ALIGN', (0, 0), (0, -1), 'CENTER')

                               ]))

        elements.append(t)

    def wifi_result_ex(styles,elements,json_array):

        WifiString = '''<b>WiFi Router(s):</b>'''
        elements.append(Spacer(1, 20))
        elements.append(Paragraph(WifiString, styles['Justify']))


        titleWifi = Paragraph(''' <b>SSID</b>''', styles["centered"])
        # titlesecurity = Paragraph(''' <b>Security</b>''', styles["centered"])
        titlesresult = Paragraph(''' <b>Result</b>''', styles["centered"])


        listofwifiname = [[titleWifi,titlesresult]]


        for item in json_array:

            WIFI_NAME = item['jsonOutput']['payload']['crackResult']['essid']
            STATUS = item['jsonOutput']['payload']['crackResult']['status']

            if STATUS =="failed":
                resultYN = Paragraph(''' <font color="green">✓</font> ''', styles["centered"])
            else:
                resultYN = Paragraph(''' <font color="red">x</font> ''', styles["centered"])

            listofwifiname.append([WIFI_NAME, resultYN])

        sumwifi = Table(listofwifiname)
        sumwifi.setStyle(TableStyle([
                               ('VALIGN', (0, 0), (0, -1), 'TOP'),
                               ('BACKGROUND', (0, 0), (-1, 0), '#b3f0ff'),
                               ('BOX', (0, 0), (-1, -1), 0.25, colors.black),
                               ('INNERGRID', (0, 0), (-1, -1), 0.25, colors.black),
                               # ('ALIGN', (0, 0), (1, 0), 'CENTER'),
                               ('ALIGN', (0, 0), (-1, -1), 'CENTER')
                               ]))

        elements.append(sumwifi)

    def iot_result_ex(styles, elements, json_array_iot_device ):

        Iotextitle ='''<b>IoT Device(s):</b>'''
        elements.append(Spacer(1, 10))
        elements.append(Paragraph(Iotextitle, styles['Justify']))

        titleIP = Paragraph(''' <b>IP address</b>''', styles["centered"])
        titleDT = Paragraph(''' <b>Device Type</b>''', styles["centered"])
        titlesresult = Paragraph(''' <b>Result</b>''', styles["centered"])
        listofiotex = [[titleIP, titleDT, titlesresult]]

        for item in json_array_iot_device:

            IP_ADDRESS = item['jsonOutput']['payload']['host']['ipv4']
            if 'deviceType' not in json_array_iot_device :
                DEVICETYPE = " - "
            else:
                DEVICETYPE = item['jsonOutput']['payload']['host']['deviceType']

            for item_service in item['jsonOutput']['payload']['host']['services']:

                if len(item_service['cves']) >= 1:
                    resultYN = Paragraph(''' <font color="red">x</font> ''', styles["centered"])
                    break
                else:
                    resultYN = Paragraph(''' <font color="green">✓</font> ''', styles["centered"])

            listofiotex.append([IP_ADDRESS, DEVICETYPE, resultYN])

        sumIoT = Table(listofiotex)
        sumIoT.setStyle(TableStyle([
            ('VALIGN', (0, 0), (0, -1), 'TOP'),
            ('BACKGROUND', (0, 0), (-1, 0), '#b3f0ff'),
            ('BOX', (0, 0), (-1, -1), 0.25, colors.black),
            ('INNERGRID', (0, 0), (-1, -1), 0.25, colors.black),
            # ('ALIGN', (0, 0), (1, 0), 'CENTER'),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER')
        ]))

        elements.append(sumIoT)


    def bluetooth_attack_ex(styles, elements, json_array):

        Apptitle = '''<b>Bluetooth Attack:</b>'''
        elements.append(Spacer(1, 10))
        elements.append(Paragraph(Apptitle, styles['Justify']))

        BluName = Paragraph(''' <b>Bluetooth Name</b>''', styles["centered"])

        Bluresult = Paragraph(''' <b>Result</b>''', styles["centered"])
        listofbluex = [[BluName, Bluresult]]

        for item in json_array:

            bluTitle = item['jsonOutput']['payload']["bluetoothDevice"]['name']
            blustatus = item['jsonOutput']['payload']['status']
            if blustatus =='success':
                resultYN = Paragraph(''' <font color="red">x</font> ''', styles["centered"])
            else:
                resultYN = Paragraph(''' <font color="green">✓</font> ''', styles["centered"])

            listofbluex.append([bluTitle, resultYN])

        sumBLU = Table(listofbluex)
        sumBLU.setStyle(TableStyle([
            ('VALIGN', (0, 0), (0, -1), 'TOP'),
            ('BACKGROUND', (0, 0), (-1, 0), '#b3f0ff'),
            ('BOX', (0, 0), (-1, -1), 0.25, colors.black),
            ('INNERGRID', (0, 0), (-1, -1), 0.25, colors.black),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER')
        ]))

        elements.append(sumBLU)


    def mobile_app_ex(styles, elements, json_array_mobile_app):

        MobileApptitle ='''<b>Mobile Application(s):</b>'''
        elements.append(Spacer(1, 10))
        elements.append(Paragraph(MobileApptitle, styles['Justify']))

        appName = Paragraph(''' <b>Application Name</b>''', styles["centered"])
        appPerm = Paragraph(''' <b>Permission</b>''', styles["centered"])
        appVul = Paragraph(''' <b>Application VUL</b>''', styles["centered"])
        appresult = Paragraph(''' <b>Result</b>''', styles["centered"])
        listofiotex = [[appName, appPerm,appVul, appresult]]


        for item in json_array_mobile_app:

            IP_ADDRESS =  item['jsonOutput']['payload']["appNormalDetail"]['title']

            for item_check in item['jsonOutput']['payload']["permissions"]:

                resultYNPCheck = True
                resultYNVCheck = True

                if item_check['status'] == 'dangerous':
                    resultYNP = Paragraph(''' <font color="red">x</font> ''', styles["centered"])
                    break
                else:
                    resultYNP = Paragraph(''' <font color="green">✓</font> ''', styles["centered"])


            if len(item['jsonOutput']['payload']['findings']) >= 1:
                resultYNV = Paragraph(''' <font color="red">x</font> ''', styles["centered"])
                resultYNPCheck = False
            else:
                resultYNV = Paragraph(''' <font color="green">✓</font> ''', styles["centered"])


            if resultYNPCheck is False or resultYNVCheck is False:
                 resultYN = Paragraph(''' <font color="red">x</font> ''', styles["centered"])
                 resultYNVCheck = False
            else:
                resultYN = Paragraph(''' <font color="green">✓</font> ''', styles["centered"])

            listofiotex.append([IP_ADDRESS, resultYNP,resultYNV, resultYN])

        sumIoT = Table(listofiotex)
        sumIoT.setStyle(TableStyle([
            ('VALIGN', (0, 0), (0, -1), 'TOP'),
            ('BACKGROUND', (0, 0), (-1, 0), '#b3f0ff'),
            ('BOX', (0, 0), (-1, -1), 0.25, colors.black),
            ('INNERGRID', (0, 0), (-1, -1), 0.25, colors.black),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER')
        ]))

        elements.append(sumIoT)

    def wifi_testing_result(styles, elements, json_array):

        WiFi_testing = 'Wi-Fi Testing:'

        elements.append(Spacer(1, 40))
        title = Paragraph(WiFi_testing, styles['undered'])
        elements.append(title)
        elements.append(Spacer(1, 40))

        for item in json_array:

            WIFI_NAME = item['jsonOutput']['payload']['crackResult']['essid']
            BSSID = item['jsonOutput']['payload']['crackResult']['bssid']

            NUMBERITEM = str(list(json_array).index(item) + 1) + "."
            SSIDTEXT = '<b>SSID :</b>  ' + WIFI_NAME
            MACTEXT = '<b>MAC address :</b>  ' + BSSID

            elements.append(Paragraph(NUMBERITEM, styles['Justify']))
            elements.append(Paragraph(SSIDTEXT, styles['Justify']))
            elements.append(Paragraph(MACTEXT, styles['Justify']))

            STATUS = item['jsonOutput']['payload']['crackResult']['status']
            PASSWORD = " - "
            if 'key' in item['jsonOutput']['payload']['crackResult']:
                PASSWORD = item['jsonOutput']['payload']['crackResult']['key']
            if 'asciiKey' in item['jsonOutput']['payload']['crackResult']:
                PASSWORD = item['jsonOutput']['payload']['crackResult']['asciiKey']

            if STATUS == "success":
                resultYN = ''' <font color="green">Success</font> '''

            else:
                resultYN = ''' <font color="red">Unsuccess</font> '''
                PASSWORD = " - "

            elements.append(Paragraph('<b>Crack Status:</b> ' + resultYN, styles['Justify']))


            if STATUS == "success":
                fontst = '''<font color="red">'''
                endst = '''</font> '''

                PASSWORD = fontst + PASSWORD + endst

            else:

                fontst='''<font size=14 color="green">'''
                endst='''</font> '''

                PASSWORD = fontst+PASSWORD+endst

            elements.append(Paragraph('<b>Password Result:</b> ' + PASSWORD, styles['Justify']))
            elements.append(Spacer(1, 20))

            if STATUS == "success":
                elements.append(Paragraph(WIFI_NAME+' router is insecure', styles['insecure']))
            else:
                elements.append(Paragraph(WIFI_NAME+' router is secure', styles['secure']))

            elements.append(Spacer(1, 20))


        elements.append(Paragraph('<b>Strong password Tips</b><font size=8>[3]</font>: ', styles['Justify']))
        elements.append(Spacer(1, 15))

        H1 = """<b>1. Has 12 Characters, Minimum:</b><br/>"""
        L1 = """    You need to choose a password thats long enough. There's no minimum password length everyone agrees on, but you should generally go for passwords that are a minimum of 12 to 14 characters in length. A longer password would be even better.<br/><br/>"""
        H2 = """<b>2. Includes Numbers, Symbols, Capital Letters, and Lower-Case Letters:</b><br/>"""
        L2 = """    Use a mix of different types of characters to make the password harder to crack.<br/><br/>"""
        H3 = """<b>3. Isn't a Dictionary Word or Combination of Dictionary Words:</b><br/>"""
        L3 = """    Stay away from obvious dictionary words and combinations of dictionary words. Any word on its own is bad. Any combination of a few words, especially if they're obvious, is also bad. For example, "house" is a terrible password. "Red house" is also very bad.<br/><br/>"""
        H4 = """<b>4. Doesn't Rely on Obvious Substitutions:</b><br/>"""
        L4 = """    Don't use common substitutions, either - for example, "H0use" isn't strong just because you've replaced an o with a 0. That's just obvious."""

        elements.append(Paragraph( H1+L1+H2+L2+H3+L3+H4+L4, styles['tipsbox']))
        elements.append(PageBreak())

    def port_attack_result(styles, elements, json_array):

        WiFi_testing = 'Port Attack Testing:'

        elements.append(Spacer(1, 40))
        title = Paragraph(WiFi_testing, styles['undered'])
        elements.append(title)
        elements.append(Spacer(1, 40))

        for item in json_array:
            IPaddress = " - "
            DeviceType = " - "
            OsName = " - "
            osVendor = " - "
            portName = " - "
            portNum = " - "
            if 'ipv4' in item['jsonOutput']['payload']['host']:
                IPaddress = item['jsonOutput']['payload']['host']['ipv4']
            if 'deviceType' in item['jsonOutput']['payload']['host']:
                DeviceType = item['jsonOutput']['payload']['host']['deviceType']
            if 'osName' in item['jsonOutput']['payload']['host']:
                OsName = item['jsonOutput']['payload']['host']['osName']
            if 'osVendor' in item['jsonOutput']['payload']['host']:
                osVendor = item['jsonOutput']['payload']['host']['osVendor']
            if 'name' in item['jsonOutput']['payload']['host']:
                portName = item['jsonOutput']['payload']['service']['name']
            if 'port' in item['jsonOutput']['payload']['host']:
                portNum = item['jsonOutput']['payload']['service']['port']

            PortAttack = "Port "+str(portNum)+" ( "+portName.upper()+" )"

            STATUS = item['jsonOutput']['payload']['attackResult']
            usename = " - "
            password = " - "
            if 'username' in item['jsonOutput']['payload']:
                username = item['jsonOutput']['payload']['username']
            if 'password' in item['jsonOutput']['payload']:
                password = item['jsonOutput']['payload']['password']

            if (DeviceType is None):
                DeviceType =" - "
            if (OsName is None):
                OsName = " - "
            if (osVendor is None):
                osVendor = " - "

            NUMBERITEM = str(list(json_array).index(item) + 1) + "."
            IPTEXT = '<b>IP Address :</b>  ' + str(IPaddress)
            attackPort = '<b>Attack Target:</b>  ' + PortAttack

            TypeTEXT = '<b>Device Type :</b>  ' + str(DeviceType)
            venderName = '<b>Vender Name:</b>  ' + osVendor
            OsName = '<b>OS Name:</b>  ' + OsName

            elements.append(Paragraph(NUMBERITEM, styles['Justify']))
            elements.append(Paragraph(IPTEXT, styles['Justify']))
            elements.append(Paragraph(attackPort, styles['Justify']))
            elements.append(Paragraph(TypeTEXT, styles['Justify']))
            elements.append(Paragraph(venderName, styles['Justify']))
            elements.append(Paragraph(OsName, styles['Justify']))

            if STATUS == "success":
                resultYN = ''' <font color="green">Success</font> '''
                elements.append(Paragraph('<b>Crack Status:</b> ' + resultYN, styles['Justify']))

                fontst = '''<font color="red">'''
                endst = '''</font> '''

                PASSWORD = fontst + password + endst
                USERNAME = fontst + username + endst
                elements.append(Paragraph('<b>Username: </b>'+USERNAME, styles['Justify']))
                elements.append(Paragraph('<b>Password: </b>'+PASSWORD, styles['Justify']))
                elements.append(Spacer(1, 10))
                elements.append(Paragraph(str(IPaddress) + ' is insecure', styles['insecure']))

            else:
                resultYN = ''' <font color="red">Unsuccess</font> '''
                elements.append(Paragraph('<b>Crack Status:</b> ' + resultYN, styles['Justify']))
                elements.append(Spacer(1, 10))
                elements.append(Paragraph(str(IPaddress)+ '  is secure', styles['secure']))

            elements.append(Spacer(1, 10))
            elements.append(
                Paragraph("__________________________________________________________________________________",
                          styles['centered']))
            elements.append(Spacer(1, 30))

        elements.append(Paragraph("<b>Recommended Tips for Securing Your Ports:</b>", styles['Justify']))
        elements.append(Spacer(1, 10))
        IoTRec='''&bull <b> Disable unnecessary ports whenever possible,</b> Users should consider opening only necessary ports because unused services tend to be left with default configurations, which are not always secure, or may be using default passwords. <br/>&bull <b>Keep firmware updated,</b>This method allows users update their port version. Unused services tend to be forgotten, which means that they not get updated. Old versions of software tend to be full of known vulnerabilities.<br/>'''
        elements.append(Paragraph(IoTRec, styles['tipsbox']))

        elements.append(PageBreak())

    def iot_testing_result(styles, elements, json_array_iot_device):

        IoT_testing = 'IoT Device Penetration Testing:'
        T2DeviceInfor = '''<b>Device Result(s):</b>'''
        T2Opening = '''<b>Open Port(s) Detail(s):</b>'''

        elements.append(Spacer(1, 10))
        elements.append(Paragraph(IoT_testing, styles['undered']))
        elements.append(Spacer(1, 30))
        elements.append(Paragraph(T2DeviceInfor, styles['Justify']))
        elements.append(Spacer(1, 10))

        for item in json_array_iot_device:

            NUMLIST = str(list(json_array_iot_device).index(item) + 1)

            STATUS = item['jsonOutput']['payload']['host']['status']
            IP_ADDRESS = item['jsonOutput']['payload']['host']['ipv4']
            if 'deviceType' not in json_array_iot_device :
                DEVICETYPE = " - "
            else:
                DEVICETYPE = item['jsonOutput']['payload']['host']['deviceType']

            OSDEVICE = item['jsonOutput']['payload']['host']['osName']

            if 'osVendor' not in json_array_iot_device :
                OSVENDER = " - "
            else:
                OSVENDER = item['jsonOutput']['payload']['host']['osVendor']

            if DEVICETYPE is None:  DEVICETYPE = " - "
            if OSDEVICE is None:    OSDEVICE = " - "
            if OSVENDER is None:    OSVENDER = " - "

            IP_ADDRESSTEXT = """<b>IP's Device: </b> """ + IP_ADDRESS
            STATUSTEXT = '''<b>Device Status : </b>''' + STATUS
            DEVICETYPETEXT = '''<b>Device Type :  </b>''' + DEVICETYPE
            OSDEVICETEXT = '''<b>OS Name : </b>''' + OSDEVICE
            OSVENDERTEXT = '''<b>OS Vender : </b>''' + OSVENDER
            elements.append(Paragraph("<b>Device No."+NUMLIST+"</b>", styles['Justify']))
            elements.append(Paragraph(IP_ADDRESSTEXT, styles['Justify']))
            elements.append(Paragraph(STATUSTEXT, styles['Justify']))
            elements.append(Paragraph(DEVICETYPETEXT, styles['Justify']))
            elements.append(Paragraph(OSDEVICETEXT, styles['Justify']))
            elements.append(Paragraph(OSVENDERTEXT, styles['Justify']))
            elements.append(Spacer(1, 10))
            elements.append(Paragraph(T2Opening, styles['Justify']))
            elements.append(Spacer(1, 10))

            titleNumber = Paragraph(''' <b>No. </b>''', styles["centered"])
            titlePort = Paragraph(''' <b>Port Name</b>''', styles["centered"])
            titlePortnumber = Paragraph(''' <b>Port Number</b>''', styles["centered"])
            titlePortpotocol = Paragraph(''' <b>Protocol</b>''', styles["centered"])

            listofports = [[titleNumber, titlePort, titlePortnumber,titlePortpotocol]]

            for item_service in item['jsonOutput']['payload']['host']['services']:
                NUMLIST =  str(list(item['jsonOutput']['payload']['host']['services']).index(item_service) + 1)
                PORTNUM = item_service['port']
                PROTOCOL = item_service['protocol']
                PORTNAME = item_service['name']

                listofports.append([NUMLIST,PORTNAME, PORTNUM, PROTOCOL])

            portTable = Table(listofports)
            portTable.setStyle(TableStyle([
                ('VALIGN', (0, 0), (0, -1), 'TOP'),
                ('BACKGROUND', (0, 0), (-1, 0), '#b3f0ff'),
                ('BOX', (0, 0), (-1, -1), 0.25, colors.black),
                ('INNERGRID', (0, 0), (-1, -1), 0.25, colors.black),
                # ('ALIGN', (0, 0), (1, 0), 'CENTER'),
                ('ALIGN', (0, 0), (-1, -1), 'CENTER')
            ]))

            elements.append(portTable)

            #Network service checking Detail(s):
            elements.append(Spacer(1, 10))
            elements.append(Paragraph('''<b>Network service checking Detail(s):</b>''', styles['Justify']))
            elements.append(Spacer(1, 10))
            Insecure_List = []
            Secure_List = []

            array_insecure = item['jsonOutput']['payload']['insecureServices']
            array_secure = item['jsonOutput']['payload']['secureServices']

            for item_service in item['jsonOutput']['payload']['insecureServices']:
                Insecure_List.append(item_service)

            for item_service in item['jsonOutput']['payload']['secureServices']:
                Secure_List.append(item_service)

            if len(array_insecure) !=0:
                answer = '<b>'+str(Insecure_List).translate({ord("\'"): None}).translate({ord("["): None}).translate({ord("]"): None})+'</b>'
                redfont ='''<font color="red">'''
                greenfont='''<font color="green">'''
                font='''</font>'''
                elements.append(Paragraph(redfont+"- We found "+ str(len(Insecure_List))+" unencrypted  network service(s) on your IP"+"( "+answer+" )"+font, styles['Justify']))
                elements.append(Spacer(1, 10))

            if len(array_secure) != 0:
                answer2 = '<b>' + str(Secure_List).translate({ord("\'"): None}).translate({ord("["): None}).translate(
                    {ord("]"): None}) + '</b>'
                elements.append(Paragraph(greenfont+"- We found " + str(
                    len(Secure_List)) + " encrypted  network service(s) on your IP" + "( " + answer2 + " )"+font,
                                          styles['Justify']))


            if len(array_insecure) == 0 and len(array_secure) == 0:
                elements.append(Paragraph('''<font color="red">Network services are not founded.</font>''', styles['Justify']))


            #CPE Common Platform Enumeration (CPE™)'s Port(s) detail(s)

            titleCPE = Paragraph('''<b>Common Platform Enumeration (CPE™)'s Port(s) detail(s):</b>''', styles['Justify'])
            elements.append(Spacer(1, 10))
            elements.append(titleCPE)
            elements.append(Spacer(1, 10))


            titleNameCPE = Paragraph(''' <b>Port Name </b>''', styles["centered"])
            titleCPEdetail = Paragraph(''' <b>Details</b>''', styles["centered"])

            listofCPE = [[titleNameCPE, titleCPEdetail]]

            for item_service in item['jsonOutput']['payload']['host']['services']:

                PORTNAME = item_service['name']
                FullstringCPE=""

                if len(item_service['cpe']) == 0:
                    continue
                else:
                    for item_cpe in item_service['cpe']:
                        #NoCVE =str(list(item_service['cpe']).index(item_cpe) + 1)
                        StringCPE = item_cpe[7:]+"""<br/>"""
                        FullstringCPE = FullstringCPE+StringCPE

                    tempStringCPE = Paragraph(FullstringCPE, styles['Justify'])

                    listofCPE.append([PORTNAME,tempStringCPE])

            CPETable = Table(listofCPE)
            CPETable.setStyle(TableStyle([
                ('VALIGN', (0, 0), (0, -1), 'TOP'),
                ('BACKGROUND', (0, 0), (-1, 0), '#b3f0ff'),
                ('BOX', (0, 0), (-1, -1), 0.25, colors.black),
                ('INNERGRID', (0, 0), (-1, -1), 0.25, colors.black),
                # ('ALIGN', (0, 0), (1, 0), 'CENTER'),
                ('ALIGN', (0, 0), (-1, -1), 'CENTER')
            ]))

            elements.append(CPETable)

            #CVE Common Vulnerabilities and Exposures (CVE®)

            titleCVE = Paragraph('''<b>Common Vulnerabilities and Exposures(CVE®)'s detail(s):</b>''', styles['Justify'])
            elements.append(Spacer(1, 25))
            elements.append(titleCVE)
            elements.append(Spacer(1, 10))

            PortCount = 0
            for item_service in item['jsonOutput']['payload']['host']['services']:
                if len(item_service['cves']) == 0:
                    continue
                else:
                    PortCount=PortCount+1

            CVECountString ='''- Security Vulnerabilities are found <font color="red"><b>'''+str(PortCount)+ " port(s)</b></font> on this device."
            CVEportCount = Paragraph(CVECountString, styles['Justify'])
            elements.append(CVEportCount)
            elements.append(Spacer(1, 20))

            PortCount = 0
            for item_service in item['jsonOutput']['payload']['host']['services']:

                PORTNAME = item_service['name']

                if len(item_service['cves']) == 0:
                    continue
                else:
                    PortCount=PortCount+1
                    elements.append(Paragraph("<b>"+str(PortCount)+". "+PORTNAME.upper()+" Port</b>", styles['Justify']))
                    elements.append(Spacer(1, 10))

                    for item_cve in item_service['cves']:
                        CVEID = item_cve['id']
                        CVEDES = item_cve['description']
                        Severity = item_cve['severity']['severity']

                        if Severity =='low':
                            Severity='''<font color="green">'''+Severity.upper()+'''</font>'''

                        elif Severity == 'moderate' :

                            Severity='''<font color="#cece00">'''+Severity.upper()+'''</font>'''
                        else:
                            Severity='''<font color="red">'''+Severity.upper()+'''</font>'''

                        elements.append(Paragraph("<b>CVE ID: </b>" +CVEID, styles['Justify']))
                        elements.append(Paragraph("<b>Description: </b>" +CVEDES, styles['Justify']))
                        elements.append(Spacer(1, 5))

                        for item_cvss in item_cve['severity']['cvss2']:

                            AccessComplexity = item_cvss['accessComplexity']
                            CVSSSCORE = item_cvss['base']
                            ACESSVECTOR = item_cvss['accessVector']
                            CVSSVECTOR = item_cvss['vector']

                            elements.append(Paragraph("<b>CVSS Score : </b>" +str(CVSSSCORE), styles['Justify']))

                            elements.append(Paragraph("<b>CVSS Severity: </b>" +Severity, styles['Justify']))

                            elements.append(Paragraph("<b>Access Complexity: </b>" +AccessComplexity.upper(), styles['Justify']))

                            elements.append(Paragraph("<b>Access Vector: </b>" +ACESSVECTOR, styles['Justify']))

                            elements.append(Paragraph("<b>Vector: </b>" +CVSSVECTOR, styles['Justify']))
                            elements.append(Spacer(1, 10))

            if PortCount == 0:
                elements.append(Paragraph(IP_ADDRESS + ' is secure', styles['secure']))
            else:
                elements.append(Paragraph(IP_ADDRESS + '  is insecure', styles['insecure']))
            elements.append(Spacer(1, 10))
            elements.append(Paragraph("__________________________________________________________________________________", styles['centered']))
            elements.append(Spacer(1, 20))

        # CVSS SCORE INFORMATION #FFFF00

        titleCVSSSeverity = Paragraph(''' <b> Severity </b>''', styles["centered"])
        titleCVSSBSRange = Paragraph(''' <b>Base Score Range</b>''', styles["centered"])
        Low = Paragraph('''<font color="green">Low</font>''', styles["centered"])
        LowNum = Paragraph('''<font color="green">0.0-3.9</font>''', styles["centered"])
        Moderate = Paragraph('''<font color="#cece00">Moderate</font>''', styles["centered"])
        ModerateNum = Paragraph('''<font color="#cece00">4.0-6.9</font>''', styles["centered"])
        High = Paragraph('''<font color="red">High</font>''', styles["centered"])
        HighNum = Paragraph('''<font color="red">7.0-10.0</font>''', styles["centered"])
        listofCVSSInfor = [[titleCVSSSeverity, titleCVSSBSRange], [Low, LowNum], [Moderate, ModerateNum],
                           [High, HighNum]]

        CVSSinfoable = Table(listofCVSSInfor)
        CVSSinfoable.setStyle(TableStyle([
            ('VALIGN', (0, 0), (0, -1), 'TOP'),
            ('BACKGROUND', (0, 0), (-1, 0), '#b3f0ff'),
            ('BOX', (0, 0), (-1, -1), 0.25, colors.black),
            ('INNERGRID', (0, 0), (-1, -1), 0.25, colors.black),
            # ('ALIGN', (0, 0), (1, 0), 'CENTER'),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER')
        ]))

        elements.append(Spacer(1, 10))
        elements.append(PageBreak())

        elements.append(Paragraph("<b><u>Explaination:</u></b>", styles['Justify']))
        elements.append(Spacer(1, 10))
        elements.append(Paragraph("<b>CVSS - Common Vulnerability Scoring System</b><font size=8>[4]</font>:", styles['Justify']))

        elements.append(Paragraph('''Common Vulnerability Scoring System (CVSS) is a free and open industry standard for assessing the severity of computer system security vulnerabilities. It is under the custodianship of NIST. It attempts to establish a measure of how much concern a vulnerability warrants, compared to other vulnerabilities, so efforts can be prioritized. The scores are based on a series of measurements (called metrics) based on expert assessment. ''', styles['Justify']))

        elements.append(Spacer(1, 10))
        elements.append(Paragraph("The following table show scores range of CVSS from 0 to 10 matching with severity.",
                                  styles['Justify']))
        elements.append(Spacer(1, 10))
        elements.append(CVSSinfoable)
        elements.append(Spacer(1, 10))
        elements.append(Paragraph("<b>CVE - Common Vulnerabilities and Exposures</b><font size=8>[5]</font>:", styles['Justify']))
        elements.append(Paragraph("Common Vulnerabilities and Exposures (CVE) is a dictionary-type list of standardized names for vulnerabilities and other information related to security exposures. CVE aims to standardize the names for all publicly known vulnerabilities and security exposures. The goal of CVE is to make it easier to share data across separate vulnerable databases and security tools.", styles['Justify']))
        elements.append(Spacer(1, 10))
        elements.append(Paragraph("<b>Consumer IoT Security Recommendations based on OWASP</b><font size=8></font>[1]:", styles['Justify']))
        elements.append(Spacer(1, 10))


        IoTRec = '''<b>Focused on (I2) Insufficient Authentication/Authorisation </b><br/> &bull If your system has a local or cloud-based web application, ensure that you change the default password to a strong one and if possible change the default username as well.<br/> &bull If the system has account lockout functionality, ensure that it is enabled.<br/> &bull If the system has the option to require strong passwords, ensure that is enabled.<br/> &bull If the system has the option to require new passwords after 90 days for example, ensure that is enabled.<br/> &bull If your system has a two factor authentication option, ensure that it is enabled.<br/> &bull If your system has the option to set user privileges, consider setting user privileges to the minimal needed for operation.<br/> &bull Consider employing network segmentation technologies such as firewalls to isolate IoT systems from critical IT systems.<br/><br/> <b>Focused on (I3) Insecure Network Services</b><br/> &bull If your system has a firewall option available, enable it and ensure that it can only be accessed from your client systems.<br/> &bull Consider employing network segmentation technologies such as firewalls to isolate IoT systems from critical IT systems.<br/>'''
        elements.append(Paragraph( IoTRec, styles['tipsbox']))

        elements.append(Spacer(1, 10))

        elements.append(Paragraph("<b>Recommended Tips for Securing Your IoT Devices:</b>",styles['Justify']))
        elements.append(Spacer(1, 10))

        recommendTips = '''&bull <b>Put down IoT devices to fire-walled and monitored network,</b> This method allows users to restrict incoming traffic to identify attackers.<br/> &bull <b>Turn off IoT devices that’s not being used, </b>This method seem obvious, but the checklist also recommends the physical blocking and covering of malicious intention on ports, cameras, and microphones on IoT devices.<br/> &bull <b>Keep firmware and software updated,</b>This method allows users update their IoT devices via automatic updates or monthly checks. The users should avoid products that cannot be updated, follow the lifecycle of all devices, and remove them from service when they are no longer updatable or secure.<br/>'''

        elements.append(Paragraph(recommendTips, styles['tipsbox2']))

        elements.append(PageBreak())

    def mobileapp_testing_result(styles, elements, json_array_mobile_app):

        Mobile_testing = 'Mobile Application Penetration Testing:'
        elements.append(Spacer(1, 10))
        elements.append(Paragraph(Mobile_testing, styles['undered']))
        elements.append(Spacer(1, 30))
        elements.append(Paragraph('''<b>Application(s) Information:</b>''', styles['Justify']))
        elements.append(Spacer(1, 10))

        # Permission Count:
        DangerpCount = 0
        SignaturepCount = 0
        NormalpCount = 0
        SpecialpCount = 0
        HighvulCount = 0
        WarningvulCount  = 0
        LowRiskvulCount  = 0
        InfovulCount  = 0

        #CVSS SCORE
        M1Score = 0
        M1Count = 0
        M2Score = 0
        M2Count = 0
        M3Score = 0
        M3Count = 0
        M5Score = 0
        M5Count = 0
        M9Score = 0
        M9Count = 0

        json_array_mobile_app2 = []
        item2 = {}
        for item in json_array_mobile_app:
            for item_mobile in item['jsonOutput']['payload']['permissions']:
                SVLEVEL = item_mobile['status']

                if SVLEVEL == 'dangerous':
                    DangerpCount = DangerpCount+1

                elif SVLEVEL == 'signature':
                    SignaturepCount = SignaturepCount+1

                elif SVLEVEL == 'special':
                    SpecialpCount = SpecialpCount+1
                else:
                    NormalpCount =NormalpCount+1

            for item_mobile in item['jsonOutput']['payload']['findings']:
                if 'owaspId' not in item_mobile:
                    continue
                OWASPID = item_mobile['owaspId']
                Level = item_mobile['level']
                CVSS_score = item_mobile['cvss']

                if Level == 'high':
                    HighvulCount = HighvulCount+1
                elif Level == 'info':
                    InfovulCount =InfovulCount+1
                elif Level == 'warning':
                    WarningvulCount  = WarningvulCount+1
                else:
                    LowRiskvulCount = LowRiskvulCount+1

                if OWASPID == '[M1-Improper Platform Usage]':
                    M1Count = M1Count+1
                    M1Score = M1Score+CVSS_score
                elif OWASPID == '[M2-Insecure Data Storage]':
                    M2Count = M2Count + 1
                    M2Score = M2Score + CVSS_score
                elif OWASPID == '[M3-Insecure Communication]':
                    M3Count = M3Count + 1
                    M3Score = M3Score + CVSS_score
                elif OWASPID == '[M5-Insufficient Cryptography]':
                    M5Count = M5Count + 1
                    M5Score = M5Score + CVSS_score
                elif OWASP == '[M9-Reverse Engineering]':
                    M9Count += 1
                    M9Score += CVSS_score

            if M1Count != 0:
                M1Score = M1Score / M1Count
            if M2Count != 0:
                M2Score = M2Score / M2Count
            if M3Count != 0:
                M3Score = M3Score / M3Count
            if M5Count != 0:
                M5Score = M5Score / M5Count
            if M9Count != 0:
                M9Score = M9Score / M9Count

            item2['item'] = item
            item2['DangerpCount'] = DangerpCount
            item2['SignaturepCount'] = SignaturepCount
            item2['SpecialpCount'] = SpecialpCount
            item2['NormalpCount'] = NormalpCount
            item2['HighvulCount'] = HighvulCount
            item2['WarningvulCount'] = WarningvulCount
            item2['LowRiskvulCount'] = LowRiskvulCount
            item2['InfovulCount'] = InfovulCount
            item2['M1Score'] = M1Score
            item2['M2Score'] = M2Score
            item2['M3Score'] = M3Score
            item2['M5Score'] = M5Score
            item2['M9Score'] = M9Score
            json_array_mobile_app2.append(item2)
            item2 = {}

        for item2 in json_array_mobile_app2:
            item = item2['item']
            PACK_NAME = item['jsonOutput']['payload']["packageName"]
            APP_NAME = item['jsonOutput']['payload']["appNormalDetail"]['title']
            APP_SIZE = item['jsonOutput']['payload']["appNormalDetail"]['size']
            APP_CVSS_SCORE = item['jsonOutput']['payload']["averageCvss"]
            APP_VERSION = item['jsonOutput']['payload']["appNormalDetail"]['current_version']
            LAST_Update = item['jsonOutput']['payload']["appNormalDetail"]['updated']
            URL_Load = item['jsonOutput']['payload']["appNormalDetail"]['url']

            elements.append(Paragraph("<b>Application Name: </b>" + APP_NAME, styles['Justify']))
            elements.append(Paragraph("<b>Version: </b>" + APP_VERSION, styles['Justify']))
            elements.append(Paragraph("<b>Size: </b>" + APP_SIZE, styles['Justify']))
            elements.append(Paragraph("<b>Package: </b>" + PACK_NAME, styles['Justify']))
            elements.append(Paragraph("<b>URL link: </b>" + URL_Load, styles['Justify']))
            elements.append(Paragraph("<b>Last Updated: </b>" + LAST_Update, styles['Justify']))

            elements.append(Spacer(1, 10))
            elements.append(Paragraph('''<b>Mobile Application Scanning Summary:</b>''', styles['Justify']))
            elements.append(Spacer(1, 10))
            elements.append(Paragraph("<b>- <u>List of Android Permissions:</u></b>", styles['Justify']))
            elements.append(Spacer(1, 10))
            sumMobileV = MyPrint.get_android_permission_table(styles, item2['NormalpCount'], item2['DangerpCount'], item2['SignaturepCount'], item2['SpecialpCount'])
            elements.append(sumMobileV)
            elements.append(Spacer(1, 10))
            elements.append(Paragraph("<b>- <u>List of Android Application Vulnerabilities Information</u></b>", styles['Justify']))
            elements.append(Spacer(1, 10))
            sumMobile = MyPrint.get_android_vuln_info_table(styles, item2['HighvulCount'], item2['WarningvulCount'], item2['LowRiskvulCount'], item2['InfovulCount'])
            elements.append(sumMobile)
            elements.append(Spacer(1, 10))
            elements.append(Paragraph('''<b>CVSS Score:</b>''', styles['Justify']))
            elements.append(Spacer(1, 5))
            drawing = MyPrint.get_cvss_graph_drawing(styles, [(item2['M1Score'], item2['M2Score'], item2['M3Score'], item2['M5Score'], item2['M9Score'])])
            elements.append(drawing)
            elements.append(Spacer(1, 10))
            elements.append(Paragraph("<b>Average CVSS Score: </b>" + str(APP_CVSS_SCORE), styles['Justify']))
            elements.append(Spacer(1, 10))
            elements.append(PageBreak())
            elements.append(Paragraph("<b>- <u>List of Android Permissions:</u></b>", styles['Justify']))
            elements.append(Spacer(1, 10))

            for item_mobile in item['jsonOutput']['payload']['permissions']:

                TITLE = item_mobile['title']

                if 'info' not in item_mobile:
                    INFO =""
                else:
                    INFO = "( "+item_mobile['info'].capitalize()+")"

                DESCRIPTION = item_mobile['description']
                SVLEVEL = item_mobile['status']

                if SVLEVEL == 'dangerous':
                    SVLEVEL = '''<font color="red">''' + SVLEVEL.upper() + '''</font>'''

                elif SVLEVEL == 'signature':

                    SVLEVEL = '''<font color="#cece00">''' + SVLEVEL.upper() + '''</font>'''
                else:
                    SVLEVEL = '''<font color="green">''' + SVLEVEL.upper() + '''</font>'''

                NUMBERITEM = str(list(item['jsonOutput']['payload']['permissions']).index(item_mobile) + 1)
                #elements.append(Paragraph(NUMBERITEM+". ", styles['Justify']))
                elements.append(Paragraph(NUMBERITEM+". <b>Permission: </b>" + TITLE+ INFO, styles['Justify']))
                elements.append(Paragraph("<b>Description: </b>" + DESCRIPTION, styles['JustifyMo']))
                elements.append(Paragraph("<b>Permission Level: </b>" + SVLEVEL, styles['JustifyMo']))
                elements.append(Spacer(1, 15))


            elements.append(Spacer(1, 30))
            elements.append(Paragraph("<b>- <u>List of Android Application Vulnerabilities Information</u></b>", styles['Justify']))
            elements.append(Spacer(1, 10))
            for item_mobile in item['jsonOutput']['payload']['findings']:
                if 'owaspId' not in item_mobile:
                    continue
                VARESCRIPTION = item_mobile['title']
                OWASP = item_mobile['owaspId']
                Level = item_mobile['level']
                CVSS =  item_mobile['cvss']
                CWE = item_mobile['cwe']

                if Level == 'high':
                    Level = '''<font color="red">''' + Level.upper() + '''</font>'''

                elif Level == 'info':

                    Level = '''<font color="red">INFORMATION RISK</font>'''
                elif Level == 'warning':

                    Level = '''<font color="#cece00">''' + Level.upper() + '''</font>'''
                else:
                    Level = '''<font color="green">''' + Level.upper() + '''</font>'''

                NUMBERITEM = str(list(item['jsonOutput']['payload']['findings']).index(item_mobile) + 1)
                #elements.append(Paragraph(NUMBERITEM+". ", styles['Justify']))
                elements.append(Paragraph(NUMBERITEM+". "+"<b>Vulnerability Infornation:</b>"+VARESCRIPTION, styles['Justify']))
                elements.append(Paragraph("<b>OWASP: </b>"+OWASP, styles['Justify']))
                elements.append(Paragraph("<b>CVSS Score: </b>"+str(CVSS), styles['Justify']))
                elements.append(Paragraph("<b>CWE: </b>"+CWE, styles['Justify']))
                elements.append(Paragraph("<b>Level: </b>" + Level, styles['Justify']))
                elements.append(Spacer(1, 15))

        elements.append(Spacer(1, 50))
        elements.append(Paragraph("<b><u>Explaination:</u></b>", styles['Justify']))
        elements.append(Spacer(1, 10))
        elements.append(
            Paragraph("<b>Android Permission</b>:", styles['Justify']))
        elements.append(Spacer(1, 10))
        elements.append(Paragraph(
            '''<b>Normal permissions</b> (<font color="green">NORMAL</font>)cover areas where your app needs to access data or resources outside the app's sandbox, but where there's very little risk to the user's privacy or the operation of other apps. For example, permission to set the time zone is a normal permission. If an app declares in its manifest that it needs a normal permission, the system automatically grants the app that permission at install time. The system doesn't prompt the user to grant normal permissions, and users cannot revoke these permissions.''',
            styles['Justify']))
        elements.append(Spacer(1, 10))
        elements.append(Paragraph(
            '''<b>Signature permissions</b> (<font color="#cece00">SIGNATURE</font>) grants these app permissions at install time, but only when the app that attempts to use a permission is signed by the same certificate as the app that defines the permission.''',
            styles['Justify']))
        elements.append(Spacer(1, 10))
        elements.append(Paragraph(
            '''<b>Dangerous permissions</b> (<font color="red">DANGEROUS</font>) cover areas where the app wants data or resources that involve the user's private information, or could potentially affect the user's stored data or the operation of other apps. For example, the ability to read the user's contacts is a dangerous permission. If an app declares that it needs a dangerous permission, the user has to explicitly grant the permission to the app. Until the user approves the permission, your app cannot provide functionality that depends on that permission.''',
            styles['Justify']))
        elements.append(Spacer(1, 10))

        elements.append(
            Paragraph("<b>Android rules</b>:", styles['Justify']))
        elements.append(Spacer(1, 10))
        elements.append(Paragraph('''<font color="green"><b>GOOD</b></font>: Application use some method that can enhanced the security of application (beneficial to application). For example, application can prevent certain attack, or application use safe encryption method.''',styles['Justify']))
        elements.append(Spacer(1, 10))
        elements.append(Paragraph('''<font color="#cece00"><b>WARNING</b></font>: Application use some method that is most likely to have malicious intention (some also found in malwares) or create critical flaw in application. For example, listens to clipboard changes, or other methods that malwares do.''',styles['Justify']))
        elements.append(Spacer(1, 10))
        elements.append(Paragraph('''<font color="red"><b>HIGH</b></font>: Application use some method that is considerably dangerous to the security of user. For example, using outdated or exploited encryption method, or allow any app to read certain file.''',styles['Justify']))
        elements.append(Spacer(1, 10))
        elements.append(Paragraph('''<b><font color="red">INFORMATION RISK</font></b>: Application use some method that might leak user’s sensitive informations. For example, logging sensitive informations or storing sensitive informations without encrypting.''',styles['Justify']))
        elements.append(PageBreak())

    @staticmethod
    def get_cvss_graph_drawing(styles, data):
        drawing = Drawing(600, 200)
        # data = [(M1Score, M2Score, M3Score, M5Score, M9Score)]
        bc = VerticalBarChart()
        bc.x = 50
        bc.y = 50
        bc.height = 125
        bc.width = 300
        bc.data = data
        bc.barLabelFormat = DecimalFormatter(1)
        bc.barLabels.dy = 10
        bc.valueAxis.valueMin = 0
        bc.valueAxis.valueMax = 10
        bc.valueAxis.valueStep = 2
        bc.categoryAxis.labels.boxAnchor = 'ne'
        bc.categoryAxis.labels.dx = 8
        bc.categoryAxis.labels.dy = -2
        bc.categoryAxis.labels.angle = 30
        bc.valueAxis.labels.fontSize = 8
        bc.bars[(0, 0)].fillColor = colors.red
        bc.bars[(0, 1)].fillColor = colors.green
        bc.bars[(0, 2)].fillColor = colors.yellowgreen
        bc.bars[(0, 3)].fillColor = colors.blue
        bc.bars[(0, 4)].fillColor = colors.maroon
        bc.categoryAxis.categoryNames = ['M1', 'M2', 'M3', 'M5', 'M9']
        drawing.add(bc)
        return drawing
    
    @staticmethod
    def get_android_permission_table(styles, NormalpCount, DangerpCount, SignaturepCount, SpecialpCount):
        # data = [NormalpCount, DangerpCount, SignaturepCount, ]
        Normalp = Paragraph(''' <b>NORMAL</b>''', styles["centered"])
        Dangerp =  Paragraph(''' <b>DANGEROUS</b>''', styles["centered"])
        Signaturep = Paragraph(''' <b>SIGNATURE</b>''', styles["centered"])
        Specialp = Paragraph(''' <b>SPECIAL</b>''', styles["centered"])

        listofmobileVsum = [[Dangerp,Signaturep,Specialp,Normalp]]

        NormalpAdd = Paragraph(str(NormalpCount), styles["centered"])
        DangerpAdd = Paragraph(str(DangerpCount), styles["centered"])
        SignaturepAdd = Paragraph(str(SignaturepCount), styles["centered"])
        SpecialpAdd = Paragraph(str(SpecialpCount), styles["centered"])

        listofmobileVsum.append([DangerpAdd,SignaturepAdd,SpecialpAdd,NormalpAdd])

        sumMobileV = Table(listofmobileVsum)

        sumMobileV.setStyle(TableStyle([
            ('VALIGN', (0, 0), (0, -1), 'TOP'),
            ('BACKGROUND', (0, 0),(0, 0), '#EA6866'),
            ('BACKGROUND', (1, 0),(1, 0), '#F6BB6C'),
            ('BACKGROUND', (2, 0), (2, 0), '#5FA3EC'),
            ('BACKGROUND', (3, 0), (3, 0), '#5FC971'),
            ('BOX', (0, 0), (-1, -1), 0.25, colors.black),
            ('INNERGRID', (0, 0), (-1, -1), 0.25, colors.black),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER')
        ]))

        return sumMobileV
    
    @staticmethod
    def get_android_vuln_info_table(styles, HighvulCount, WarningvulCount, LowRiskvulCount, InfovulCount):
        highRisk = Paragraph(''' <b>HIGH RISK</b>''', styles["centered"])
        lowRisk =  Paragraph(''' <b>LOW RISK</b>''', styles["centered"])
        Info = Paragraph(''' <b>INFO</b>''', styles["centered"])
        warning = Paragraph(''' <b>WARNING</b>''', styles["centered"])

        listofmobilesum = [[highRisk, warning,lowRisk,Info]]

        highL = Paragraph(str(HighvulCount), styles["centered"])
        Warningvul = Paragraph(str(WarningvulCount), styles["centered"])
        LowRiskvul = Paragraph(str(LowRiskvulCount), styles["centered"])
        Infovul = Paragraph(str(InfovulCount), styles["centered"])

        listofmobilesum.append([highL, Warningvul,Infovul,LowRiskvul])

        sumMobile = Table(listofmobilesum)

        sumMobile.setStyle(TableStyle([
            ('VALIGN', (0, 0), (0, -1), 'TOP'),
            ('BACKGROUND', (0, 0),(0, 0), '#EA6867'),
            ('BACKGROUND', (1, 0),(1, 0), '#F5BC6D'),
            ('BACKGROUND', (2, 0), (2, 0), '#F1E264'),
            ('BACKGROUND', (3, 0), (3, 0), '#5FC971'),
            ('BOX', (0, 0), (-1, -1), 0.25, colors.black),
            ('INNERGRID', (0, 0), (-1, -1), 0.25, colors.black),
            # ('ALIGN', (0, 0), (1, 0), 'CENTER'),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER')
        ]))
        return sumMobile

    def bluetooth_attack_result(styles, elements, json_array_blu_attack):
        WiFi_testing = 'Bluetooth Attack Testing:'
        elements.append(Spacer(1, 40))
        title = Paragraph(WiFi_testing, styles['undered'])
        elements.append(title)
        elements.append(Spacer(1, 40))

        for item in json_array_blu_attack:


            BluName = item['jsonOutput']['payload']['bluetoothDevice']['name']
            BluMac = item['jsonOutput']['payload']['bluetoothDevice']['mac']

            BluClass = item['jsonOutput']['payload']['bluetoothDevice']['class']

            BluType = item['jsonOutput']['payload']['bluetoothDevice']['type']

            STATUS = item['jsonOutput']['payload']['status']

            if (BluName is None):
                BluName =" - "
            if (BluClass is None):
                BluClass = " - "
            if (BluMac is None):
                BluMac = " - "
            if (BluType is None):
                BluType = " - "


            NUMBERITEM = str(list(json_array_blu_attack).index(item) + 1) + "."
            NameBlu = '<b>Bluetooth Name :</b>  ' + BluName
            MacBlu = '<b>MAC address:</b>  ' + BluMac
            ClassBlu = '<b>Bluetooth Class :</b>  ' + str(BluClass)
            TypeTEXT = '<b>Bluetooth Type :</b>  ' + str(BluType)

            elements.append(Paragraph(NUMBERITEM, styles['Justify']))
            elements.append(Paragraph(NameBlu, styles['Justify']))
            elements.append(Paragraph(MacBlu, styles['Justify']))
            elements.append(Paragraph(ClassBlu, styles['Justify']))
            elements.append(Paragraph(TypeTEXT, styles['Justify']))

            if STATUS == "success":
                resultYN = ''' <font color="green">Success</font> '''
                elements.append(Paragraph('<b>Crack Status:</b> ' + resultYN, styles['Justify']))
                elements.append(Spacer(1, 10))
                elements.append(Paragraph(NameBlu + ' is insecure', styles['insecure']))

            else:
                resultYN = ''' <font color="red">Unsuccess</font> '''
                elements.append(Paragraph('<b>Crack Status:</b> ' + resultYN, styles['Justify']))
                elements.append(Spacer(1, 10))
                elements.append(Paragraph(NameBlu+ ' is secure', styles['secure']))

            elements.append(Spacer(1, 10))

            elements.append(
                    Paragraph("__________________________________________________________________________________",
                              styles['centered']))
            elements.append(Spacer(1, 30))

        elements.append(Paragraph("<b>Recommended Tips for Securing Your Bluetooth Device:</b>", styles['Justify']))
        elements.append(Spacer(1, 10))
        BLURec= """&bull<b> Keep Your Operating System and Its Programs on Your Mobile Current</b><br/> Update your mobile device frequently, selecting the automatic update option if available for your particular phone. Keep any installed software, including operating systems and applications, up-to-date as well.. <br/>"""
        elements.append(Paragraph(BLURec, styles['tipsbox']))

        elements.append(PageBreak())




    def referencePrint(styles, elements):

        elements.append(Paragraph("References", styles['toppic']))
        elements.append(Spacer(1, 50))

        elements.append(Paragraph(
            "[1] Project, O.W.A.S. Top IoT Vulnerabilities. 2014, Retrieved March 23, 2019. Available from: https://www.owasp.org/index.php/Top_IoT_Vulnerabilities.",
            styles['Justify']))
        elements.append(Spacer(1, 20))

        elements.append(Paragraph(
            "[2] Project, O.W.A.S. Mobile Top 10 2016-Top 10. 2016, Retrieved March 23, 2019. Available from: https://www.owasp.org/index.php/Mobile_Top_10_2016-Top_10.",
            styles['Justify']))
        elements.append(Spacer(1, 20))

        elements.append(Paragraph("[3] Lauren Morley. (2018, Sep 4). How to Create (and Remember!) Strong Passwords, Retrieved March 19, 2019. Available from https://blog.techvera.com", styles['Justify']))
        elements.append(Spacer(1, 20))

        elements.append(Paragraph(
            "[4] Peter Mell, Karen Scarfone ,A Complete Guide to the Common Vulnerability Scoring System, National Infrastructure Advisory Council (NIAC),Retrieved 24 March 2019. Availablefrom https://www.first.org/cvss/v2/guide",
            styles['Justify']))
        elements.append(Spacer(1, 20))

        elements.append(Paragraph(
            "[5] Vangie Beal ,Find a Technology Definition ,CVE - Common Vulnerabilities and Exposures , Retrieved March 19, 2019, Available from https://www.webopedia.com/TERM/C/CVE.html",styles['Justify']))
        elements.append(Spacer(1, 20))

        elements.append(PageBreak())

    def print_all(self,data):

        buffer = self.buffer
        doc = SimpleDocTemplate(buffer,
                                rightMargin=72,
                                leftMargin=72,
                                topMargin=95,
                                bottomMargin=72,
                                pagesize=self.pagesize)

        # Our container for 'Flowable' objects
        elements = []

        #JSON IMPORT

        #DATA_STRING = '/Users/bookthiti/Desktop/pdf/report.json'

        # DATA_STRING = '/Users/bookthiti/Desktop/pdf/test.json'
        # data1 = open(DATA_STRING)

        json_read_data = json.loads(data)

        TESTINGID = json_read_data['testingId']
        TESTINGNAME = json_read_data['testingName']

        json_array_wifi_crack_result = json_read_data['routerCracking']
        json_array_iot_device = json_read_data['deviceAssessment']
        json_array_port_attack = json_read_data['portAttack']
        json_array_mobile_app = json_read_data['mobileAppScan']
        json_array_blu_attack = json_read_data['bluetoothAttack']

        styles = getSampleStyleSheet()

        styles.add(ParagraphStyle(name='centered', alignment=TA_CENTER))
        styles.add(ParagraphStyle(name='Justify', alignment=TA_JUSTIFY, leading=16))
        styles.add(ParagraphStyle(name='toppic', alignment=TA_CENTER,fontName="Times-Roman",fontSize = 30))
        styles.add(ParagraphStyle(name='Center', alignment=TA_CENTER,fontName="Times-Roman",fontSize = 60,textColor= "Color(0,0,0)"))
        styles.add(ParagraphStyle(name='under', alignment=TA_CENTER,fontName="Times-Roman",fontSize = 22,textColor= "#87CEFA",underlineGap = '1'
        ,underlineOffset = '50',underlineWidth ="1" ))
        styles.add(ParagraphStyle(name='undered',
                                borderColor = '#000000',
                                borderRadius=None,
                                borderWidth = 1,
                                fontSize=20,
                                borderPadding = (7, 2, 20),
                                alignment=TA_CENTER))

        styles.add(ParagraphStyle(name='secure',
                                  backColor = '#32CD32',
                                borderRadius=None,
                                fontSize=15,
                                borderPadding = (5, 2, 15),
                                alignment=TA_CENTER))

        styles.add(ParagraphStyle(name='insecure',
                                  backColor='#DC143C',
                                  borderRadius=None,
                                  fontSize=15,
                                  borderPadding=(5, 2, 15),
                                  alignment=TA_CENTER))

        styles.add(ParagraphStyle(name='JustifyMo',leftIndent=11, alignment=TA_JUSTIFY, leading=16))

        styles.add(ParagraphStyle(name='tipsbox',
                                  alignment=TA_JUSTIFY,
                                  fontName="Times-Roman",
                                  fontSize = 10,
                                  backColor=  "#b3f0ff",
                                  underlineGap = '1',
                                  borderColor = "#595959",
                                  borderPadding = (10,7,10),
                                  underlineOffset = '50',
                                  underlineWidth ="1" ))

        styles.add(ParagraphStyle(name='tipsbox2',
                                  alignment=TA_JUSTIFY,
                                  fontName="Times-Roman",
                                  fontSize=10,
                                  backColor="#98fb3f",
                                  underlineGap='1',
                                  borderColor="#595959",
                                  borderPadding=(10, 7, 10),
                                  underlineOffset='50',
                                  underlineWidth="1"))

        #Print First Page
        MyPrint.firstpage_print(styles,elements)
        #
        MyPrint.Introduction_print(styles, elements)

        #Executive Summary
        MyPrint.executive_summary_print(styles, elements,TESTINGID,TESTINGNAME)
        MyPrint.wifi_result_ex(styles,elements,json_array_wifi_crack_result)
        MyPrint.iot_result_ex(styles, elements, json_array_iot_device)
        MyPrint.bluetooth_attack_ex(styles, elements, json_array_blu_attack)
        MyPrint.mobile_app_ex(styles, elements, json_array_mobile_app)
        elements.append(PageBreak())

        #Print Testing Result

        MyPrint.wifi_testing_result(styles, elements,json_array_wifi_crack_result)
        MyPrint.iot_testing_result(styles, elements, json_array_iot_device)
        MyPrint.port_attack_result(styles,elements,json_array_port_attack)
        MyPrint.bluetooth_attack_result(styles, elements, json_array_blu_attack)
        MyPrint.mobileapp_testing_result(styles, elements, json_array_mobile_app)

        MyPrint.referencePrint(styles, elements)


        doc.build(elements, onFirstPage=self._header_footer, onLaterPages=self._header_footer,canvasmaker=NumberedCanvas)

    def return_self(self):

        return self
    '''
        Usage with django

    @staff_member_required
    def print_all(request):
        # Create the HttpResponse object with the appropriate PDF headers.
        response = HttpResponse(content_type='application/pdf')
        response['Content-Disposition'] = 'attachment; filename="My Users.pdf"'

        buffer = BytesIO()

        report = MyPrint(buffer, 'Letter')
        pdf = report.print_all()

        response.write(pdf)
        return response
    '''


class NumberedCanvas(canvas.Canvas):

    def __init__(self, *args, **kwargs):
        canvas.Canvas.__init__(self, *args, **kwargs)
        self._saved_page_states = []

    def showPage(self):
        self._saved_page_states.append(dict(self.__dict__))
        self._startPage()

    def save(self):
        """add page info to each page (page x of y)"""
        num_pages = len(self._saved_page_states)
        for state in self._saved_page_states:
            self.__dict__.update(state)
            self.draw_page_number(num_pages)
            canvas.Canvas.showPage(self)
        canvas.Canvas.save(self)

    def draw_page_number(self, page_count):
        # Change the position of this to wherever you want the page number to be
        # self.drawRightString(500, 15 * mm + (0.2 * inch),"Page %d of %d" % (self._pageNumber, page_count))
        self.drawCentredString(300,15,"Page %d of %d" % (self._pageNumber, page_count))

# if __name__ == '__main__':
#     buffer = BytesIO()
#     report = MyPrint(buffer, 'Letter')
#     data ='eiei'
#     pdf = report.print_all(data)
#     buffer.seek(0)
#     with open('/Users/bookthiti/Desktop/pdf/test.pdf', 'wb') as f:
#         f.write(buffer.read())