# -*- coding: utf-8 -*-
# Thursday, 4 April 2019
# Author:nianhua
# Blog:http://nianhua.in

# Python Import
import time
import json
import re

# Burp Import
from burp import IBurpExtender
from burp import IHttpListener
from burp import IMessageEditorTab
from burp import IMessageEditorTabFactory

# Java Import
from java.io import PrintWriter


class BurpExtender(IBurpExtender, IHttpListener, IMessageEditorTabFactory):

    #
    # implement IBurpExtender
    #

    def registerExtenderCallbacks(self, callbacks):
        # keep a reference to our callbacks object
        self._callbacks = callbacks

        # obtain an extension helpers object
        self._helpers = callbacks.getHelpers()

        # set our extension name
        callbacks.setExtensionName("Intelligent analysis")

        # obtain our output streams
        self._stdout = PrintWriter(callbacks.getStdout(), True)

        # register ourselves as an HTTP listener
        callbacks.registerHttpListener(self)

        # register ourselves as an Tab factory
        callbacks.registerMessageEditorTabFactory(self)

        return

    def createNewInstance(self, controller, editable):

        # implement createNewInstance
        return JSONDecoderTab(self, controller, editable)

    def stringIsGps(self, Xhacker, string):

        if Xhacker:

            return False

        if ("\"longitude\"" in string and "\"latitude\"" in string) or ("\"lat\"" in string and "\"lon\"" in string):

            locations = re.findall(r'\d{2,3}\.\d{3,6}', string)

            for location in locations:

                if 3 < float(location) < 135:

                    print time.strftime("%Y-%m-%d %H:%M:%S Find:", time.localtime())

                    print location

                    return True

        return False

    def stringIsPhone(self, string):

        iphones = re.findall(
            r'[%"\'< ](?:13[012]\d{8}[%"\'< ]|15[56]\d{8}[%"\'< ]|18[56]\d{8}[%"\'< ]|176\d{8}[%"\'< ]|145\d{8}[%"\'< ]|13[456789]\d{8}[%"\'< ]|147\d{8}[%"\'< ]|178\d{8}[%"\'< ]|15[012789]\d{8}[%"\'< ]|18[23478]\d{8}[%"\'< ]|133\d{8}[%"\'< ]|153\d{8}[%"\'< ]|189\d{8}[%"\'< ])', string)

        if iphones != []:

            iphones = set(iphones)

            print time.strftime("%Y-%m-%d %H:%M:%S Find:", time.localtime())

            for iphone in iphones:

                print str(iphone[:-1]),

            print ""

            return True

        return False

    def stringIsIdCard(self, string):

        coefficient = [7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2]

        parityBit = '10X98765432'

        idcards = re.findall(
            r'([1-8][1-7]\d{4}[1|2]\d{3}[0|1]\d{1}[1-3]\d{4}[0-9|X|x])', string)

        if idcards != []:

            for idcard in idcards:

                sumnumber = 0

                for i in range(17):

                    sumnumber += int(idcard[i]) * coefficient[i]

                if parityBit[sumnumber % 11] == idcard[-1]:

                    print time.strftime("%Y-%m-%d %H:%M:%S Find:", time.localtime())

                    print idcard

                    return True

        return False

    #
    # implement IHttpListener
    #

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):

        # only process response
        if messageIsRequest:

            return

        content = messageInfo.getResponse()

        r = self._helpers.analyzeResponse(content)

        headers = content[:r.getBodyOffset()].tostring()

        msg = content[r.getBodyOffset():].tostring()

        Xhacker = True if "X-Hacker" in headers else False

        if self.stringIsGps(Xhacker, msg):

            messageInfo.setHighlight('green')

        if self.stringIsPhone(msg):

            messageInfo.setHighlight('blue')

        if self.stringIsIdCard(msg):

            messageInfo.setHighlight('red')


class JSONDecoderTab(IMessageEditorTab):

    def __init__(self, extender, controller, editable):

        self._extender = extender

        self._helpers = extender._helpers

        self._editable = editable

        self._txtInput = extender._callbacks.createTextEditor()

        self._txtInput.setEditable(editable)

        self._jsonMark = ['{"', '["', '[{']

        return

    def getTabCaption(self):

        return "JSON Decoder"

    def getUiComponent(self):

        return self._txtInput.getComponent()

    def isEnabled(self, content, isRequest):  # 始终显示该窗体

        return True

    def setMessage(self, content, isRequest):

        if content is None:

            self._txtInput.setText(None)

            self._txtInput.setEditable(False)

        else:

            if isRequest:

                r = self._helpers.analyzeRequest(content)

            else:

                r = self._helpers.analyzeResponse(content)

            msg = content[r.getBodyOffset():].tostring()

            try:

                boundary = min(
                    msg.index('{') if '{' in msg else len(msg),
                    msg.index('[') if '[' in msg else len(msg)
                )

            except ValueError:

                return

            garbage = msg[:boundary]

            clean = msg[boundary:]

            try:

                pretty_msg = garbage.strip() + '\n' + json.dumps(json.loads(clean), indent=4)

            except:

                pretty_msg = garbage + clean

            self._txtInput.setText(pretty_msg)

            self._txtInput.setEditable(self._editable)

        self._currentMessage = content

        return

    def getMessage(self):

        if self._txtInput.isTextModified():  # 判断用户是否修改了数据

            try:

                pre_data = self._txtInput.getText().tostring()  # 检索当前正在显示的文本

                boundary = min(pre_data.index('{') if '{' in pre_data else len(pre_data),
                               pre_data.index(
                                   '[') if '[' in pre_data else len(pre_data)
                               )

                garbage = pre_data[:boundary]    # 分开乱七八糟

                clean = pre_data[boundary:]  # 分开clean数据

                data = garbage + json.dumps(json.loads(clean))  # 获取数据

            except:

                data = self._helpers.bytesToString(
                    self._txtInput.getText())   # 原样的数据

            # Reconstruct request/response   #重构数据
            r = self._helpers.analyzeRequest(self._currentMessage)  # 再次获取

            return self._helpers.buildHttpMessage(r.getHeaders(), self._helpers.stringToBytes(data))

        else:

            return self._currentMessage  # 显示当前数据

    def isModified(self):

        return self._txtInput.isTextModified()

    def getSelectedData(self):

        return self._txtInput.getSelectedText()
