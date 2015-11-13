# coding: UTF-8
'''
Created on 2015/11/13

@author: root
'''

from ctypes import *
from my_debugger_defines_former import *

kernel32 = windll.kernel32

class debugger():
    def __init__(self):
        pass

    def load(self,path_to_exe):

        #dwCreationFlagsによりプロセスをどのように生成するかが決まる
                    #電卓のGUIを見たければ creation_flags = CREATION_NEW_CONSOLE
        creation_flags = DEBUG_PROCESS

                    #構造体をインスタンス化
        startupinfo = STARTUPINFO()
        process_information = PROCESS_INFORMATION()

        #次の2つのオプションにより、起動されたプロセスは別ウィンドウとして表示される
        #STARTUPINFO構造体における設定がデバッグ対象に影響を及ぼす例でもある
        startupinfo.dwFlags = 0x1
        startupinfo.wShowWindow = 0x0

        #STARTUPINFO構造体のサイズを表す変数cbを初期化する
        startupinfo.cb = sizeof(startupinfo)

        if kernel32.CreateProcessA(path_to_exe,
                                   None,
                                   None,
                                   None,
                                   None,
                                   creation_flags,
                                   None,
                                   None,
                                   byref(startupinfo),
                                   byref(process_information)):

            print "[*] We have successfully launched the process!"
            print "[*] PID: %d" % process_information.dwProcessId

        else:
            print "[*] Error: 0x%08x." % kernel32.GetLastError()
