# coding: UTF-8
'''
Created on 2015/11/13

@author: root
'''

from ctypes import *
from my_debugger_defines import *

kernel32 = windll.kernel32

class debugger():
    def __init__(self):
        self.h_process = None
        self.pid = None
        self.debugger_active = False

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

            #プロセスのハンドルを取得し将来の利用に備えて保存
            self.h_process = self.open_process(process_information.dwProcessId)

        else:
            print "[*] Error: 0x%08x." % kernel32.GetLastError()

    def open_process(self,pid):

        h_process = kernel32.OpenProcess(PROCESS_ALL_ACCESS,False,pid)
        return h_process

    def attach(self,pid):

        self.h_process = self.open_process(pid)

        #プロセスへのアタッチを試みる
        #失敗した場合は呼び出し元に戻る
        if kernel32.DebugActiveProcess(pid):
            self.debugger_active = True
            self.pid = int(pid)
        else:
            print "[*] Unable to attach to the process."

    def run(self):
        #デバッグ対象プロセスからのデバックイベントを待機
        while self.debugger_active == True:
            self.get_debug_event()

    def get_debug_event(self):

        debug_event = DEBUG_EVENT()
        continue_status = DBG_CONTINUE

        if kernel32.WaitForDebugEvent(byref(debug_event),INFINITE):

            #イベントハンドラはまだ用意していない
            #さしあたってはプロセスを再開するにとどめる
            #raw_input("Press a key to continue...")
            #self.debugger_active = False
            kernel32.ContinueDebugEvent(
                debug_event.dwProcessId,
                debug_event.dwThreadId,
                continue_status )

    def detach(self):

        if kernel32.DebugActiveProcessStop(self.pid):
            print "[*] Finished debugging.Exiting..."
            return True
        else:
            print "There was an error."
            return False

    def open_thread(self,thread_id):

        h_thread = kernel32.OpenThread(THREAD_ALLACCESS, None, thread_id)

        if h_thread is not 0:
            return h_thread
        else:
            print "[*] Could not obtain a valid thread handle."
            return False

    def enumerate_threads(self):
        thread_entry = THREADENTRY32()
        thread_list = []
        snapshot = kernel32.CreatToolhelp32Snapshot(
            TH32CS_SNAPTHREAD, self.pid)

        if snapshot is not None:
            #構造体のサイズを設定しておかないと呼び出しが失敗する
            thread_entry.dwSize = sizeof(thread_entry)
            success = kernel32.Thread32First(snapshot,
                byref(thread_entry))

            while sucess:
                if thread_entry.th32OwnerProcessID == self.pid:
                    thread_list.append(thread_entry.th32ThreadID)
                    success = kernel32.Thread32Next(snapshot,
                        byref(thread_entry))

            kernel32.CloseHandle(snapshot)
            return thread_list
        else:
            return False:

    def get_thread_context(self, thread_id=None, h_thread=None):

        context = CONTEXT()
        context.ContextFlags = CONTEXT_FULL | CONTEXT_DEBUG_REGISTERS

        #スレッドのハンドルを取得
        if h_thread is None:
            h_thread = self.open_thread(thread_id)
        if kernel32.GetThreadContext(h_thread, byref(context)):
            kernel32.CloseHandle(h_thread)
            return context
        else:
            return False
