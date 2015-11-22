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
        self.h_thread = None
        self.context = None
        self.software_breakpoints = {}
        self.first_breakpoint = True
        self.hardware_breakpoints = {}
        self.guarded_pages = []
        self.memory_breakpoints = {}

        #ここでシステムのデフォルトページサイズを求めて保存
        system_info = SYSTEM_INFO()
        kernel32.GetSyetemInfo(byref(system_info))
        self.page_size = system_info.dwPageSize

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

            #スレッドとコンテキストの情報を取得
            self.h_thread = self.open_thread(debug_event.dwThreadId)
            self.context = self.get_thread_context(h_thread=self.h_thread)
            print "Event Code: %d Thread ID: %d" % (debug_event.dwDebugEventCode, debug_event.dwThreadId)


            #イベントコードが例外を示していればさらに調査する
            if debug_event.dwDebugEventCode == EXCEPTION_DEBUG_EVENT:

                #例外コードを調べる
                exception =  debug_event.u.Exception.ExceptionRecord.ExceptionCode
                self.exception_address = debug_event.u.Exception.ExceptionRecord.ExceptionAddress

                if exception == EXCEPTION_ACCESS_VIOLATION:
                    print "Access Violation Detected."

                #ブレークポイントであれば内部ハンドラを呼び出す
                elif exception == EXCEPTION_BREAKPOINT:
                    continue_status = self.exception_handler_breakpoint()

                elif exception == EXCEPTION_GUARD_PAGE:
                    print "Guard Page Access Detected."

                elif exception == EXCEPTION_SINGLE_STEP:
                    continue_status = self.exception_handler_single_step()



            kernel32.ContinueDebugEvent( debug_event.dwProcessId,
                                        debug_event.dwThreadId,
                                        continue_status )

    def detach(self):
        if kernel32.DebugActiveProcessStop(self.pid):
            print "[*] Finished debugging. Exiting..."
            return True
        else:
            print "There was an error"
            return False

    def open_thread(self, thread_id):
        h_thread = kernel32.OpenThread(THREAD_ALL_ACCESS, None, thread_id)

        if h_thread is not 0:
            return h_thread
        else:
            print "[*] Could not obtain a valid thread handle."
            return False

    def enumerate_threads(self):
        thread_entry = THREADENTRY32()
        thread_list = []

        snapshot = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, self.pid)
        if snapshot is not None:
            #構造体のサイズを設定しておかないと呼び出しが失敗する
            thread_entry.dwSize = sizeof(thread_entry)
            success = kernel32.Thread32First(snapshot,byref(thread_entry))

            while success:
                if thread_entry.th32OwnerProcessID == self.pid:
                    thread_list.append(thread_entry.th32ThreadID)
                success = kernel32.Thread32Next(snapshot, byref(thread_entry))

            kernel32.CloseHandle(snapshot)
            return thread_list
        else:
            return False

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

    def exception_handler_breakpoint():

        print "[*] Inside the breakpoint handler."
        print "Exception Address: 0x%08x" % self.exception_address
        return DBG_CONTINUE

    def read_process_memory(self,address,length):
        data = ""
        read_buf = create_string_buffer(length)
        count = c_ulong(0)

        if not kernel32.ReadProcessMemory(self.h_process,
                                            address,
                                            read_buf,
                                            length,
                                            byref(count)):
            return False

        else:
            data += read_buf.raw
            return data

    def bp_set_sw(self,address):
        print "[*] Setting breakpoint at: 0x%08x" % address
        if not self.software_breakpoints.has_key(address):
            try:
                #オリジナルのバイトを保存
                original_byte = self.read_process_memory(address, 1)

                #INT3のオペコードを書き込む
                self.write_process_memory(address, "\xCC")

                #内部にブレークポイントを登録
                self.software_breakpoints[address] = (original_byte)
            except:
                return False

        return True

    def func_resolve(self,dll,function):

        handle = kernel32.GetModuleHandleA(dll)
        address = kernel32.GetProcAddress(handle, function)
        kernel32.CloseHandle(handle)
        return address

    def bp_set_hw(self, address, length, condition):

        #長さの値が有効かチェック
        if length not in (1,2,4):
            return False
        else:
            length -= 1

        #タイプ(条件)が有効かどうかをチェック
        if condition not in (HW_ACCESS, HW_EXECUTE, HW_WRITE):
            return False

        #空いているレジスタをチェック
        if not self.hardware_breakpoints.has_key(0):
            available = 0
        elif not self.hardware_breakpoints.has_key(1):
            available = 1
        elif not self.hardware_breakpoints.has_key(2):
            available = 2
        elif not self.hardware_breakpoints.has_key(3):
            available = 3
        else:
            return False

        #全スレッドについてデバックレジスタ設定を行う
        for thread_id in self.enumerate_threads():
            context = self.get_thread_context(thread_id=thread_id)

            #DR7レジスタ中の対応するビットを設定してブレークポイントを有効にする
            context.Dr7 |= 1 << (available * 2)

            #空いているレジスタにブレークポイントのアドレスを設定
            if available == 0:
                context.Dr0 = address
            elif available == 1:
                context.Dr1 = address
            elif available == 2:
                context.Dr2 = address
            elif available == 3:
                context.Dr3 == address

            #ブレークポイントのタイプ(条件)を設定
            context.Dr7 |= condition << ((available * 4) + 16)

            #長さを設定
            context.Dr7 |= length << ((available * 4) +18)

            #ブレークポイントを設定したスレッドコンテキストを設定
            h_thread = self.open_thread(thread_id)
            kernel32.SetThreadContext(h_thread,byref(context))

        #利用するレジスタについてハードウェアブレークポイントの辞書を更新
        self.hardware_breakpoints[available] = (address,length,condition)

        return True

    def exception_handler_single_step():
        #Pydbgのコメント:
        #この単一ステップイベントがハードウェアブレークポイントを受けて発生したのかをチェックし到達したブレークポイントを決定する
        #IntelのドキュメントによればDR6の中のBSフラグをチェックできるはず
        #しかしWindowsはそのフラグを適切に伝えてくれていない模様
        if self.context.Dr6 & 0x1 and self.hardware_breakpoints.has_key(0):
            slot = 0
        elif self.context.Dr6 & 0x2 and self.hardware_breakpoints.has_key(1):
            slot = 1
        elif self.context.Dr6 & 0x4 and self.hardware_breakpoints.has_key(2):
            slot = 2
        elif self.context.Dr6 & 0x8 and self.hardware_breakpoints.has_key(3):
            slot = 3
        else:
            #ハードウェアブレークポイントによって生成されたINT1ではなかった
            continue_status = DBG_EXCEPTION_NOT_HANDLED

        #辞書からブレークポイントを除去
        if self.bp_del_hw(slot):
            continue_status = DBG_CONTINUE

        print "[*] Hardware breakpoint removed."
        return continue_status

    def bp_del_hw(self,slot):

        #全アクティブスレッドについてブレークポイントを無効化
        for thread_id in self.enumerate_threads():

            context = self.get_thread_context(thread_id=thread_id)

            #フラグビットをリセットしてブレークポイントを除去
            context.Dr7 &= ~(1 << (slot * 2))

            #アドレスをゼロクリア
            if slot == 0:
                context.Dr0 = 0x00000000
            elif slot == 1:
                context.Dr1 = 0x00000000
            elif slot == 2:
                context.Dr2 = 0x00000000
            elif slot == 3:
                context.Dr3 = 0x00000000

            #条件フラグをクリア
            context.Dr7 &= ~(3 << ((slot * 4) + 16))

            #長さフラグをクリア
            context.Dr7 &= ~(3 << ((slot * 4) + 18))

            #ブレークポイントを除去したコンテキストを設定し直す
            h_thread = self.open_thread(thread_id)
            kernel32.SetThreadContext(h_thread,byref(context))

        del self.hardware_breakpoints[slot]

        return True

    def bp_set_mem(self, address, size):

        mbi = MEMORY_BASIC_INFORMATION()

        #VirtualQueryEx()から返された値がMEMORY_BASIC_INFORMATIONのサイズに満たない場合はFalseを返す
        if kernel32.VirtualQueryEx(self.h_process, address, buref(mbi), sizeof(mbi)) < sizeof(mbi):
            return False

        current_page = mbi.BaseAddress

        #対象となる全ページにパーミッションを設定
        while current_page <= address + size:

            #該当するページをリストに追加
            #これにより、我々の保護ページをOSまたは対象プロセスによって設定されたページから区別できる
            self.guarded_pages.append(current_page)

            old_protection = c_ulong(0)
            if not kernel32.VirtualQueryEx(self.h_process, current_page, size,
                                            mbi.Protect | PAGE_GUARD, byref(old_protection)):
                return False
            #システムのデフォルトページサイズ分だけ範囲を広げる
            current_page += self.page_size

        #対象のメモリブレークポイントをグローバルな辞書に追加
        self.memory_breakpoints[address] = (size, mbi)

        return False
