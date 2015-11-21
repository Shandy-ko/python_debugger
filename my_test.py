# coding: UTF-8
'''
Created on 2015/11/13

@author: root
'''
import my_debugger
from my_mydebugger_defines import *

debugger = my_debugger.debugger()

pid = raw_input("Enter the PID of the process to atach to: ")

debugger.attach(int(pid))
#list = debugger.enumerate_threads()
#print list

#リスト中の各スレッドについて各レジスタの値を取得
#for thread in list:
#    thread_context = debugger.get_thread_context(thread)

    #レジスタの内容をいくつか取得
#    print "[*] Dumping registers for thread ID: 0x%08x" % thread
#    print "[**] EIP: 0x%08x" % thread_context.Eip
#    print "[**] ESP: 0x%08x" % thread_context.Esp
#    print "[**] EBP: 0x%08x" % thread_context.Ebp
#    print "[**] EAX: 0x%08x" % thread_context.Eax
#    print "[**] EBX: 0x%08x" % thread_context.Ebx
#    print "[**] ECX: 0x%08x" % thread_context.Ecx
#    print "[**] EDX: 0x%08x" % thread_context.Edx
#    print "[*] END DUMP"



#printf_address = debugger.func_resolve("msvcrt.dll","printf")

#print "[*] Address of  printf: 0x%08x" % printf_address

#debugger.bp_set_sw(printf_address)

printf = debugger.func_resolve("msvcrt.dll", "printf")
print "[*] Address of printf: 0x%08x" % printf

debugger.bp_set_hw(printf,1,HW_EXECUTE)

debugger.run()
#debugger.detach()
