# coding: UTF-8
'''
Created on 2015/11/13

@author: root
'''
import my_debugger

debugger = my_debugger.debugger()

pid = raw_input("Enter the PID of the process to atach to: ")

debugger.attach(int(pid))
debugger.run()
debugger.detach()
