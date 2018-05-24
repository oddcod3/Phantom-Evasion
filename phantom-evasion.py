#!/usr/bin/env python


     ########################################################################################
     #                                                                                      #
     #    This file is part of Phantom-Evasion.                                             #
     #                                                                                      #
     #    Phantom-Evasion is free software: you can redistribute it and/or modify           #
     #    it under the terms of the GNU General Public License as published by              #
     #    the Free Software Foundation, either version 3 of the License, or                 #
     #    (at your option) any later version.                                               #
     #                                                                                      #
     #    Phantom-Evasion is distributed in the hope that it will be useful,                #
     #    but WITHOUT ANY WARRANTY; without even the implied warranty of                    #
     #    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the                     #
     #    GNU General Public License for more details.                                      #
     #                                                                                      #  
     #    You should have received a copy of the GNU General Public License                 #
     #   along with Phantom-Evasion.  If not, see <http://www.gnu.org/licenses/>.           #
     #                                                                                      #
     ########################################################################################

import sys
import os,platform
import atexit
import random
import subprocess
from time import sleep 
from shutil import rmtree
from random import shuffle
sys.path.insert(0,"Setup")
import Phantom_lib
sys.dont_write_bytecode = True

class bcolors:
    PURPLE = '\033[95m'
    BLUE = '\033[94m'
    GREEN = '\033[92m'
    OCRA = '\033[93m'
    RED = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'


def complete_menu():
    answ=True
    while answ:
        Phantom_lib.clear()
        Phantom_lib.banner()
        Phantom_lib.menu_options()
        py_version=platform.python_version()
        if py_version[0] == "3":
            ans = input("\n[>] Please insert choice\'s number: ")
        else:
            ans = raw_input("\n[>] Please insert choice\'s number: ")
        if ans=="1":
            Phantom_lib.clear()
            print("---------------------------------------------------------------------------")
            print(bcolors.OCRA + "[+] WINDOWS MODULES:" + bcolors.ENDC)
            print("---------------------------------------------------------------------------")
            sleep(0.10)
            print("\n[1]  Windows Shellcode Injection VirtualAlloc                         (C)")
            sleep(0.10)
            print("\n[2]  Windows Shellcode Injection VirtualAlloc NoDirectCall LL/GPA     (C)")
            sleep(0.10)
            print("\n[3]  Windows Shellcode Injection VirtualAlloc NoDirectCall GPA/GMH    (C)")
            sleep(0.10)
            print("\n[4]  Windows Shellcode Injection Multipath HeapAlloc                  (C)")
            sleep(0.10)
            print("\n[5]  Windows Shellcode Injection Heapalloc NoDirectCall LL/GPA        (C)")
            sleep(0.10)
            print("\n[6]  Windows Shellcode Injection Heapalloc NoDirectCall GPA/GMH       (C)")
            sleep(0.10)
            print("\n[7]  Windows Pure C meterpreter/reverse_tcp Stager                    (C)")
            sleep(0.10)
            print("\n[8]  Windows Pure C meterpreter/reverse_http Stager                   (C)")
            sleep(0.10)
            print("\n[9]  Windows Powershell Oneliner Dropper                     (Powershell)")
            sleep(0.10)
            print("\n[10] Windows Powershell Script Dropper                       (Powershell)")
            sleep(0.10)
            print("\n[11] Windows WinePyinstaller Python Meterpreter                  (Python)")
            sleep(0.10)
            print("\n[12] Windows WinePyinstaller Oneline payload dropper             (Python)")
            sleep(0.10)
            print("\n[0] Back")
            sleep(0.10)
            if py_version[0] == "3":
                ans=input("\n[>] Please insert choice\'s number: ")
            else:
                ans = raw_input("\n[>] Please insert choice\'s number: ") 
            if ans=="1":
                module_type = "Polymorphic_MVA_mathinject_windows.py"
                Phantom_lib.clear()
                Phantom_lib.description_printer(module_type)
                print("\n\n")
                Phantom_lib.shellcode_completer(module_type)

            elif ans=="2":
                module_type = "Polymorphic_MVA_NDC_LLGPA_mathinject_windows.py" 
                Phantom_lib.clear()
                Phantom_lib.description_printer(module_type)       
                print("\n\n")
                Phantom_lib.shellcode_completer(module_type)

            elif ans=="3":
                module_type = "Polymorphic_MVA_NDC_GPAGMH_mathinject_windows.py"
                Phantom_lib.clear()
                Phantom_lib.description_printer(module_type)        
                print("\n\n")
                Phantom_lib.shellcode_completer(module_type)

            elif ans=="4":
                module_type = "Polymorphic_MHA_mathinject_windows.py"
                Phantom_lib.clear()
                Phantom_lib.description_printer(module_type)        
                print("\n\n")
                Phantom_lib.shellcode_completer(module_type)

            elif ans=="5":
                module_type = "Polymorphic_MHA_NDC_LLGPA_mathinject_windows.py"
                Phantom_lib.clear()
                Phantom_lib.description_printer(module_type)        
                print("\n\n")
                Phantom_lib.shellcode_completer(module_type)


            elif ans=="6":
                module_type = "Polymorphic_MHA_NDC_GPAGMH_mathinject_windows.py"
                Phantom_lib.clear()
                Phantom_lib.description_printer(module_type)        
                print("\n\n")
                Phantom_lib.shellcode_completer(module_type)

            elif ans=="7":
                module_type = "Polymorphic_C_x86ReverseTcpMeterpreter_windows.py"
                Phantom_lib.clear()
                Phantom_lib.description_printer(module_type)        
                print("\n\n")
                Phantom_lib.Polymorphic_C_x86Meterpreter_launcher(module_type)

            elif ans=="8":
                module_type = "Polymorphic_C_x86ReverseHttpMeterpreter_windows.py"
                Phantom_lib.clear()
                Phantom_lib.description_printer(module_type)        
                print("\n\n")
                Phantom_lib.Polymorphic_C_x86Meterpreter_launcher(module_type)

            elif ans=="9":
                module_type = "Polymorphic_PowershellOnelineDropper_windows.py"
                Phantom_lib.clear()
                Phantom_lib.description_printer(module_type)        
                print("\n\n")
                Phantom_lib.powershell_completer(module_type)


            elif ans=="10":
                module_type = "Polymorphic_PowershellScriptDropper_windows.py"
                Phantom_lib.clear()
                Phantom_lib.description_printer(module_type)        
                print("\n\n")
                Phantom_lib.powershell_completer(module_type)


            elif ans =="11":

                if Phantom_lib.wine_fastcheck() == True:

                    module_type = "Pytherpreter_Polymorphic"
                    Phantom_lib.clear()
                    Phantom_lib.description_printer(module_type) 
                    Phantom_lib.pytherpreter_completer(module_type,"True")

                else:

                    print(bcolors.RED + "\n[-] Wine Environment not ready\n" + bcolors.ENDC)
                    Phantom_lib.Enter2Continue()

            elif ans =="12":

                if Phantom_lib.wine_fastcheck() == True:

                    module_type = "Pytherpreter_Polymorphic_Powershelloneline"
                    Phantom_lib.clear()
                    Phantom_lib.description_printer(module_type) 
                    Phantom_lib.python_sys_completer("True")

                else:

                    print(bcolors.RED + "\n[-] Wine Environment not ready\n" + bcolors.ENDC)
                    Phantom_lib.Enter2Continue()

            elif ans=="0":
                print("\n")

        elif ans=="2":
            Phantom_lib.clear()
            print("------------------------------------------------------------------------")
            print(bcolors.OCRA + "[+] LINUX MODULES:" + bcolors.ENDC)
            print("------------------------------------------------------------------------")
            sleep(0.10)
            print("\n[1] Linux Shellcode Injection HeapAlloc                            (C)")
            sleep(0.10)
            print("\n[2] Linux Bash Oneliner Dropper                                    (C)")
            sleep(0.10)
            print("\n[0] Back")
            sleep(0.10)
            if py_version[0] == "3":
                ans=input("\n[>] Please insert choice\'s number: ")
            else:
                ans = raw_input("\n[>] Please insert choice\'s number: ") 

            if ans=="1":
                module_type = "Polymorphic_MHA_mathinject_linux.py"
                Phantom_lib.clear()
                Phantom_lib.description_printer(module_type)
                print("\n\n")
                Phantom_lib.shellcode_completer(module_type)


            if ans=="2":
                module_type = "Polymorphic_BashOnelinerDropper_mathinject_linux.py"
                Phantom_lib.clear()
                Phantom_lib.description_printer(module_type)
                print("\n\n")
                Phantom_lib.BashOnelinerDropper()


            elif ans=="0":
                print("\n")


        elif ans=="3":
            Phantom_lib.clear()
            print("------------------------------------------------------------------------")
            print(bcolors.OCRA + "[+] OSX MODULES:" + bcolors.ENDC)
            print("------------------------------------------------------------------------")
            sleep(0.10)
            print("\n[1] OSX 32 bit cascade encoding                            (Macho/Dmg)")
            sleep(0.10)
            print("\n[0] Back")
            sleep(0.10)
            if py_version[0] == "3":
                ans=input("\n[>] Please insert choice\'s number: ")
            else:
                ans = raw_input("\n[>] Please insert choice\'s number: ") 
            if ans =="1":
                module_type = "Osx_Cascade_Encoding"
                Phantom_lib.clear()
                Phantom_lib.description_printer(module_type)
                Phantom_lib.clear() 
                Phantom_lib.osx_cascade_encoding()
            elif ans=="0":
                print("\n\n")

        elif ans=="4":
            Phantom_lib.clear()
            print("-------------------------------------------------------------------------")
            print(bcolors.OCRA + "[+] ANDROID MODULES:" + bcolors.ENDC)
            print("-------------------------------------------------------------------------")
            sleep(0.10)
            print("\n[1] Android Msfvenom Baksmali Obfuscator                          (Apk)")
            sleep(0.10)
            print("\n[0] Back")
            sleep(0.10)
            if py_version[0] == "3":
                ans=input("\n[>] Please insert choice\'s number: ")
            else:
                ans = raw_input("\n[>] Please insert choice\'s number: ") 
            if ans =="1":
                module_type = "Smali_Droidmare"
                Phantom_lib.clear()
                Phantom_lib.description_printer(module_type)
                Phantom_lib.clear() 
                Phantom_lib.droidmare_launcher()

            elif ans=="0":
                print("\n\n")

        elif ans=="5":
            Phantom_lib.clear()
            print("-------------------------------------------------------------------------")
            print(bcolors.OCRA + "[+] UNIVERSAL MODULES:" + bcolors.ENDC)
            print("-------------------------------------------------------------------------")
            sleep(0.10)
            print("\n[1] Universal Meterpreter increments-trick                     (Python)")
            sleep(0.10)
            print("\n[2] Universal Polymorphic Meterpreter                          (Python)")
            sleep(0.10)
            print("\n[3] Universal Polymorphic Oneliner dropper                     (Python)")
            sleep(0.10)
            print("\n[0] Back")
            sleep(0.10)
            if py_version[0] == "3":
                ans=input("\n[>] Please insert choice\'s number: ")
            else:
                ans = raw_input("\n[>] Please insert choice\'s number: ") 
            if ans =="1":
                module_type = "Pytherpreter"
                Phantom_lib.clear()
                Phantom_lib.description_printer(module_type) 
                Phantom_lib.pytherpreter_completer(module_type,False)

            elif ans =="2":
                module_type = "Pytherpreter_Polymorphic"
                Phantom_lib.clear()
                Phantom_lib.description_printer(module_type) 
                Phantom_lib.pytherpreter_completer(module_type,False)

            elif ans =="3":
                module_type = "Pytherpreter_Polymorphic_Powershelloneline"
                Phantom_lib.clear()
                Phantom_lib.description_printer(module_type) 
                Phantom_lib.python_sys_completer("False")

            elif ans=="0":
                print("\n\n")

        elif ans=="6":
            Phantom_lib.clear()
            print("-------------------------------------------------------------------------")
            print(bcolors.OCRA + "[+] POST-EXPLOITATION MODULES:" + bcolors.ENDC)
            print("-------------------------------------------------------------------------")
            sleep(0.10)
            print("\n[1] Windows Persistence RegCreateKeyExW Add Registry Key            (C)")
            sleep(0.10)
            print("\n[2] Windows Persistence REG Add Registry Key                      (CMD)")
            sleep(0.10)  
            print("\n[3] Windows Persistence Keep Process Alive                          (C)")
            sleep(0.10)
            print("\n[4] Windows Persistence Schtasks cmdline                          (CMD)")
            sleep(0.10)
            print("\n[5] Windows Set Files Attribute Hidden                          (C/CMD)")
            sleep(0.10)
            print("\n[0] Back")
            sleep(0.10)    
        
            if py_version[0] == "3":
                ans=input("\n[>] Please insert choice\'s number: ")
            else:
                ans = raw_input("\n[>] Please insert choice\'s number: ") 

            if ans == "1":
                module_type = "Windows_C_Persistence_Startup.py"
                Phantom_lib.clear()
                Phantom_lib.description_printer(module_type) 
                Phantom_lib.Windows_C_PersistenceAgent(module_type)

            if ans == "2":
                module_type = "Windows_CMD_Persistence_REG"
                Phantom_lib.clear()
                Phantom_lib.description_printer(module_type) 
                Phantom_lib.Windows_CMD_PersistenceAgent()


            elif ans == "3":
                module_type = "Windows_C_Persistence_TimeBased.py"
                Phantom_lib.clear()
                Phantom_lib.description_printer(module_type) 
                Phantom_lib.Windows_C_PersistenceAgent(module_type)

            elif ans == "4":
                module_type = "Windows_CMD_Persistence_Schtasks.py"
                Phantom_lib.clear()
                Phantom_lib.description_printer(module_type) 
                Phantom_lib.Windows_Schtasks_Persistence()

            elif ans == "5":
                module_type = "Windows_C_SetFilesAttributeHidden.py"
                Phantom_lib.clear()
                Phantom_lib.description_printer(module_type) 
                Phantom_lib.SelectHideMode()




            elif ans=="0":
                print("\n\n")


        elif ans=="7":

            print("\n[>] Update check\n")
            sleep(0.2)
            if platform.system() == "Windows":
 
                subprocess.call(['git','status','-uno'],shell=True)

            else: 

                subprocess.call(['git','status','-uno'])
            sleep(2)
            print("[>] Update check completed!\n")
            sleep(1)

        elif ans=="0":
            Phantom_lib.clear()
            print(bcolors.RED + "\n[<<PHANTOM--EXIT>>]\n\n" + bcolors.ENDC)
            sleep(0.2)
            Phantom_lib.exit_banner()
            sleep(0.2)
            quit()

        elif ans !="":
            print("\n[-] Option Not Valid \n") 
            sleep(1.5)


if __name__ == "__main__":

    Phantom_lib.python_banner()
    Phantom_lib.dependencies_checker()
    Phantom_lib.advisor()
    try:
        with open("Setup/Config.txt", "r") as donate_config:
            for line in donate_config:
                if "Mining=True" in line:
                    if platform.system() == "Linux":
                        Phantom_lib.xmr_miner()

        complete_menu()

    except (KeyboardInterrupt, SystemExit):
        subprocess.call(['tmux','send-keys','-t','phantom-miner','\"\x03\"','C-m'], stdout=open(os.devnull,'wb'), stderr=open(os.devnull,'wb'))



