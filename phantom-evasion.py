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
import atexit
from time import sleep 
sys.path.insert(0,"Setup")
import Phantom_lib
from Setup_lib import AutoSetup
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


def CompleteMenu():

    answ=True

    while answ:

        Phantom_lib.Clear()
        Phantom_lib.Banner()
        Phantom_lib.MenuOptions()

        ans = ""
        ans = Phantom_lib.InputFunc("\n[>] Please insert option: ")

        if ans=="1":

            Phantom_lib.Clear()            
            print("---------------------------------------------------------------------------")
            print(bcolors.OCRA + "[+] WINDOWS MODULES:" + bcolors.ENDC)
            print("---------------------------------------------------------------------------")
            sleep(0.10)
            print("\n[1]  Windows Shellcode Injection                 (C)")
            sleep(0.10)
            print("\n[2]  Windows Reverse Tcp Stager                  (C)")
            sleep(0.10)
            print("\n[3]  Windows Reverse Http Stager                 (C)")
            sleep(0.10)
            print("\n[4]  Windows Reverse Https Stager                (C)")
            sleep(0.10)
            print("\n[5]  Windows Download Execute Exe NoDiskWrite    (C)")
            sleep(0.10)
            print("\n[6]  Windows Download Execute Dll NoDiskWrite    (C)")
            sleep(0.10)
            print("\n[0]  Back                                                                ")
            sleep(0.10)

            ValidAns=False

            while not ValidAns:

                ans = ""
                ans = Phantom_lib.InputFunc("\n[>] Insert payload number: ")

                if ans=="1":

                    module_type = "ShellcodeInjection_C_windows"
                    ValidAns=True

                elif ans=="2":

                    module_type = "ReverseTcpStager_C_windows"
                    ValidAns=True

                elif ans=="3":

                    module_type = "ReverseHttpStager_C_windows"
                    ValidAns=True

                elif ans=="4":

                    module_type = "ReverseHttpsStager_C_windows"
                    ValidAns=True

                elif ans=="5":

                    module_type = "DownloadExecExe_C_windows"
                    ValidAns=True

                elif ans=="6":

                    module_type = "DownloadExecDll_C_windows"
                    ValidAns=True

                elif ans=="0":

                    break

                else:
                    print("[-] Invalid option")
                    sleep(1.5)

            if ValidAns==True:
                Phantom_lib.Clear()
                Phantom_lib.ModuleDescription(module_type)        
                Phantom_lib.ModuleLauncher(module_type)

        elif ans=="2":

            Phantom_lib.Clear()
            print("------------------------------------------------------------------------")
            print(bcolors.OCRA + "[+] LINUX MODULES:" + bcolors.ENDC)
            print("------------------------------------------------------------------------")
            sleep(0.10)
            print("\n[1] Linux Shellcode Injection    (C)")
            sleep(0.10)
            print("\n[0] Back")
            sleep(0.10)

            ValidAns = False

            while not ValidAns:

                ans = ""
                ans = Phantom_lib.InputFunc("\n[>] Insert payload number: ") 

                if ans=="1":

                    ValidAns = True
                    module_type = "ShellcodeInjection_C_linux"
                    Phantom_lib.Clear()
                    Phantom_lib.ModuleDescription(module_type)
                    Phantom_lib.ModuleLauncher(module_type)

                elif ans=="0":
                    
                    break

                else:
                    print("[-] Invalid option")
                    sleep(1.5)




        elif ans=="3":

            Phantom_lib.Clear()
            print("-------------------------------------------------------------------------")
            print(bcolors.OCRA + "[+] ANDROID MODULES:" + bcolors.ENDC)
            print("-------------------------------------------------------------------------")
            sleep(0.10)
            print("\n[1] Android Msfvenom Obfuscator/Backdoor (APK)")
            sleep(0.10)
            print("\n[0] Back")
            sleep(0.10)

            ValidAns = False

            while not ValidAns:

                ans = ""
                ans = Phantom_lib.InputFunc("\n[>] Please insert option: ")
 
                if ans =="1":

                    ValidAns = True
                    module_type = "MsfvenomObfuscateBackdoor_android"
                    Phantom_lib.Clear()
                    Phantom_lib.ModuleDescription(module_type)
                    Phantom_lib.ModuleLauncher(module_type)

                elif ans=="0":

                    break

                else:
                    print("[-] Invalid option")
                    sleep(1.5)

        elif ans=="4":

            Phantom_lib.Clear()
            print("-------------------------------------------------------------------------")
            print(bcolors.OCRA + "[+] PERSISTENCE MODULES:" + bcolors.ENDC)
            print("-------------------------------------------------------------------------")
            print("\n[1] Windows REG Add Registry Key         (C)")
            sleep(0.10) 
            print("\n[2] Windows REG Add Registry Key       (CMD)")
            sleep(0.10) 
            print("\n[3] Windows Keep Process Alive           (C)")
            sleep(0.10)
            print("\n[4] Windows Schtasks cmdline           (CMD)")
            sleep(0.10)
            print("\n[5] Windows Create Service             (CMD)")
            sleep(0.10)
            print("\n[0] Back")
            sleep(0.10)    


            ValidAns = False

            while not ValidAns:

                ans = ""
                ans = Phantom_lib.InputFunc("\n[>] Insert module number: ") 

                if ans == "1":

                    module_type = "Persistence_C_REG_windows"
                    ValidAns = True

                elif ans == "2":
    
                    module_type = "Persistence_CMD_REG_windows"
                    ValidAns = True

                elif ans == "3":

                    module_type = "Persistence_C_KeepAliveProcess_windows"
                    ValidAns = True

                elif ans == "4":

                    module_type = "Persistence_CMD_Schtasks_windows"
                    ValidAns = True

                elif ans == "5":

                    module_type = "Persistence_CMD_CreateService_windows"
                    ValidAns = True

                elif ans=="0":

                    break

                else:
                    print("[-] Invalid option")
                    sleep(1.5)

            if ValidAns==True:

                Phantom_lib.Clear()
                Phantom_lib.ModuleDescription(module_type) 
                Phantom_lib.ModuleLauncher(module_type)

        elif ans=="5":

            Phantom_lib.Clear()
            print("-------------------------------------------------------------------------")
            print(bcolors.OCRA + "[+] PRIV-ESC MODULES:" + bcolors.ENDC)
            print("-------------------------------------------------------------------------")
            print("\n[1] Windows DuplicateTokenEx             (C)")
            sleep(0.10)  
            print("\n[0] Back")
            sleep(0.10)

            ValidAns = False

            while not ValidAns:

                ans = ""
                ans = Phantom_lib.InputFunc("\n[>] Insert module number: ") 

                if ans == "1":

                    ValidAns = True
                    module_type = "Privesc_C_DuplicateTokenEx_windows"
                    Phantom_lib.Clear()
                    Phantom_lib.ModuleDescription(module_type) 
                    Phantom_lib.ModuleLauncher(module_type)

                elif ans=="0":
                
                    break

                else:
                    print("[-] Invalid option")
                    sleep(1.5)

        elif ans=="6":

            Phantom_lib.Clear()
            print("-------------------------------------------------------------------------")
            print(bcolors.OCRA + "[+] POST-EX MODULES:" + bcolors.ENDC)
            print("-------------------------------------------------------------------------")
            print("\n[1] Windows Unload Sysmon             (CMD)")
            sleep(0.10)
            print("\n[2] Windows Unload Sysmon               (C)")
            sleep(0.10)
            print("\n[3] Windows Attrib hide file          (CMD)")
            sleep(0.10) 
            print("\n[4] Windows SetFileAttribute hide file  (C)")
            sleep(0.10)
            print("\n[5] Windows Dump Lsass                  (C)")
            sleep(0.10)
            print("\n[6] Windows Dump Lsass                (CMD)")
            sleep(0.10)
            print("\n[0] Back")
            sleep(0.10)

            ValidAns = False

            while not ValidAns:

                ans = ""
                ans = Phantom_lib.InputFunc("\n[>] Insert module number: ") 

                if ans == "1":

                    module_type = "Postex_CMD_UnloadSysmonDriver_windows"
                    ValidAns = True

                elif ans == "2":

                    module_type = "Postex_C_UnloadSysmonDriver_windows"
                    ValidAns = True

                elif ans == "3":

                    module_type = "Postex_CMD_AttribHideFile_windows"
                    ValidAns = True

                elif ans == "4":

                    module_type = "Postex_C_SetFileAttributeHidden_windows"
                    ValidAns = True

                elif ans == "5":

                    module_type = "Postex_C_MiniDumpWriteDumpLsass_windows"
                    ValidAns = True

                elif ans == "6":

                    module_type = "Postex_CMD_DumpLsass_windows"
                    ValidAns = True

                elif ans=="0":

                    break

                else:
                    print("[-] Invalid option")
                    sleep(1.5)

            if ValidAns==True:

                Phantom_lib.Clear()
                Phantom_lib.ModuleDescription(module_type) 
                Phantom_lib.ModuleLauncher(module_type)

        elif ans=="7":

            Phantom_lib.Clear()
            print("\n[>>>] Phantom-Evasion setup...\n")
            AutoSetup()
            sleep(1)

        elif ans=="0":
            Phantom_lib.Clear()
            print(bcolors.RED + "\n[ <<< PHANTOM-EVASION 3.0 >>> ]\n" + bcolors.ENDC)
            sleep(0.2)
            Phantom_lib.ExitBanner()
            sleep(0.2)
            quit()

        else:
            print("\n[-] Option Not Valid \n") 
            sleep(1.5)


if __name__ == "__main__":

    if len(sys.argv) > 1:

        Phantom_lib.CmdlineLauncher(sys.argv)
    else:
        Phantom_lib.Clear()
        Phantom_lib.Advisor()

        try:
            CompleteMenu()

        except (KeyboardInterrupt, SystemExit):

            pass
