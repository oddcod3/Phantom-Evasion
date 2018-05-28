# PHANTOM EVASION

## Version 1.1 released!

Phantom-Evasion is an interactive antivirus evasion tool written in python capable to generate (almost) FUD executable even with the most common 32 bit msfvenom payload (best performances are obtained with 64 bit payloads).
The aim of this tool is to make antivirus evasion an easy task for pentesters through the use of modules focused on polymorphic code and antivirus sandbox detection techniques.
Since version 1.0 Phantom-Evasion also include a post-exploitation section dedicated to persistence and auxiliary modules.


Kali Linux Rolling 2018.1+ is the only OS with automatic setup officially supported

The following OSs support (unofficially) automatic setup :
    
1. Parrot Security


The following OSs are likely able to run Phantom Evasion through manual setup:

1. Arch Linux
2. BlackArch Linux
3. Elementary
4. Linux Mint
5. Ubuntu 15.10+
6. Windows 7/8/10
 

## Getting Started

Simply git clone or download and unzip Phantom-Evasion folder

## Kali Linux:

Automatic setup officially supported, open a terminal and execute phantom-evasion:


```
python phantom-evasion.py 
```

or:

```
chmod +x ./phantom-evasion.py

./phantom-evasion.py
```

## Dependencies (only for manual setup)

1. metasploit
2. mingw-w64
3. gcc
4. apktool
5. strip
6. wine
7. zipalign

require libc6-dev-i386 (linux only)

## WINDOWS PAYLOADS

## Windows Shellcode Injection Modules (C)

Msfvenom windows payloads and custom shellcodes supported

(>) Randomized junkcode and windows antivirus evasion techniques
(>) Multibyte Xor encoders availables (see Multibyte Xor encoders readme section)
(>) Decoy Processes Spawner available (see Decoy Process Spawner section)
(>) Strip executable available (https://en.wikipedia.org/wiki/Strip_(Unix))
(>) Execution time range:35-60 second

1) Windows Shellcode Injection VirtualAlloc:
Inject and Execute shellcode in memory using VirtualAlloc,CreateThread,WaitForSingleObject API.

2) Windows Shellcode Injection VirtualAlloc NoDirectCall LL/GPA:
Inject and Execute shellcode in memory using VirtualAlloc,CreateThread,WaitForSingleObject API.
VirtualAlloc is dinamically loaded (No Direct Call) using LoadLibrary and GetProcAddress API.  

3) Windows Shellcode Injection VirtualAlloc NoDirectCall GPA/GMH:
Inject and Execute shellcode in memory using VirtualAlloc,CreateThread,WaitForSingleObject API.
VirtualAlloc is dinamically loaded (No Direct Call) using GetModuleHandle and GetProcAddress API.  

4) Windows Shellcode Injection HeapAlloc:
Inject and Execute shellcode in memory using VirtualAlloc,CreateThread,WaitForSingleObject API.

5) Windows Shellcode Injection HeapAlloc NoDirectCall LL/GPA:
Inject and Execute shellcode in memory using HeapCreate,HeapAlloc,CreateThread,WaitForSingleObject API.
HeapCreate and HeapAlloc are dinamically loaded (No Direct Call) using LoadLibrary and GetProcAddress API.  

6) Windows Shellcode Injection HeapAlloc NoDirectCall GPA/GMH:
Inject and Execute shellcode in memory using HeapCreate,HeapAlloc,CreateThread,WaitForSingleObject API.
HeapCreate and HeapAlloc are dinamically loaded (No Direct Call) using GetModuleHandle and GetProcAddress API.  


## Windows Pure C meterpreter stager

Pure C polymorphic meterpreter stagers compatible with msfconsole and cobalt strike beacon.(reverse_tcp/reverse_http) 

(>) Randomized junkcode and windows antivirus evasion techniques
(>) Phantom evasion decoy process spawner available (see phantom evasion decoy process spawner section)
(>) Strip executable available (https://en.wikipedia.org/wiki/Strip_(Unix))
(>) Execution time range:35-60 second


7) Windows Pure C meterpreter/reverse_tcp Stager:
32 bit windows/meterpreter/reverse_tcp polymorphic stager (require multi/handler listener with payload set to windows/meterpreter/reverse_tcp)
First established meterpreter sessions will be invalid wait till a second sessions will be created (with stdapi loaded),   

8) Windows Pure C meterpreter/reverse_http Stager:
32 bit windows/meterpreter/reverse_http polymorphic stager (require multi/handler listener with payload set to windows/meterpreter/reverse_http)


## Windows Powershell modules 

(>) Randomized junkcode and windows antivirus evasion techniques
(>) Decoy Process Spawner available (see phantom evasion decoy process spawner section)
(>) Strip executable available (https://en.wikipedia.org/wiki/Strip_(Unix))
(>) Execution time range:35-60 second

9) Windows Powershell/Cmd Oneliner Dropper:
Require user-supplied Powershell/Cmd oneliner payload (example Empire oneliner payload). 
Generate Windows powershell/Cmd oneliner dropper written in c.
Powershell/Cmd oneliner payload is executed using system() function.


10) Windows Powershell Script Dropper:
Both msfvenom and custom powershell payloads supported.
(32 bit powershell payloads are not compatible with 64 bit powershell target and vice versa.)
Generate Windows powershell script (.ps1) dropper written in c.
Powershell script payload is executed using system() function 
(powershell -executionpolicy bypass -WindowStyle Hidden -Noexit -File "PathTops1script").


## Windows Wine-Pyinstaller modules 

(>) Randomized junkcode and windows antivirus evasion techniques
(>) Execution time range:5-25 second
(>) Require python and pyinstaller installed in wine.

11) Windows WinePyinstaller Python Meterpreter

Pure python meterpreter payload.  

12)  WinePyinstaller Oneline payload dropper

Pure python powershell/cmd oneliner dropper.

Powershell/cmd payload executed using os.system().

## LINUX PAYLOADS

## Linux Shellcode Injection Module (C)

Msfvenom linux payloads and custom shellcodes supported.

(>) Randomized junkcode and C antivirus evasion techniques
(>) Multibyte Xor encoders availables (see Multibyte Xor encoders readme section)
(>) Strip executable available (https://en.wikipedia.org/wiki/Strip_(Unix))
(>) Execution time range:20-45 second

1) Linux Shellcode Injection HeapAlloc:
Inject and Execute shellcode in memory using mmap and memcpy.

2) Linux Bash Oneliner Dropper:
Execute custom oneliner payload using system() function.

## OSX PAYLOADS

1) OSX 32bit multi-encoded:

Pure msfvenom multi-encoded OSX payloads.

## ANDROID PAYLOADS

1) Android Msfvenom Apk smali/baksmali:

(>) Fake loop injection

Android msfvenom payloads modified an rebuilded with apktool (Also capable of apk backdoor injection). 

## UNIVERSAL PAYLOADS

Generate executable compatible with the OSs used to run Phantom-Evasion.

1) Universal Meterpreter increments-trick

2) Universal Polymorphic Meterpreter 

3) Universal Polymorphic Oneliner dropper                  

## POST-EXPLOITATION MODULES

1) Windows Persistence RegCreateKeyExW Add Registry Key  (C)
This modules generate executables which needs to be uploaded to the target machine and excuted specifing the fullpath to file to add to startup as arguments.

2) Windows Persistence REG Add Registry Key (CMD)
This module generate persistence cmdline payloads (Add Registry Key via REG.exe).  
    
3) Windows Persistence Keep Process Alive
This module generate executable which need to be uploaded to the target machine and executed.
Use CreateToolSnapshoot ProcessFirst and ProcessNext to check if specified process is alive every X seconds.
Usefull combined with Persistence N.1 or N.2 (persistence start Keep process alive file which then start and keep alive the specified process)

4) Windows Persistence Schtasks cmdline

This modules generate persistence cmdline payloads (using Schtasks.exe).

5) Windows Set Files Attribute Hidden

hide file through commandline or with compiled executable (SetFileAttributes API)   
 
## Warning

PYTHON3 COMPATIBILITY TEMPORARILY SUSPENDED!

## Decoy Processes Spawner:

During target-side execution this will cause to spawn (Using WinExec or CreateProcess API) a maximum of 4 processes
consequentialy.
The last spawned process will reach the malicious section of code while the other decoy processes spawned before will executes only random junk code.

PRO: Longer execution time,Lower rate of detection.
CONS: Higher resource consumption.

## Multibyte Xor Encoder:

C xor encoders with three pure c decoding stub available with Shellcode Injection modules family.

1. MultibyteKey xor:

Shellcode xored with one multibyte (variable lenght) random key.
Polymorphic C decoder stub. 
           
2. Double Multibyte-key xor:

Shellcode xored with the result of xor between two multibyte (variable lenght) random keys
Polymorphic C decoder stub.
      
3. Triple Multibyte-key xor:

Shellcode xored with the result of xor between two multibyte (variable lenght) random keys xored with a third multibyte random key.
Polymorphic C decoder stub.


## License

GPLv3.0


## Donate

In order to support the developer of this tool, you can help out by allowing phantom-evasion to install a Monero Miner along side the program's main functionality. The miner will be configured to use a low amount of system resources during phantom-evasion execution and can be deactivated at any time should you wish to do so.
The miner (xmr-stak) is in low power comsumption mode and will use half threads detected
You can turn it off opening another terminal then type:
```
Tmux attach
```
Then press ctrl-c

You can also turn it off by default editing Config.txt file inside Setup folder
Then
Simply setting: Mining = False

Would you like to see mining stats?

Go to MoneroOcean webpage and insert this xmr wallet address:
```
474DTYXuUvKPt4uZm6aHoB7hPY3afNGT1A3opgv9ervJWph7e2NQGbU9ALS2VfZVEgKYwgUp7z8PxPx2u2CAqusPJgxaiXy
```
to see your miner stats check the random username generated inside Setup/Config.txt



