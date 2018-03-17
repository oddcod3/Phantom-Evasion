# PHANTOM EVASION

## Version 0.3 released!

Phantom-Evasion is an antivirus evasion tool written in python able to generate metamorphic malware capable to detect sandbox artifacts and 
delay payload execution (EXECUTION TIME RANGE: 30/120 seconds, tested on "win10 vbox 2core 2gb Ram").
The aim of this tool is to make antivirus evasion an easy task for pentesters 
with the use of prewitten modules that require minimal knowledge and grant excellent results.

Format: exe/elf/apk/dmg

MODULE TYPE:
 
Windows,Linux,Android,Osx,Universal   (Platform-Target)

Xmr miner integrated (see Donate section)

## New Indirect Call modules

4 new windows modules that load critical functions (VirtualAlloc,Heapcreate,Heapalloc) dynamically using LoadLibrary/GetProcAddress or GetProcAddress/GetModuleHandle


## New Wine-pyinstaller modules

Still experimental (More on 0.4 version)  

## Three Custom Encoders

New Double & Triple key multibyte xor encoder with C decryption stub compatible with msfvenom and custom payloads

## Full undetectable 64bit payloads

Again 64 bit payloads are fully supported and completely undetectable (0/66) while 32 bit payloads are less efficient (6/66) even if they still evade most common antiviruses.
Almost all pcs these days are 64bit so you should consider the benefits of using 64 bit payloads

Give it a try comparing result for example using:

windows/meterpreter/reverse_tcp

And:

windows/x64/meterpreter/reverse_tcp

## Powershell payload support

Powershell oneline dropper usefull to drop empire oneline payload

Powershell script dropper support msfvenom powershell payloads and custom powershell payload

Powershell script dropper can't execute 32 bit powershell payload on 64 bit target
Be sure in that case to use 64 bit payload


## Getting Started

Simply git clone or download and unzip Phantom-Evasion folder


## Installing


## kali linux:

The best.
Actually the only OS truly supported.
Automatic setup, simply launch with:
```
python phantom-evasion.py 
```
or:
```
chmod +x ./phantom-evasion.py

./phantom-evasion.py
```

## windows 10

Install python 2.7

Install dependencies manually:

Install & setup gcc,cygwin,pyinstaller,apktool,openssl,metasploit

remember to set Environment variables 

go to phantom-evasion folder and launch:

```
py phantom-evasion.py 
```

## linux with apt:



Manually install metasploit framework if not present then:

Automatic setup, simply launch with:
```
python phantom-evasion.py 
```
or:

```
chmod +x ./phantom-evasion.py

./phantom-evasion.py

```

## linux no apt:

Install dependencies manually:

Install & setup gcc,mingw-w64,pyinstaller,apktool,openssl,metasploit,zipalign



## Module choice 

Modules which targets specific platform are prefixed with Windows,Linux,Android,OSX,

Universal modules generate different type of executable dependending on which platform is used to launch Phantom Evasion (pyinstaller)


## Modules options

Multipath modules support both msfvenom payload or custom shellcode 

Powershell oneline dropper support empire one-liner payload

Powershell script dropper support msfvenom powershell payloads or custom powershell scripts

Android msvenom smali obfuscator module support both msfvenom payload obfuscation and injection in existing apk (if apktool succeed in baksmailing the apk)

Pytherpreter modules supports all python msfvenom payload

## Warning

Never rename generated executable (choose file name during generation process)

Actually there is no error checking routine on user input!!
Be sure to input options correctly!!

PYTHON3 COMPATIBILITY TEMPORARILY SUSPENDED!

Like Jon Snow "I know nothing"


## Cross platform autocompile SUPPORTED:

Using linux :

GCC used to compile source code to ELF format

Mingw-w64 used to compile source code to EXE format

Pyinstaller used to generate pyhton  ELF executable

in windows:

GCC  used to compile source code to EXE format

Cygwin > AUTOCOMPILE ELF not supported

Pyinstaller used to generate python EXE executable

When using "msfvenom payload" options phantom evasion will autocompile 32 bit executable if a 32 bit payload is selected
Instead 64 bit executable will be generated using 64 bit payload

Example:

Windows/meterpreter/reverse_tcp  (autocompiled to exe 32 bit)

Windows/x64/meterpreter/reverse_tcp (autocompiled to exe 64 bit)

Equivalent for linux modules

When using "Polymorphic Powershell Script Dropper" remember that 32 bit powershell payloads are not compatible with 64 bit powershell target and vice versa


## license

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

Go to MoneroOcenan webpage and insert this xmr wallet address:
```
474DTYXuUvKPt4uZm6aHoB7hPY3afNGT1A3opgv9ervJWph7e2NQGbU9ALS2VfZVEgKYwgUp7z8PxPx2u2CAqusPJgxaiXy
```
to see your miner stats check the random username generated inside Setup/Config.txt


