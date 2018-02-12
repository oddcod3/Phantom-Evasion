# PHANTOM EVASION

## Version 0.2 released!

Phantom-Evasion is a malware stub generator tool written in python.
The aim of this tool is to make antivirus evasion an easy task for pentesters 
with the use of prewritten modules capable to 
generate  (almost) undetectable executable even with most common 32 bit metasploit payload.
This tool combine AV Sandbox detection with static analysis evasion 

Format: exe/elf/apk/dmg

MODULE TYPE:
 
Windows,Linux,Android,Osx,Universal   (Platform-Target)

Universal modules produces malware stub executable using pyinstaller for the  OS used during generation process.

## Full undetectable 64bit payload

Now 64 bit payloads are fully supported and completely undetectable (1/66) 
While 32 bit payloads are less efficient (16/66) even if they still evade most commons antiviruses
Almost all pcs these days are 64bit so you should consider the benefits of using 64 bit payload

Give it a try comparing result for example using:

windows/meterpreter/reverse_tcp

And:

windows/x64/meterpreter/reverse_tcp


## Custom Encoder

New multibyte xor encoder with C decryption stub compatible with msfvenom and custom payloads

## Powershell payload support

New powershell oneline dropper usefull to drop empire oneline payload

New powershell script dropper support msfvenom powershell payloads and custom powershell payload

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

Phantom-evasion now come with an integrated monero miner active by default.
The miner (xmr-stak) is in low power comsumption mode and will use half of the threads detected
You can turn it off opening another terminal then type:
```
Tmux attach
```
Then press ctrl-c

You can also turn it off by default editing Config.txt file inside Setup/Donate folder

Simply setting: Miner = False

if you like my code you can buy me a beer

Bitcoin  (BTC) :   1GgvVkgagqVcmWyppG8xPCjEpfhhUgyyJQ

Litecoin (LTC) :   LhUnmVNC7wcBCb1uiZ9S2AKkvTDSDHJB6H

Ethereum (ETH) :   0xb025bcF5b4D7F9Fd26a2D4B1412D1c0776C7B2E9

Monero   (XMR) :   474DTYXuUvKPt4uZm6aHoB7hPY3afNGT1A3opgv9ervJWph7e2NQGbU9ALS2VfZVEgKYwgUp7z8PxPx2u2CAqusPJgxaiXy
