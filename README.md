# PHANTOM EVASION

Phantom-Evasion is a malware stub generator tool written in python 
both compatibile with python 2.7 and 3.4 or higher( note that python 2.7 is required for pyinstaller).
The aim of this tool is to make antivirus evasion an easy task for pentesters 
with the use of prewritten modules capable to 
generate  (almost) undetectable executable even with most common 32 bit metasploit payload.
Dynamic Evasion is the trump card of this tool while advanced encryption is not implemented (isn't necessary). 

MODULE TYPE:
 
Windows,Linux,Android,Osx,Universal   (Platform-Target)

Universal modules produces malware stub executable using pyinstaller for the  OS used during generation process.

## NODISTRIBUTE result at the day of release:

windows and linux modules use shikata_ga_nai for static analysis evasion
sometimes some low ranked antiviruses detect shikata_ga_nai signature in that case simply rerun the module
and verify again.

payload used: 

windows/meterpreter/reverse_tcp for exe

linux/x86/meterpreter/reverse_tcp for elf 

android/meterpreter/reverse_tcp for apk

osx/x64/meterpreter/reverse_tcp for dmg

python/meterpreter/reverse_tcp in Universal modules


MODULE(FORMAT)(RESULT) 

windows multipath virtualalloc                  (exe)    (0/37)

windows multipath heapalloc                     (exe)    (0/37)

windows polymorphic multipath virtualalloc      (exe)    (0/37)

windows polymorphic multipath heapalloc         (exe)    (0/37)

linux multipath heapalloc                       (elf)    (0/37)

linux polymorphic multipath heapalloc           (elf)    (0/37)

osx cascade encoding                            (dmg)    (4/37)

android smali droidmare:

obfuscate apk payload                           (apk)    (1/37)

obfuscate apk payload & backdoor existing apk   (apk)    (2/37)

universal pytherpreter increments               (elf)    (0/37)

universal pytherpreter polymorphic              (elf)    (0/37)

## Cross platform autocompile SUPPORTED:

In linux :

GCC > elf 

Mingw-w64 > exe

Pyinstaller > elf

in windows:

GCC > exe

Cygwin > elf (AUTOCOMPILE not supported)

Pyinstaller > exe

## Getting Started

Simply git clone or download and unzip Phantom-Evasion folder

requires python2.7 for Universal Modules ( excluding that it works great also with python 3)


## Installing


## kali linux:

The best.

Automatic setup, simply launch with:
```
python phantom-evasion.py 
```
or:

```
python3 phantom-evasion.py
```
or:
```
chmod +x ./phantom-evasion.py

./phantom-evasion.py
```

## windows 10

Install python 2.7

You need to install dependencies manually:

Install & setup gcc,cygwin,pyinstaller,apktool,openssl,metasploit

remember to set Environment variable 

go to phantom-evasion folder and launch:

```
py phantom-evasion.py 
```

## linux with apt:



You need to manually install metasploit framework if not present then:

Automatic setup, simply launch with:
```
python phantom-evasion.py 
```
or:

```
python3 phantom-evasion.py
```
or:
```
chmod +x ./phantom-evasion.py

./phantom-evasion.py

```

## linux no apt:

You need to install dependencies manually:

Install & setup gcc,mingw-w64,pyinstaller,apktool,openssl,metasploit,zipalign



## Module choice 

Modules which targets specified platform are prefixed with Windows,Linux,Android,OSX,

Universal modules create an executable type dependent on which platform is used for generation process (pyinstaller)


## Modules options

Multipath modules support both msfvenom payload or custom shellcode 

Android Smali-Droidmare module support both msfvenom payload obfuscation and injection in existing apk (if apktool succeed in baksmailing the apk)

Pytherpreter modules supports all python msfvenom payload

## license
GPLv3.0

## Donate

if you want you can buy me a beer

Bitcoin: 1J7UHCc5PvWEA4CgaeuLDHJgmiAWBvn8Qe



