


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

import platform
import subprocess
import os
from time import sleep

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

def path_finder(filename):
    path = ""
    lookfor = filename
    
    if platform.system() == "Windows":

        for root, dirs, files in os.walk('C:\\'):
            if lookfor in files:
                path = os.path.join(root, lookfor)
                return path

def AutoSetup():

    pl = platform.system().lower()
    rel = platform.platform().lower()

    if pl == "linux":

        if "kali" in rel or "parrot" in rel:

            KaliParrotSetup()

        else:

            OtherLinuxSetup()

    elif pl == "darwin":

        OSXSetup()

    elif pl == "windows":

        WinSetup()



def PMinst(pm,namelist):

    for name in namelist:

        print(bcolors.GREEN + "\n[>] Trying to install: " + name + bcolors.ENDC + "\n")
        sleep(0.5)

        if pm == "apt":

            subprocess.call(['sudo','apt-get','install',name,'-y'])

        elif pm == "dnf":

            subprocess.call(['sudo','dnf','-y','install',name])

        elif pm == "pacman":

            subprocess.call('sudo','pacman','-Sy',name,'--needed')

        elif pm == "brew":

            os.system('brew install ' + name)


def KaliParrotSetup():

    deplist = ["gcc-multilib","mingw-w64","strip","osslsigncode","apktool","apksigner","zipalign"]

    try:
        PMinst("apt",deplist)
        Apktool_download()
    except:

        print(bcolors.RED + "\n[>] Setup Completed [error occured during setup]!!\n" + bcolors.ENDC)
        sleep(1)
    else:
        print(bcolors.GREEN + "\n[>] Setup Completed!!\n" + bcolors.ENDC)
        sleep(1)

def OtherLinuxSetup(rel):

    if "centos" in rel or "fedora" in rel or "rhel" in rel:

        pm = "dnf"

    elif "debian" in rel or "deepin" in rel or "linuxmint" in rel or "ubuntu" in rel or "elementary" in rel:

        pm = "apt"

    elif "blackarch" in rel:

        pm = "pacman"
    
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

    deplist = ["gcc-multilib","mingw-w64","strip","osslsigncode","apktool","apksigner"]

    try:

        PMinst(pm,deplist)
        Apktool_download()

    except:

        print(bcolors.RED + "\n[>] Setup Completed [error occured during setup]!!\n" + bcolors.ENDC)
        sleep(1)
    else:
        print(bcolors.GREEN + "\n[>] Setup Completed!!\n" + bcolors.ENDC)
        sleep(1)

def OSXSetup():

    try:
        is_present=subprocess.check_output(['which','brew'],stderr=subprocess.STDOUT)

    except subprocess.CalledProcessError: 

        print("[-] Trying to install Homebrew...\n")
   
        os.system("/usr/bin/ruby -e \"$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/master/install)\"")

    else:

        print("[>] Homebrew Found..\n")

    deplist = ["gcc","mingw-w64","osslsigncode","apktool"]

    PMinst("brew",deplist)
    Apktool_download()

def Apktool_download():

    if os.path.isfile("Setup/apk_sign/apktool_2.4.1.jar") != True:
        print(bcolors.GREEN + "[>] Apktool_2.4.1 download from https://ibotpeaches.github.io/Apktool...\n" + bcolors.ENDC)
        sleep(0.1)
        PH_dir=os.getcwd()
        os.chdir("Setup/apk_sign")
        os.system("wget https://bitbucket.org/iBotPeaches/apktool/downloads/apktool_2.4.1.jar || curl -O https://bitbucket.org/iBotPeaches/apktool/downloads/apktool_2.4.1.jar")
        os.chdir(PH_dir)




