
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
sys.dont_write_bytecode = True

def python_poly_multipath(number,step):
    num_space = ""
    if step == "1":
        num_space=""
    elif step == "2":
        num_space="    "
    elif step == "3":
        num_space="        "
    elif step == "4":
        num_space="            "
    
    if number == "1":    #Long Counter
        Randcounter = varname_creator()
        Randbig = str(random.randint(6000000,12000000))  
        Hollow_code = ""
        Hollow_code += num_space + Randcounter + " = 0\n"
        Hollow_code += num_space + "while " + Randcounter + " < " + Randbig + ":\n"
        Hollow_code += num_space + "    " + Randcounter + " += 1\n"
        Hollow_code += num_space + "if " + Randcounter + " == " + Randbig + ":\n"
        return Hollow_code 

    elif number == "2":   #BacktoZero

        Randbig1 = str(random.randrange(4000000,12000000,1000000))
        Randcpt = varname_creator()
        Hollow_code = ""
        Hollow_code += num_space + Randcpt + "  = " + Randbig1 + "\n"
        Hollow_code += num_space + "while  " + Randcpt + " > 0 :\n"
        Hollow_code += num_space + "    " + Randcpt + " = " + Randcpt + " - 1\n"
        Hollow_code += num_space + "if " + Randcpt + " == 0 :\n"
        return Hollow_code 

    elif number == "3": # crazy pow 

        Randvar = varname_creator()
        Randfloat = random.uniform(1.110,1.119)
        Randint = random.randint(100,300)
        Randpow = Randfloat**Randint
        Randpow = str(Randpow)  
        Hollow_code = ""
        Hollow_code += num_space + Randvar + " = " + Randpow + "\n"
        Hollow_code += num_space + "while " + Randvar + " > 1:\n"
        Hollow_code += num_space + "    " + Randvar + " = " + Randvar + "/" + str(Randfloat) + "\n"
        Hollow_code += num_space + "if " + Randvar + " <= 1:\n" 
        return Hollow_code

def Junkmathinject(number):

    if number == "1":#sum firs n integer 
        Randcounter = varname_creator()
        Randcounter2 = varname_creator()
        Randcounter3 = varname_creator()
        Randbignumb = str(random.randint(60000,90000))
        Junkcode = ""
        Junkcode += "int " + Randcounter + "," + Randcounter2 + "," + Randcounter3 + " = 0;\n"
        Junkcode += Randcounter2 + " = " + Randbignumb + ";\n"
        Junkcode += "for (" + Randcounter + " = 1;" + Randcounter + " <= " + Randcounter2 + "; " + Randcounter + "++){\n"
        Junkcode += Randcounter3 + " = " + Randcounter3 + "+" + Randcounter + ";}\n"
        Junkcode += "printf (\"%d\"," + Randcounter3 + ");\n" 

    elif number == "2":#fibonacci numbers in range (1,N)

        Rand1=varname_creator()
        Rand2=varname_creator()
        Rand3=varname_creator()
        Rand4=varname_creator()
        Rand5=varname_creator()
        Randbignumb = str(random.randint(600000,900000))

        Junkcode = ""
        Junkcode += "int " + Rand1 + " = 0," + Rand2 + " = 1," + Rand3 + "," + Rand4 + "," + Rand5 + " = 0;\n"
        Junkcode += Rand4 + " = " + Randbignumb + ";\n"
        Junkcode += "printf(\" %d \"," + Rand4 + ");\n"
        Junkcode += "while (" + Rand5 + " < " + Rand4 + "){\n"
        Junkcode += Rand3 + " = " + Rand1 + " + " + Rand2 + ";\n" + Rand5 + "++;\n"
        Junkcode += "printf(\"%d \"," + Rand3 + ");\n" + Rand1 + "=" + Rand2 + ";\n" + Rand2 + " = " + Rand3 + ";}\n"
 

    elif number == "3":#colossal factorial
        Randn = varname_creator()
        Randbig = str(random.randint(60,120))
        Randii = varname_creator()
        Randfact = varname_creator()

        Junkcode = ""
        Junkcode += "int " + Randn + " = " + Randbig + "," + Randii + ";\n" + "unsigned long long " + Randfact + " = 1;\n"
        Junkcode += "for(" + Randii + "=1; " + Randii + "<=" + Randn + ";" + Randii + "++){\n" + Randfact + " *= " + Randii + ";}\n"
        Junkcode += "printf(\"%llu\"," + Randfact + ");\n"

    elif number == "4": # Twin tower 

        Randbig1 = str(random.randrange(100000000,120000000,1000000))
        Randbig2 = str(random.randrange(60000000,100000000,1000000))
        Randcpt= varname_creator()
        Randcpt2= varname_creator()
        Randi = varname_creator()
        Junkcode = ""
        Junkcode += "int " + Randcpt + "  = " + Randbig1 + ";\n"
        Junkcode += "int " + Randcpt2 + " = " + Randbig2 + ";\n"
        Junkcode += "while ( " + Randcpt + " > 0 ){\n"
        Junkcode += "if (" + Randcpt + " > " + Randcpt2 + "){\n"
        Junkcode += Randcpt + " = " + Randcpt + " - 1;}\n"
        Junkcode += "else{\n"
        Junkcode += Randcpt2 + " = " + Randcpt2 + " - 1;}\n"
        Junkcode += "printf(\"%d\"," + Randcpt + ");}\n"

    elif number == "5": #BacktoZero

        Randbig1 = str(random.randrange(40000000,120000000,1000000))
        Randcpt= varname_creator()
        Junkcode = ""
        Junkcode += "int " + Randcpt + "  = " + Randbig1 + ";\n"
        Junkcode += "while ( " + Randcpt + " > 0 ){\n"
        Junkcode += Randcpt + " = " + Randcpt + " - 1;\n"
        Junkcode += "printf(\"%d\"," + Randcpt + ");}\n"


    return Junkcode


def Polymorph_Multipath_Evasion(number,Filename):

    if number == "1": # What's my name

        Evasion_code = ""
        Evasion_code += "if (strstr(argv[0], \"" + Filename + ".exe\") > 0){\n"
        return Evasion_code

    elif number == "2": # Giant memory allocation 

        Randmem = varname_creator()
        Randbig = str(random.randrange(60000000,120000000,1000000))
        Evasion_code = ""
        Evasion_code += "char *" + Randmem + " = NULL;\n"
        Evasion_code += Randmem + " = (char *) malloc("+ Randbig + ");\n"
        Evasion_code += "if ("+ Randmem + "!=NULL){\n"
        Evasion_code += "memset(" + Randmem + ",00," + Randbig + ");\n"
        Evasion_code += "free(" + Randmem + ");\n"
        return Evasion_code

    elif number == "3": # Loooooong Counter 

        Randbig = str(random.randrange(60000000,120000000,1000000))
        Randcpt= varname_creator()
        Randi = varname_creator()
        Evasion_code = ""
        Evasion_code += "int " + Randcpt + "  = 0;\n"
        Evasion_code += "int " + Randi + " = 0;\n"
        Evasion_code += "for("+ Randi + " = 0;" + Randi + " < " + Randbig + "; " + Randi + "++){\n"
        Evasion_code += Randcpt + "++;}\n"
        Evasion_code += "if("+ Randcpt + " == " + Randbig + "){\n"
        return Evasion_code

    elif number == "4": # am i zero?

        Randbig = str(random.randrange(60000000,120000000,1000000))
        Randcpt= varname_creator()
        Randi = varname_creator()
        Evasion_code = ""
        Evasion_code += "int " + Randcpt + "  = " + Randbig + ";\n"
        Evasion_code += "int " + Randi + " = 0;\n"
        Evasion_code += "while ( " + Randcpt + " > 0 ){\n"
        Evasion_code += Randcpt + " = " + Randcpt + " - 1;}\n"
        Evasion_code += "if("+ Randcpt + " == 0){\n"

        return Evasion_code
          
def varname_creator():
    varname = ""
    Adam = random.randint(4,8)
    Eve = random.randint(12,16)
    varname = ''.join(random.SystemRandom().choice(string.ascii_lowercase) for _ in range(random.randint(Adam,Eve)))
    return varname 



