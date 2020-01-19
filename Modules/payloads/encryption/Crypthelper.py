
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

import os,sys
import random,string
from time import sleep
from platform import python_version
from binascii import hexlify

def RandVarname():
    varname = ""
    Adam = random.randint(4,8)
    Eve = random.randint(12,16)
    varname = ''.join(random.SystemRandom().choice(string.ascii_lowercase) for _ in range(random.randint(Adam,Eve)))
    return varname


def KeyGen(keylen):

    return os.urandom(keylen)

def Printable(data):

    data = hexlify(data)
    pdata = ""

    if python_version()[0] == "3":
    
        data = data.decode('ascii')
                
    for i in range(0,len(data)-1,2):

        pdata += "\\x" + data[i] + data[i+1]

    return pdata




