#!/usr/bin/python3
# -*- coding: utf-8 -*-
#
#  secure-password.py
#  
#  Copyright 2016 Piero Aiello <piero.aiello@protonmail.com>
#  
#  This program is free software; you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation; either version 2 of the License, or
#  (at your option) any later version.
#  
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#  
#  You should have received a copy of the GNU General Public License
#  along with this program; if not, write to the Free Software
#  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
#  MA 02110-1301, USA.
#  
#  
import hashlib
import base64
import sys
import re
import os
import os.path
from Crypto.Cipher import AES
from Crypto import Random

class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

def generateSecureKey(key):
  return hashlib.md5(str(key).encode("UTF-8")).hexdigest()

def pad(text):
  return  text + (AES.block_size - len(text) % AES.block_size) * chr(AES.block_size - len(text) % AES.block_size)

def unpad(text):
  return text[:-ord(text[len(text)-1:])]

def encryptAll(key,text):
  key  = generateSecureKey(key)
  
  try:
    filename = "test.lock"
    
    outFile = open(filename,"w")
    
    iv = Random.new().read(AES.block_size)
    cipher = AES.new(key,AES.MODE_CFB,iv)
    outFile.writelines(["%s\n"  % (str(base64.b64encode(iv + cipher.encrypt(pad(str(line)))).decode('UTF-8'))) for line in text])
    outFile.close()
    
  except Exception as e:
    print(bcolors.WARNING,"Exception: ", sys.exc_info()[0],bcolors.ENDC)
    raise

def encrypt(key,text):
  key  = generateSecureKey(key)
  
  try:
    filename = "test.lock"
    
    iv = Random.new().read(AES.block_size)
    cipher = AES.new(key,AES.MODE_CFB,iv)
    enc = base64.b64encode(iv + cipher.encrypt(pad(text))).decode('UTF-8')
    
    if(os.path.exists(filename)):
      outFile = open(filename,"a")
    else:
      os.mknod(filename)
      outFile = open(filename,"a")
    outFile.write((enc+"\n"))
    print(bcolors.WARNING,"Credenziali aggiunte con successo! ",bcolors.ENDC)
    outFile.close()
    
  except Exception as e:
    print(bcolors.WARNING,"Exception: ", sys.exc_info()[0],bcolors.ENDC)
    raise
  
  
def decrypt(key, search):
  found = False;
  filename = "test.lock"
  if(os.stat(filename).st_size > 0):
    inFile = open(filename,"r")
    while True:
      inLine = inFile.readline()

      if(inLine == ""):
        break

      inLine = decryptLine(inLine, key)

      site = re.search(search+':(.*):(.*)', inLine, re.M|re.I)

      if(site):
        print(bcolors.OKGREEN+"Corrispondeza trovata!"+bcolors.ENDC)
        print(bcolors.OKBLUE,"Username: "+site.group(1),bcolors.ENDC)
        print(bcolors.OKBLUE,"Password: "+site.group(2),bcolors.ENDC)
        found = True
        break  

    if(not found):
        print(bcolors.FAIL+"Errore: nessuna password salvata per questo indirizzo!"+bcolors.ENDC)
  else:
    print(bcolors.FAIL+"Nessuna credenziale salvata!"+bcolors.ENDC)
        
def decryptAll(key):
  found = False;
  filename = "test.lock"
  if(os.stat(filename).st_size > 0):
    inFile = open(filename,"r")
    while True:
      inLine = inFile.readline()
      if(inLine == ""):
        break

      inLine = decryptLine(inLine, key)
      inLine = inLine.split(':')
      if(len(inLine) >= 3):
        print(bcolors.OKGREEN,"--------------------------------", bcolors.ENDC)
        print(bcolors.OKBLUE,"Site: http://"+inLine[0], bcolors.ENDC)
        print(bcolors.OKBLUE,"Username: "+inLine[1],bcolors.ENDC)
        print(bcolors.OKBLUE,"Password: "+inLine[2],bcolors.ENDC)
    print(bcolors.OKGREEN,"--------------------------------", bcolors.ENDC)
  else:
    print(bcolors.FAIL+"Nessuna credenziale salvata!"+bcolors.ENDC)
  
def decryptLine(text, key):
  key  = generateSecureKey(key)
  
  try:
    text = base64.b64decode(text)
    iv = text[:AES.block_size]
    cipher = AES.new(key,AES.MODE_CFB,iv)
    
    return unpad(cipher.decrypt(text[AES.block_size:])).decode('UTF-8')
  except Exception as e:
    print(bcolors.WARNING,"Exception: ", sys.exc_info()[0],bcolors.ENDC)
    raise

def deleteForSite(site, key):
  item = list()
  found = False
  filename = "test.lock"
  if(os.stat(filename).st_size > 0):
    inFile = open(filename,"r")
    while True:
      inLine = inFile.readline()

      if(inLine == ""):
        break

      inLine = decryptLine(inLine, key)
      split = inLine.split(':')
      if(site != split[0]):
        item.append(inLine)
      else:
        found = True
        
    if(found):
      encryptAll(key, item)
      print(bcolors.WARNING,"Credenziali eliminate con successo!",bcolors.ENDC)
    else:
      print(bcolors.FAIL+"Nessuna credenziale trovata!"+bcolors.ENDC)
  else:
    print(bcolors.FAIL+"Impossibile eliminare le credenziali: Nessuna credenziale salvata!"+bcolors.ENDC)

def deleteAll():
  infile = open("test.lock", "w")
  infile.close();
  print(bcolors.WARNING,"Tutte le credenziali sono state eliminate con successo!",bcolors.ENDC)

def usage():
  print(bcolors.BOLD+"Usage:\n"+bcolors.ENDC)
  print(bcolors.BOLD+"\tsecure-password.py -(c/d) -p 'password' (-s site*)\n"+bcolors.ENDC)
  print(bcolors.BOLD+"\t\t-c -> crypt\n\t\t-d -> decrypt\n\t\t-del -> delete"+bcolors.ENDC)
  print(bcolors.BOLD+"Example:\n"+bcolors.ENDC)
  print(bcolors.BOLD+"\tsecure-password.py -c -p 'password'"+bcolors.ENDC+bcolors.WARNING+"\n\t**to crypt content**"+bcolors.ENDC)
  print(bcolors.BOLD+"\tsecure-password.py -d -p 'password'"+bcolors.ENDC+bcolors.WARNING+"\n\t**to  decrypt lall content**"+bcolors.ENDC)
  print(bcolors.BOLD+"\tsecure-password.py -d -p 'password' -s 'http://www.google.it'"+bcolors.ENDC+bcolors.WARNING+"\n\t**to decrypt you username and password from google.it**"+bcolors.ENDC)
  print(bcolors.BOLD+"\tsecure-password.py -del -p 'password' -s 'http://www.google.it'"+bcolors.ENDC+bcolors.WARNING+"\n\t**to delete you username and password from google.it**"+bcolors.ENDC)
  
if(sys.argv[1] == '-delete-all'):
  deleteAll()
elif(len(sys.argv) < 4):
  usage()
else:
  if(sys.argv[1] == '-c' and (sys.argv[2] == '-p' and len(sys.argv) == 4)):
    site = input("Inserire il sito (senza 'http://' ): ")
    username = input("Inserire l'username: ")
    password = input("Inserire la password: ")
    text = site+":"+username+":"+password
    encrypt(sys.argv[3], text)
  elif(sys.argv[1] == '-d' and (sys.argv[2] == '-p' and len(sys.argv) == 4)):
    decryptAll(sys.argv[3])
  elif(sys.argv[1] == '-d' and (sys.argv[2] == '-p' and sys.argv[4] == '-s' and len(sys.argv) == 6)):
    decrypt(sys.argv[3], sys.argv[5])
  elif(sys.argv[1]== '-del' and (sys.argv[2] == '-p' and len(sys.argv) == 4)):
    site = input("Inserire il sito (senza 'http://'): ")
    deleteForSite(site, sys.argv[3])
  elif(sys.argv[1]== '-del' and (sys.argv[2] == '-p' and sys.argv[4] == '-s' and len(sys.argv) == 6)):
    deleteForSite(sys.argv[5], sys.argv[3])

