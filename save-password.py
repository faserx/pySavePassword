#!/usr/bin/python3
import hashlib
import base64
import sys
import re
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
      outFile = open(filename,"wb")
    outFile.write((enc+"\n").encode("UTF-8"))
    outFile.close()
    
  except Exception as e:
    print(bcolors.WARNING,"Exception: ", sys.exc_info()[0],bcolors.ENDC)
    raise
    
def decrypt(key, search):
  found = False;
  inFile = open("test.lock","r")
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
  
def usage():
  print(bcolors.BOLD+"Usage:\n"+bcolors.ENDC)
  print(bcolors.BOLD+"\tsave-password.py -(c/d) -p 'password' (-s site*)\n"+bcolors.ENDC)
  print(bcolors.BOLD+"\t\t-c -> crypt\n\t\t-d -> decrypt\n"+bcolors.ENDC)
  print(bcolors.BOLD+"Example:\n"+bcolors.ENDC)
  print(bcolors.BOLD+"\tsave-password.py -c -p 'password'\n\t**for crypt content**"+bcolors.ENDC)
  print(bcolors.BOLD+"\tsave-password.py -d -p 'password'\n\t**for all content**\n"+bcolors.ENDC)
  print(bcolors.BOLD+"\tsave-password.py -d -p 'password' -s 'http://www.google.it'\n\t**for you username and password from google.it**"+bcolors.ENDC)
  
if(len(sys.argv) < 4):
  usage()
else:
  if(sys.argv[1] == '-c' and (sys.argv[2] == '-p' and len(sys.argv) >= 4)):
    site = input("Inserire il sito: ")
    username = input("Inserire l'username: ")
    password = input("Inserire la password: ")
    text = site+":"+username+":"+password
    encrypt(sys.argv[3], text)
  elif(sys.argv[1] == '-d' and (sys.argv[2] == '-p' and sys.argv[4] == '-s' and len(sys.argv) >= 6)):
    decrypt(sys.argv[3], sys.argv[5])
