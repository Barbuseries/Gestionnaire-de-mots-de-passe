# coding: utf-8

import argparse
from random import SystemRandom
import math
import sys
import getpass

cryptogen = SystemRandom()

#dico des mots de passe courants, français, anglais, catalan, espagnol, italian, malgache, norvégien, polonais, roumain et tchèque
def newDico():
    fichier = open("dico3.txt", "r")
    mainDico = {}
    for i in range(32,888):
        if not ((i >= 127 and i <= 160) or i == 173 or (i >= 97 and i <= 122)):
            mainDico[i] = {}
            for j in range(32,888):
                if not ((j >= 127 and j <= 160) or j == 173 or (i >= 97 and i <= 122)):
                    mainDico[i][j] = []
    ligne = fichier.readline()
    while (ligne != ""):
        mainDico[ord(ligne[0])][ord(ligne[1])].append(ligne[:-1])
        ligne = fichier.readline()
    fichier.close()
    return(mainDico)
    
def testDico(word, dico):
    upperWord = ""
    for i in range(len(word)):
        if (ord(word[i]) >= 97 and ord(word[i]) <= 122):
            upperWord = upperWord + word[i].upper()
        else:
            upperWord = upperWord + word[i]
    maxSimil = 0
    for i in range(len(word)-1):
        for j in range(len(word),i+1,-1):
            if (callDico(upperWord, dico, i, j)):
                if (j-i > maxSimil):
                    maxSimil = j-i
    wordLen = len(word)
    del(word)
    del(upperWord)
    return((wordLen-maxSimil)*5/wordLen)

def callDico(word, dico, i, j):
    if word[i:j] in dico[ord(word[i])][ord(word[i+1])]:
        del(word)
        return True
    del(word)
    return False
    
    
def passwordEntropy(key,characterRange = False):
    characters = [i for i in range(32,888) if not ((i >= 127 and i <= 160) or i == 173)]
      
    typeOfChar = [False for i in range(6)]
    for i in key:
        if (i >= chr(65) and i <= chr(90)):
            typeOfChar[0] = True
        elif (i >= chr(97) and i <= chr(122)):
            typeOfChar[1] = True
        elif (i >= chr(48) and i <= chr(57)):
            typeOfChar[2] = True
        elif (i >= chr(192) and i <= chr(255)):
            typeOfChar[3] = True
        elif (i >= chr(256)):
            typeOfChar[4] = True
        else:
            typeOfChar[5] = True
    if typeOfChar[0] == False:
        characters = [i for i in characters if (i < 65 or i > 90)]
    if typeOfChar[1] == False:
        characters = [i for i in characters if (i < 97 or i > 122)]
    if typeOfChar[2] == False:
        characters = [i for i in characters if (i < 48 or i > 57)]
    if typeOfChar[3] == False:
        characters = [i for i in characters if (i < 192 or i > 255)]
    if typeOfChar[4] == False:
        characters = [i for i in characters if (i < 256)]
    if typeOfChar[5] == False:
        characters = [i for i in characters if ((i >= 65 and i <= 90) or (i >= 97 and i <= 122) or (i >= 48 and i <= 57) or (i > 191))]
    
    if (characterRange == True):
        del(key)
        return(len(characters))

    if (key == ""):
        del(key)
        return(0)
    keyLen = len(key)
    previous = [0 for i in range(keyLen)]
    previous[0] = key[0]
    entropy = 0
    for j in range(1,keyLen):
        char = key[j]
        entropyChar = 0.0
        for i in range(j):
            entropyChar += abs(characters.index(ord(char))-characters.index(ord(previous[i]))) / len(characters)
        for i in range(keyLen - 1,0,-1):
            previous[i] = previous[i - 1]
        previous[0] = char
        entropy += entropyChar / (j)
    entropy = entropy / keyLen
    noteEntropy = entropy*5/0.31
    if (noteEntropy > 5):
        noteEntropy = 10 - noteEntropy
    del(key)
    del(previous)
    return(noteEntropy)

def newPass(length, upperCase, lowerCase, number, accentMark, special, duplicate):
    characters = [i for i in range(32,888) if not ((i >= 127 and i <= 160) or i == 173)]
    
    if (upperCase == None):
        characters = [i for i in characters if (i < 65 or i > 90)]
    if (lowerCase == None):
        characters = [i for i in characters if (i < 97 or i > 122)]
    if (number == None):
        characters = [i for i in characters if (i < 48 or i > 57)]
    if (accentMark == None):
        characters = [i for i in characters if (i < 192)]
    if (special == None):
        characters = [i for i in characters if ((i >= 65 and i <= 90) or (i >= 97 and i <= 122) or (i >= 48 and i <= 57) or (i > 191))]
    
    if (duplicate == True and length > len(characters)):
        print("vtff aprends à compter connard")
        exit()
    
    password = ""
    for i in range(length):
        alea = cryptogen.randrange(len(characters))
        password += chr(characters[alea])
        if (duplicate == True):
            del characters[alea]
    return password



parser = argparse.ArgumentParser(description='A password generator')

parser.add_argument("length", metavar = "LENGTH", type = int, nargs = '?', default = 12)
parser.add_argument("-u", "--upperCase", dest = "upperCase", action = "store_const", const = True, help = "If given, capitals letters will be added to the password")
parser.add_argument("-l", "--lowerCase", dest = "lowerCase", action = "store_const", const = True, help = "If given, lowercases will be added to the password")
parser.add_argument("-n", "--number", dest = "number", action = "store_const", const = True, help = "If given, numbers will be added to the password")
parser.add_argument("-s", "--special", dest = "special", action = "store_const", const = True, help = "If given, special characters will be added to the password")
parser.add_argument("-d", "--duplicate", dest = "duplicate", action = "store_const", const = True, help = "If given, the password will not contain any duplicate")
parser.add_argument("-a", "--accentMark", dest = "accentMark", action = "store_const", const = True, help = "If given, the password will contain accent marks")
parser.add_argument("-t", "--testPassword", dest = "testPassword", type = str, nargs = "?", const = "", help = "The given password security will be tested then the program will end")

args = parser.parse_args()

if (args.upperCase == None and args.lowerCase == None and args.number == None and args.special == None and args.accentMark == None):
    args.upperCase, args.lowerCase, args.number, args.special, args.accentMark = True, True, True, True, True

if (args.testPassword == ""):
    args.testPassword = getpass.getpass()
dico = newDico()
if (args.testPassword != None):
    noteDico = round(testDico(args.testPassword,dico),2)
    noteEntropy = round(passwordEntropy(args.testPassword),2)
    print("Your password marks are "+str(noteEntropy)+"/5.0 for the entropy, "+str(noteDico)+"/5.0 for the dictionnary attack which gives "+str(round(noteEntropy/2 + noteDico/2,2))+"/5.0 as a total. Keep in mind that those marks don't depend of the lenght of your password neither of the range of characters you choosed.")
    if (len(args.testPassword)<8):
        print("We must warn you that choosing a password with less than 8 characters is not recommended.")
    range = passwordEntropy(args.testPassword,True)
    if (range<62):
        print("We must warn you that choosing a password with a range of characters of less than 62 is not recommended. You are currently using a range of "+str(range)+" characters.")
    del(args.testPassword)
    exit()

newPassword = newPass(args.length, args.upperCase, args.lowerCase, args.number, args.accentMark, args.special, args.duplicate)
noteMax = 0
for i in range(1000):
    noteEntropy = passwordEntropy(newPassword)
    noteDico = testDico(newPassword,dico)
    note = noteEntropy/2 + noteDico/2
    if (note > noteMax):
        noteMax = note
        bestPassword = newPassword
    newPassword = newPass(args.length, args.upperCase, args.lowerCase, args.number, args.accentMark, args.special, args.duplicate)
noteMax = round(noteMax,8)
try:
    print("Here is the best password we found with the given conditions : \""+str(bestPassword)+"\". His mark is "+str(noteMax)+"/5.0")
except UnicodeEncodeError:
    word = ""
    for i in range(len(bestPassword)):
        if (ord(bestPassword[i]) > 255):
            word += '?'
        else:
            word += bestPassword[i]
    print("Here is the best password we found with the given conditions : \""+str(word)+"\". His mark is "+str(noteMax)+"/5.0")
    del(word)
del(bestPassword)
print("Keep in mind that those marks don't depend of the lenght of your password neither of the range of characters you choosed.")