# coding: utf-8

import argparse
from random import SystemRandom
import math
import sys
import getpass

# We set a new random system
cryptogen = SystemRandom()
"""
Usage :
    newDico() will create a dictionnary of dictionnarys of lists of strings (pretty simple isn't it ? But it is necessary and efficient). Where words are sorted by         their first two characters.
    Exemple with two words 'AABCDE','AARTYH' : 
    {'A':{'A':['AABCDE','AARTYH'],'B':...},'B':...,'C':...}
    There is only upper cases and 6168039 different words and common password from 10 different countries.
    This function is pretty slow but have to be used one time at every use of the program.

Parameters :
    No parameter

Return : 
    A dictionnary of dictionnaries of lists of strings
"""
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

"""
Usage :
    testDico(word, dico) will return a mark from 0 to 5.
    If the word is in the dictionnary "dico" then the mark will be 0.
    The less the word looks like a string of the dictionnary the better the mark will be.

Parameters :
    word = string (this is the word tested in the dictionnary)
    dico = a dictionnary of dictionnaries of lists of strings (The dictionnary in which the word will be tested)

Return : 
    Float (between 0 and 5)
"""    
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

"""
Usage :
    callDico(word, dico, i, j) will return True if the part of word between the character i and the character j is in the list of the dictionnary corresponding to the first two characters of the part of the word tested.

Parameters :
    word = string (this is the word tested in the dictionnary)
    dico = dictionnary of dictionnaries of lists of strings (The dictionnary in which the word will be tested)
    i = integer (corresponding to the first character of the part of word tested)
    j = integer (corresponding to the last character of the part of word tested)

Return : 
    Boolean
"""   
def callDico(word, dico, i, j):
    if word[i:j] in dico[ord(word[i])][ord(word[i+1])]:
        del(word)
        return True
    del(word)
    return False
    
"""
Usage :
    passwordEntropy(key,characterRange) will return a mark from 0 to 5.
    This mark will be baad if the characters of key are too close to each other.
    Exemple :
        -'123' will have a bad mark
        -'925' will have a good mark
    The mark depends of the range of character used
    Exemple :
        -'925' will have a good mark because the characters looks differents using only numbers
        -'AAzz99' will have a bad mark because even if the password is in fact probably safer than '925' the characters are too close to each other. Regardless of the length of the password.
    
    An other usage is to get the range of character used by the string key by setting characterRange to True.

Parameters :
    key =  string (this is the word tested)
    characterRange = boolean (False by default)

Return : 
    Float (from 0 to 5)
    Or Integer (If characterRange is set to True)
""" 
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

"""
Usage :
    newPass(length, upperCase, lowerCase, number, accentMark, special, duplicate): will create a new password

Parameters :
    length = integer (gives the length of the password)
    upperCase = boolean (if set will allow upper cases in the password)
    lowerCase = boolean (if set will allow lower cases in the password)
    number = boolean (if set will allow numbers in the password)
    accentMark = boolean (if set will allow characters with accent marks in the password)
    special = boolean (if set will allow special characters in the password)
    duplicate = boolean (if set will forbid duplicates in the password)

Return : 
    String (the password created)
""" 
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
        print("Not enought characters to avoid duplicate")
        exit()
    
    password = ""
    for i in range(length):
        alea = cryptogen.randrange(len(characters))
        password += chr(characters[alea])
        if (duplicate == True):
            del characters[alea]
    return password


# Here we set the parser and all the arguments
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

# By default we allow every characters in the password
if (args.upperCase == None and args.lowerCase == None and args.number == None and args.special == None and args.accentMark == None):
    args.upperCase, args.lowerCase, args.number, args.special, args.accentMark = True, True, True, True, True

# If no password is given when the user ask to test his password, then we ask for the password which will be hiden
if (args.testPassword == ""):
    args.testPassword = getpass.getpass()

# We create a new dico in any case
dico = newDico()

# If we are testing a password:
if (args.testPassword != None):
    # We calculate the marks and print the results 
    noteDico = round(testDico(args.testPassword,dico),2)
    noteEntropy = round(passwordEntropy(args.testPassword),2)
    print("Your password marks are "+str(noteEntropy)+"/5.0 for the entropy, "+str(noteDico)+"/5.0 for the dictionnary attack which gives "+str(round(noteEntropy/2 + noteDico/2,2))+"/5.0 as a total. Keep in mind that those marks don't depend of the length of your password neither of the range of characters you choosed.")
    if (len(args.testPassword)<8):
        print("We must warn you that choosing a password with less than 8 characters is not recommended.")
    range = passwordEntropy(args.testPassword,True)
    if (range<62):
        print("We must warn you that choosing a password with a range of characters of less than 62 is not recommended. You are currently using a range of "+str(range)+" characters.")
    del(args.testPassword)
    # Then the program end here
    exit()

# If we are creating a new password
newPassword = newPass(args.length, args.upperCase, args.lowerCase, args.number, args.accentMark, args.special, args.duplicate)
noteMax = 0
# We create 1000 different passwords and we keep the best one
for i in range(1000):
    noteEntropy = passwordEntropy(newPassword)
    noteDico = testDico(newPassword,dico)
    note = noteEntropy/2 + noteDico/2
    if (note > noteMax):
        noteMax = note
        bestPassword = newPassword
    newPassword = newPass(args.length, args.upperCase, args.lowerCase, args.number, args.accentMark, args.special, args.duplicate)
noteMax = round(noteMax,8)

# We try to print the results (some shells can't print every characters)
try:
    print("Here is the best password we found with the given conditions : \""+str(bestPassword)+"\". His mark is "+str(noteMax)+"/5.0")
except UnicodeEncodeError:
    # If the shell can't print the password then we replace every problematic characters by '?' and we print the results
    word = ""
    for i in range(len(bestPassword)):
        if (ord(bestPassword[i]) > 255):
            word += '?'
        else:
            word += bestPassword[i]
    print("Here is the best password we found with the given conditions : \""+str(word)+"\". His mark is "+str(noteMax)+"/5.0")
    del(word)
del(bestPassword)
print("Keep in mind that those marks don't depend of the length of your password neither of the range of characters you choosed.")