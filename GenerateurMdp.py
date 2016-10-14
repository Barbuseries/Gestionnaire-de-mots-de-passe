import argparse
import random
import math

def testPass(key,value = False):
    typeOfChar = [False for i in range(5)]
    nchars = 0
    solo = ""
    for i in key:
        if (i >= chr(65) and i <= chr(90)):
            typeOfChar[0] = True
        elif (i >= chr(97) and i <= chr(122)):
            typeOfChar[1] = True
        elif (i >= chr(48) and i <= chr(57)):
            typeOfChar[2] = True
        elif (i >= chr(192)):
            typeOfChar[3] = True
        else:
            typeOfChar[4] = True
        if not i in solo:
            solo += i
    if typeOfChar[0] == True:
        nchars += 26
    if typeOfChar[1] == True:
        nchars += 26
    if typeOfChar[2] == True:
        nchars += 10
    if typeOfChar[3] == True:
        nchars += 64
    if typeOfChar[4] == True:
        nchars += 96
    if not value:
        print(int(math.log(nchars ** len(solo),2)) + 1 >= (int(math.log(222 ** len(key),2)) + 1)*0.95)
        return(int(math.log(nchars ** len(solo),2)) + 1 >= (int(math.log(222 ** len(key),2)) + 1)*0.95)
    return(int(math.log(nchars ** len(solo),2)) + 1)

def newPass(length, upperCase, lowerCase, number, accentMark, special, duplicate):
    characters = [i for i in range(33,256) if not ((i >= 127 and i <= 160) or i == 173)]
    
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
        alea = random.randint(0,len(characters)-1)
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
parser.add_argument("-t", "--testPassword", dest = "testPassword", type = str, nargs = "?", help = "The given password security will be tested then the program will quit")

args = parser.parse_args()

if (args.upperCase == None and args.lowerCase == None and args.number == None and args.special == None and args.accentMark == None):
    args.upperCase, args.lowerCase, args.number, args.special, args.accentMark = True, True, True, True, True

if (args.testPassword != None):
    print("The entropy of your password is 2 ^",testPass(args.testPassword,True))
    exit()

newPassword = newPass(args.length, args.upperCase, args.lowerCase, args.number, args.accentMark, args.special, args.duplicate)
compteur = 0
while (testPass(newPassword)):
    newPassword = newPass(args.length, args.upperCase, args.lowerCase, args.number, args.accentMark, args.special, args.duplicate)
    print(newPassword)
    compteur += 1
print(testPass(newPassword,True))
print(compteur)
#for i in range(100):
#    if (testPass(newPassword)):
#        print(newPassword)
#        exit()
#print("Il est difficile de créer un mot de passe sécurisé avec ces paramètres veuillez réessayer")



    
