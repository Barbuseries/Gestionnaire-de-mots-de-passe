#!/usr/bin/python3
# -*- coding: utf-8 -*-

import os
import sys
import shutil
import grp, pwd
import bcrypt
import getpass
import argparse
import time
import random
import math
import subprocess
import datetime
import base64
from struct import pack
from Crypto.Cipher import *
from Crypto.PublicKey import RSA
from Crypto.Hash import HMAC

# TODO:
#       - Put everything that can be reused for file encryption in another file and import.

# DONE (but still needing thoughts):
#       - Everything relies on the integrity of ~/.yapm/.user_cookie

# NOTE: Login process:
#       - Adding user:
#           - Login prompt
#           - Password prompt
#           - If login in user database,
#               - error
#           - Otherwhise, add login:$salt$key_derived_password
#       - Connecgting as user
#           - Login prompt
#           - Password prompt
#           - If not login in database
#               - error
#           - Get salt and key_derived_password
#           - If given password derived key + salt != key_derived_password + salt
#               - error
#           - Show user categories

# NOTE: How this is going to work:
#       - Each file is hidden (has a leading dot)
#       - Each user has a private key (derived from login and password)
#         and a public key (generated on creation from private key, stored with other user information, encrypted)
#       - When a user tries to connect:
#         - Check valid connexion
#         - Store plain public key in an hidden (for what it's worth...) file
#         - Use private key (currently public key is used) to try to decrypt every file
#         - If it works and there are not dummy files
#         - Create file in current directory (filename is the category)
#           => allow putting all files in a directory and using the
#           program anywhere on the system.
#         - ...
#         - (TODO) When user is done, use public key to rencrypt each file
#         - Add leading dot.
# Advantages:
#  - Can make dummy files
#  - Can encrypt filenames
#
# Drawbacks:
#  - Anybody can create a valid file when user is logged in.
#    (Spam weak)
#  TODO: - Use a database encrypted with 'private key' as symetric key to store user's files
#        - Need to ask user's password every time a file needs to be created

YAPM_USER_NAME = "yapm"
YAPM_DUMMY_CHECK = "__dummy:"
YAPM_DIRECTORY = os.path.join(os.path.expanduser("~"), ".yapm")
YAPM_USER_DB = os.path.join(YAPM_DIRECTORY, ".users")
YAPM_FILE_DB = os.path.join(YAPM_DIRECTORY, ".db")

# NOTE: cookie stores the following: (everything is accessible via get_info_current_user())
#       - User's login.
#       - Connexion date encrypted by the user's private key.
#       - Deconnexion date encrypted by the user's private key. (same
#         as above if there is no time limit)
#       - Current directory on connexion encrypted by the user's private key.
#       - User's public key.
YAPM_CURRENT_USER_COOKIE = os.path.join(YAPM_DIRECTORY, ".user_cookie")

# TODO: It may be more secure to store the pid at the process
# creation, in case someone has the idea to kill it and recreate one
# with a sleep of 10000000...
#       In that case, it may be better not to try to recreate it.
GET_PID_BACKGROUND_SESSION_CHECK_CMD = "ps aux | grep -E -e 'sleep .* user_identification.py -k' | grep -v 'grep' | awk '{print $2}'"

# FIXME: Temporary solution to have short enough filenames.
#        See int_to_cust and cust_to_int.
#        Current version returns a 169 chars string (max is 255).
#        Just need a baseXX encoder.
#        Other solution would be to use a hash. Dummy check would then be:
#          - Read first line and extract filename.
#          - Encrypt with public key and hash.
#          - Test equality.
#        Likewhise, finding file by category would be encrypt->hash =>
#        check exists + check is dummy.
FILENAME_VALID_CHARS = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ+-[].'
COUNT_FILENAME_VALID_CHARS = len(FILENAME_VALID_CHARS)

def eprint(*args, **kwargs):    
    if (kwargs.pop("prog_name", True)):
        print("%s: %s" % (os.path.basename(sys.argv[0]), *args), file=sys.stderr, **kwargs)
    else:
        print(*args, file=sys.stderr, **kwargs)

def check_platform(plats, message = "This platform is currently not supported!"):
    if (os.name not in plats):
        if (not(message is None)):
            eprint(message)
        return False
    
    return True

# FIXME: Replace this!
def int_to_cust(i):
    result = ''
    while i:
        result = FILENAME_VALID_CHARS[i % COUNT_FILENAME_VALID_CHARS] + result
        i = i // COUNT_FILENAME_VALID_CHARS
    if not result:
        result = FILENAME_VALID_CHARS[0]
    return result

def cust_to_int(s):
    result = 0
    for char in s:
        result = result * COUNT_FILENAME_VALID_CHARS + FILENAME_VALID_CHARS.find(char)
    return result

def get_pid_background_session_check():
    return subprocess.check_output(GET_PID_BACKGROUND_SESSION_CHECK_CMD, shell=True)[:-1].decode()

# NOTE: pad wth '#' until length of m is a multiple of s.
# If r, pad right, else, pad left.
def pad(m, s, r = True):
    m = "_" * (not(r)) +  m + "_" * (r)
    size_m = len(m)
    
    if (size_m % s):
        return (m * (r)) + '#' * (s * ((size_m // s) + 1) - size_m) + (m * (not(r)))
            
    return m

def unpad(m, r = True):
    if (r):
        start_pad = m.rfind("_");

        if (start_pad == -1):
            return m
        
        return m[:start_pad]

    start_pad = m.find("_");

    if (start_pad == -1):
        return m

    return m[(start_pad + 1):]
    
def touch_open(filename, *args, **kwargs):
    open(filename, "a").close()
    return open(filename, *args, **kwargs)

def get_yapm_file(filename, flags = "r", create_parent_dir = True):
    try:
        if (create_parent_dir and
            not(os.path.exists(YAPM_DIRECTORY))):
            os.makedirs(YAPM_DIRECTORY)
            
        return touch_open(filename, flags)
    except IOError:
        return None

def get_user_db(flags = "r", create_parent_dir = True):
    return get_yapm_file(YAPM_USER_DB, flags, create_parent_dir)
    
def dump_user_db():
    database = get_user_db("rb")

    for line in database:
        print(line)
    
    database.close()

def clear_user_db():
    if (os.path.exists(YAPM_USER_DB)):
        os.remove(YAPM_USER_DB)

def password_key(password, salt = b'salt'):
    return bcrypt.kdf(password = password.encode(),
                      salt = salt,
                      desired_key_bytes = 32,
                      rounds=100)
        
def user_already_registered(login):
    database = get_user_db("rb+")

    if (database is None):
        eprint("Can not access database.")
        return False

    all_lines = database.readlines()

    for line in all_lines:
        line = line[:-1].split(b":")

        if (len(line) != 2):
            continue

        if (line[0].decode() == login):
            return True, line[1]
        
    database.close()
    
    return False, None

# TODO: Allow empty logins/passwords?
def prompt_user(login = None):
    if (login is None):
        login = input("Login: ")
    password = getpass.getpass()

    if ((len(login) == 0) or
        (len(password) == 0)):
        return False, None, None

    registered, user_line = user_already_registered(login)

    if (not(registered)):
        return False, login, password

    salt, pwd_key = user_line.split(b"$")[1:]

    if (password_key(password, salt).hex().encode() == pwd_key):
        return registered, login, password
    
    return registered, None, None

def prompt_create_new_user(login = None):
    already_registered, login, password = prompt_user(login)
    
    if (already_registered):
        print("User already registered.")
        return False
    
    if (login == None):
        print("Invalid indentifiers.")
        return False

    database = get_user_db("ab")
    database.seek(0, os.SEEK_SET)

    # TODO: Allow specification of salt's size.
    salt = os.urandom(32).hex().encode()
    pwd_key = password_key(password, salt).hex().encode()

    user_line = login.encode() + b":$" + salt + b"$" + pwd_key;

    database.write(user_line)
    database.write(b'\n')
    database.close()
    
    return True

def generate_user_rsa(login, password):
    pwd_hash = HMAC.new(password.encode("utf-8")).digest()
    rng = PRNG(login.encode("utf-8") + pwd_hash)

    return RSA.generate(1024, rng)


def get_file_dummy_check(filename, directory = "."):
    try:
        file_path = os.path.join(directory, filename)
        
        with open(file_path, "r") as enc_file:
            first_line = enc_file.readline()[:-1]
        return first_line
    except:
        return None

def generate_dummy_check(filename, is_dummy = False):
    return filename + YAPM_DUMMY_CHECK + str(int(is_dummy))
    
def check_dummy_check(name_test, ref, public_key):
    # FIXME: Find a better check than filename + const. Could be
    # easily found by an outsider, knowing the public_key
    # (which is the point).
    enc_dummy_check = public_encrypt(public_key, generate_dummy_check(name_test))

    if (enc_dummy_check == ref):
        return name_test
    
def is_displayed_file_mine(possible_category, public_key):
    category_file = get_file_from_category(possible_category, public_key);

    if (category_file is None):
        return False
    
    dummy_check = get_file_dummy_check(category_file)

    if (dummy_check is None):
        return False

    return check_dummy_check(possible_category, dummy_check, public_key)

# TODO: Currently, filename is check as is then decrypted if no
#       corresponding category is found.  Should we just check
#       according to user's preferences?
def get_category_from_file(filename, private_key):
    category = filename
            
    if (category.startswith(".")):
        category = filename[1:]
                
    dummy_check = get_file_dummy_check(filename, YAPM_FILE_DB)

    if (dummy_check is None):
        return None

    # NOTE: First check if filename as is.
    if (check_dummy_check(category, dummy_check, private_key.publickey())):
        return category

    # NOTE: Finally, check decrypted filename.
    # FIXME: See int_to_cust and cust_to_int.
    category = hex(cust_to_int(category))
    category = private_decrypt(private_key, category)

    if (category is None):
        return None
    
    if (check_dummy_check(category, dummy_check, private_key.publickey())):
        return category
    
    return None

def get_file_from_category(name, public_key):
    file_path = os.path.join(YAPM_FILE_DB, "." + name)

    # TODO: Check if file is dummy.
    #       If it is, allow rewrite.
    if (os.path.exists(file_path)):
        return file_path

    enc_name = int_to_cust(int(public_encrypt(public_key, name), 16))
    file_path = os.path.join(YAPM_FILE_DB, "." + enc_name)

    # TODO: Same as above.
    if (os.path.exists(file_path)):
        return file_path

    return None

def display_non_dummy_files(private_key):
    for root, dirs, files in os.walk(YAPM_FILE_DB):
        for f in files:
            category = get_category_from_file(f, private_key)
            
            if (category != None):
                file_path = os.path.join(root, f)
                open(category, "w+").close();
                # shutil.move(file_path, category)

def connect_as_user(login = None, time_limit = 0):
    valid_user, login, password = prompt_user(login)
    
    if (valid_user):
        key = generate_user_rsa(login, password)
        display_non_dummy_files(key)

        cookie = get_yapm_file(YAPM_CURRENT_USER_COOKIE, "wb+")

        current_time = time.time()
        enc_login = private_encrypt(key, login)
        enc_current_time = private_encrypt(key, str(current_time))
        enc_disconnect_time = private_encrypt(key, str(current_time + time_limit))
        enc_current_dir = private_encrypt(key, os.getcwd())

        cookie.write((enc_login + "\n").encode())
        cookie.write((enc_current_time + "\n").encode())
        cookie.write((enc_disconnect_time + "\n").encode())
        cookie.write((enc_current_dir + "\n").encode())
        
        cookie.write(key.publickey().exportKey())
        
        cookie.close()

        if (time_limit > 0):
            success_background_check = os.system("nohup sh -c 'sleep " + str(time_limit) + " && python3 user_identification.py -k' 2>/dev/null 1>/dev/null &")
            
            if (success_background_check != 0):
                eprint("Failed to start background session check.\nYou will not be disconnected automatically.")
        
        return True

    return False

def get_info_current_user():
    enc_login = None
    enc_start_date = None
    enc_end_date = None
    enc_dir = None
    public_key = None
    
    try:
        with open(YAPM_CURRENT_USER_COOKIE, "rb") as cookie:
            enc_login = cookie.readline()
            enc_start_date = cookie.readline()
            enc_end_date = cookie.readline()
            enc_dir = cookie.readline()
            
            key = b""
            for l in cookie:
                key += l

        public_key = RSA.importKey(key)

        login = public_decrypt(public_key, enc_login)
        start_date = float(public_decrypt(public_key, enc_start_date))
        end_date = float(public_decrypt(public_key, enc_end_date))

        directory = public_decrypt(public_key, enc_dir)
        
        if (start_date != end_date):
            if (time.time() >= end_date):
                disconnect_user(start_date, end_date, directory, public_key)
                return None, None, None, None, None

            pid = get_pid_background_session_check()

            if (len(pid) == 0):
                print("WARNING:")
                print("A background process (to check your session) has been killed suspiciously (i.e: not by me).")
                print("If it's not your doing, make sure to disconnect manually.")
                print("Otherwhise, files you own will still be visible")
                print("until you run this program again (once the timer has run out).")
                print("")
        
        return login, start_date, end_date, directory, public_key
    except:
        return None, None, None, None, None

def get_start_date_current_user():
    login, start_date, end_date, directory, key = get_info_current_user()

    return start_date

def get_end_date_current_user():
    login, start_date, end_date, directory, key = get_info_current_user()

    return end_date

def get_directory_current_user():
    login, start_date, end_date, directory, key = get_info_current_user()

    return directory

def get_public_key_current_user():
    login, start_date, end_date, directory, key = get_info_current_user()

    return key

# TODO: Instead of multiple dump functions, just use one with multiple
# flags. 
def dump_user_categories(key = None, directory = None):
    if (key is None):
        login, start_date, end_date, directory, key = get_info_current_user()

    if (key is None):
        print("No user is logged in.")
        return

    user_categories = get_user_categories(key, directory)
    
    for category in user_categories:
        print(category)

def dump_user_info():
    login, start_date, end_date, directory, key = get_info_current_user()

    if (key is None):
        print("No user is logged in.")
        return

    print("Login: " + login)
    print("")
    print("Connected at: " + datetime.datetime.fromtimestamp(start_date).strftime('%H:%M:%S %Y-%m-%d'))
    
    if (start_date != end_date):
        print("Connected until: " + datetime.datetime.fromtimestamp(end_date).strftime('%H:%M:%S %Y-%m-%d'))
        print(str(math.floor(end_date - time.time())) + " seconds left")

    print("")
    print("Directory: " + directory)
    print("")
    print("Categories:")
    
    dump_user_categories(key, directory)
        
    print("")
    print("Public key:\n" + key.exportKey().decode())
    
    
# NOTE: m must be a string.
#       Return an hexadecimal string.
def public_encrypt(public_key, m, encoding = "utf-8", byteorder = "little"):
    return hex(public_key.encrypt(int.from_bytes(m.encode(encoding), byteorder=byteorder), 'x')[0])

# NOTE: enc_m must be an hexadecimal string.
#       Return a string.
#       Return None if enc_m can not be decrypted.
def private_decrypt(private_key, enc_m, enc_m_len = None, encoding = "utf-8", byteorder = "little"):
    try:
        enc_m = int(enc_m, 16)

        if (enc_m_len is None):
            enc_m_len = math.ceil(math.log(enc_m, 2) / 8)
        
        return private_key.decrypt(enc_m).to_bytes(enc_m_len, byteorder=byteorder).decode(encoding).replace('\0', '')
    except:
        return None

# NOTE: m must be a string.
#       Return an hexadecimal string.
def private_encrypt(private_key, m, encoding = "utf-8", byteorder = "little"):
    return hex(private_key.decrypt(int.from_bytes(m.encode(encoding), byteorder=byteorder)))

# NOTE: enc_m must be an hexadecimal string.
#       Return a string.
#       Return None if enc_m can not be decrypted.
def public_decrypt(public_key, enc_m, enc_m_len = None, encoding = "utf-8", byteorder = "little"):
    try:
        enc_m = int(enc_m, 16)

        if (enc_m_len is None):
            enc_m_len = math.ceil(math.log(enc_m, 2) / 8)

        return public_key.encrypt(enc_m, 'x')[0].to_bytes(enc_m_len, byteorder=byteorder).decode(encoding).replace('\0', '')
    except:
        return None

def hide_user_files(public_key, directory):
    user_categories = get_user_categories(public_key, directory, True)

    for category in user_categories:
        try:
            os.remove(category)
        except:
            eprint("Failed to hide category '%s'." % os.path.basename(category))

def get_user_categories(public_key, directory, full_path = False):
    user_categories = []

    for root, dirs, files in os.walk(directory):
        for f in files:
            if (is_displayed_file_mine(f, public_key)):
                if (full_path):
                    user_categories.append(os.path.join(root, f))
                else:
                    user_categories.append(f)
                    
    return user_categories
                    

def revive_current_user_if_needed(time_limit = 0):
    public_key = get_public_key_current_user()
    
    if (public_key is None):
        # TODO: Check if any file is still visible or find a way
        # to know if files still need to be hidden (file database, ...).
        if (not(connect_as_user(None, time_limit))):
            print("Access denied.")
            quit()

    return public_key

def disconnect_user(start_date, end_date, directory, public_key):
    if (not(public_key is None)):
        # TODO: Notify user and ask him to indicate the directory?
        if (directory is None):
            directory = os.getcwd()
            
        hide_user_files(public_key, directory)
        os.remove(YAPM_CURRENT_USER_COOKIE)

        if (start_date != end_date):
            try:
                pid = get_pid_background_session_check()
            
                os.system("kill " + pid + " 2>/dev/null 1>/dev/null")
            except:
                pass

def disconnect_current_user():
    # public_key = revive_current_user_if_needed()
    login, start_date, end_date, directory, public_key = get_info_current_user()
    
    disconnect_user(start_date, end_date, directory, public_key)
        

class PRNG(object):
    def __init__(self, seed):
        self.index = 0
        self.seed = seed
        self.buffer = b""

    def __call__(self, n):
        while (len(self.buffer) < n):
            self.buffer += HMAC.new(self.seed + pack("<I", self.index)).digest()
            self.index += 1

        result, self.buffer = self.buffer[:n], self.buffer[n:]
        return result
