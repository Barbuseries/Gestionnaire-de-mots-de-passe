#!/usr/bin/python3
# -*- coding: utf-8 -*-

import os
import sys
import shutil
import bcrypt
import getpass
import argparse
import time
import random
import math
import subprocess
import datetime
import base64
import hashlib
from struct import pack
from Crypto.Cipher import *
from Crypto.PublicKey import RSA
from Crypto.Hash import HMAC, SHA256
import Crypto.Util.number as CUN
from ast import literal_eval as make_tuple

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
#       - Connecting as user
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
YAPM_USER_CATEGORIES_DIRECTORY = os.path.join(YAPM_DIRECTORY, ".categories")

# NOTE + TODO: Right now, directory is not used anymore:
#              Plain-text category names are files in YAPM_USER_CATEGORIES_DIRECTORY.
#              Should we keep directory, revert, find a better way?
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

# NOTE: Time to wait after user enters wrong login/password.
ACCESS_DENIED_WAIT_DELAY = 1.5;

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

def confirm_password(test_pwd, input_text = "Confirm password:"):
    confirm_pwd = getpass.getpass(input_text)
    
    if (confirm_pwd != test_pwd):
        eprint("passwords do not match.")
        return False
    
    return True

def enter_password_and_confirm(input_text = "Password:", confirm_input_text = "Confirm password:"):
    test_pwd = getpass.getpass(input_text)

    if (confirm_password(test_pwd, confirm_input_text)):
        return test_pwd
    
    return None

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

# TODO: Should both of them have the same salt?
def password_hash(password, salt = b'salt'):
    return hashlib.pbkdf2_hmac('sha256',
                               password_key(password, salt),
                               salt,
                               100000).hex()

def password_keyhash(password_key, salt = b'salt'):
    return hashlib.pbkdf2_hmac('sha256',
                               password_key,
                               salt,
                               100000).hex()
        
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

# TODO?: Allow empty logins/passwords.
def prompt_user(login = None):
    if (login is None):
        login = input("Login: ")
    password = getpass.getpass()

    if ((len(login) == 0) or
        (len(password) == 0)):
        return False, None, None

    registered, user_line = user_already_registered(login)

    if (registered):
        salt, pwd_keyhash = user_line.split(b"$")[1:]
        return (password_hash(password, salt).encode() == pwd_keyhash) and registered, login, password
    
    return False, login, None

def prompt_new_user(login = None):
    if (login is None):
        login = input("Login: ")

    if (len(login) == 0):
        return False, None, None
        
    registered, user_line = user_already_registered(login)

    if (registered):
        return True, login, None

    password = enter_password_and_confirm();

    if ((password is None) or (len(password) == 0)):
        password = None

    return False, login, password

def prompt_create_new_user(login = None):
    already_registered, login, password = prompt_new_user(login)
    
    if (already_registered):
        print("User already registered.")
        return False
    
    if ((login is None) or (password is None)):
        print("Invalid indentifiers.")
        return False

    database = get_user_db("ab")
    database.seek(0, os.SEEK_SET)

    # TODO: Allow specification of salt's size.
    #       (But > 16 bytes)
    salt = os.urandom(16).hex().encode()

    # TODO?: Allow specification of algorithm used?
    pwd_hash = password_hash(password, salt).encode()

    user_line = login.encode() + b":$" + salt + b"$" + pwd_hash;

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

def get_category_from_file(filename, private_key):
    category = filename
            
    if (category.startswith(".")):
        category = filename[1:]
                
    dummy_check = get_file_dummy_check(filename, YAPM_FILE_DB)

    if (dummy_check is None):
        return None

    # NOTE: Should not be useful anymore as filename are encrypted
    # anyway.
    # # NOTE: First check if filename as is.
    # if (check_dummy_check(category, dummy_check, private_key.publickey())):
    #     return category

    # NOTE: Check decrypted filename.
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
    if not os.path.exists(YAPM_USER_CATEGORIES_DIRECTORY):
        os.makedirs(YAPM_USER_CATEGORIES_DIRECTORY)
    for root, dirs, files in os.walk(YAPM_FILE_DB):
        for f in files:
            category = get_category_from_file(f, private_key)
            
            if (category != None):
                file_path = os.path.join(root, f)
                open(os.path.join(YAPM_USER_CATEGORIES_DIRECTORY, category), "w+").close()
                # shutil.move(file_path, category)

def connect_as_user(login = None, time_limit = 0):
    valid_user, login, password = prompt_user(login)
    
    if (valid_user):
        key = generate_user_rsa(login, password)
        display_non_dummy_files(key)

        cookie = get_yapm_file(YAPM_CURRENT_USER_COOKIE, "wb+")

        current_time = time.time()
        
        toto = ""
        toto += "Login = " + login + "\n"
        toto += "Connexion timestamp = " + str(current_time) + "\n"
        
        if (time_limit > 0):
            toto += "Deconnexion timestamp = " + str(current_time + time_limit) + "\n"
            
        toto += "Directory = " + os.getcwd() + "\n"
        toto += key.publickey().exportKey().decode() + "\n"

        toto = toto.encode()

        # TODO: Allow specification of hash and sign algorithms.
        #       RSA for now.
        hash_toto = SHA256.new(toto).hexdigest().encode()

        # NOTE: For RSA only, K is not used.
        # K = CUN.getRandomNumber(128, os.urandom)
        K = ""
        
        # NOTE: For RSA only, signature is a 1 element tuple.
        signature = str(key.sign(hash_toto, K)).encode()

        cookie.write(b"Signature = " + signature + b"\n")
        cookie.write(toto + b"\n")        
        cookie.close()

        if (time_limit > 0):
            success_background_check = os.system("nohup sh -c 'sleep " + str(time_limit) + " && python3 user_identification.py -k' 2>/dev/null 1>/dev/null &")
            
            if (success_background_check != 0):
                eprint("Failed to start background session check.\nYou will not be disconnected automatically.")
        
        return True
    else:
        time.sleep(ACCESS_DENIED_WAIT_DELAY)
        
    return False

# Return decode content after start and before end (both excluding).
def get_string_after(byte_content, start, end = b"\n"):
    found = False
    result = None

    try:
        result = byte_content.split(start)[1].split(end)[0].decode()
        found = True;
    except:
        pass
        
    return result, found

# Return info on current user if its connexcion is still valid (hasn't
# run out of time, and its cookie hasn't been tampered with).
# Return Nones otherwhise.
def get_info_current_user():
    try:
        with open(YAPM_CURRENT_USER_COOKIE, "rb") as cookie:
            signature_tag = b"Signature = "
            signature = cookie.readline().split(signature_tag)[1][:-1];
            signature = make_tuple(signature.decode())
            
            content = cookie.read()[:-1]
            
            public_key_tag = (b"-----BEGIN PUBLIC KEY-----", b"-----END PUBLIC KEY-----")
            public_key = content.split(public_key_tag[0])[1].split(public_key_tag[1])[0]
            
            public_key = public_key_tag[0] + content.split(public_key_tag[0])[1].split(public_key_tag[1])[0] + public_key_tag[1]
            public_key = RSA.importKey(public_key)
            
            hash_toto = SHA256.new(content).hexdigest().encode()
            
            if (public_key.verify(hash_toto, signature)):
                login_tag = b"Login = "
                login = get_string_after(content, login_tag)[0]
                
                directory_tag = b"Directory = "
                directory = get_string_after(content, directory_tag)[0]
                
                connexion_timestamp_tag = b"Connexion timestamp = "
                connexion_timestamp = float(get_string_after(content, connexion_timestamp_tag)[0])
                
                deconnexion_timestamp = -1
                deconnexion_timestamp_tag = b"Deconnexion timestamp = "
                deconnexion_str, deconnexion_found = get_string_after(content, deconnexion_timestamp_tag)
                
                if (deconnexion_found):
                    deconnexion_timestamp = float(deconnexion_str)
                    
                    if (time.time() >= deconnexion_timestamp):
                        disconnect_user(True, directory, public_key)
                        return None, None, None, None, None
                    
                    pid = get_pid_background_session_check()
                    
                    if (len(pid) == 0):
                        print("WARNING:")
                        print("A background process (to check your session) has been killed suspiciously (i.e: not by me).")
                        print("If it's not your doing, make sure to disconnect manually.")
                        print("Otherwhise, files you own will still be visible")
                        print("until you run this program again (once the timer has run out).")
                        print("")
                        
                return login, connexion_timestamp, deconnexion_timestamp, directory, public_key
            else:
                os.remove(YAPM_CURRENT_USER_COOKIE)
                eprint("error: current user's cookie has been tampered with. Logging you out...")
    except:
        pass

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

    # user_categories = get_user_categories(key, directory)
    user_categories = get_user_categories(key, YAPM_USER_CATEGORIES_DIRECTORY)
    
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
    
    if (end_date != -1):
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

# NOTE: Replaced by signing and verifying.
# # NOTE: m must be a string.
# #       Return an hexadecimal string.
# def private_encrypt(private_key, m, encoding = "utf-8", byteorder = "little"):
#     return hex(private_key.decrypt(int.from_bytes(m.encode(encoding), byteorder=byteorder)))

# # NOTE: enc_m must be an hexadecimal string.
# #       Return a string.
# #       Return None if enc_m can not be decrypted.
# def public_decrypt(public_key, enc_m, enc_m_len = None, encoding = "utf-8", byteorder = "little"):
#     try:
#         enc_m = int(enc_m, 16)

#         if (enc_m_len is None):
#             enc_m_len = math.ceil(math.log(enc_m, 2) / 8)

#         return public_key.encrypt(enc_m, 'x')[0].to_bytes(enc_m_len, byteorder=byteorder).decode(encoding).replace('\0', '')
#     except:
#         return None

# NOTE: Hide categories belonging to the current user.
# def hide_user_categories(public_key, directory):
    # user_categories = get_user_categories(public_key, directory, True)
    # shutil.rmtree(YAPM_USER_CATEGORIES_DIRECTORY)
    # for category in user_categories:
    #     try:
    #         # NOTE; Yes, this counts as hiding...
    #         os.remove(category)
    #     except:
    #         eprint("Failed to hide category '%s'." % os.path.basename(category))
def hide_user_categories():
    shutil.rmtree(YAPM_USER_CATEGORIES_DIRECTORY)

# NOTE: Assumes each file in directory may be a category. Tries to get
# a valid file for each one.
# Return categories belonging to the current user.
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
        # NOTE: In case previous session did not end as expected.
        hide_user_categories()
        
        if (not(connect_as_user(None, time_limit))):
            print("Access denied.")
            quit()
            
        public_key = get_public_key_current_user()

    return public_key

def disconnect_user(has_background_check, directory, public_key):
    if (not(public_key is None)):
        # TODO: Notify user and ask him to indicate the directory?
        if (directory is None):
            directory = os.getcwd()
            
        # hide_user_categories(public_key, directory)
        hide_user_categories()
        os.remove(YAPM_CURRENT_USER_COOKIE)

        if (has_background_check):
            try:
                pid = get_pid_background_session_check()
            
                os.system("kill " + pid + " 2>/dev/null 1>/dev/null")
            except:
                pass

def disconnect_current_user():
    # public_key = revive_current_user_if_needed()
    login, start_date, end_date, directory, public_key = get_info_current_user()
    
    disconnect_user(not(end_date is None), directory, public_key)
        

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
