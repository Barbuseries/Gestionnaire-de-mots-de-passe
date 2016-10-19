#!/usr/bin/python3
# -*- coding: utf-8 -*-

import os
import shutil
import grp, pwd
import bcrypt
import getpass
import argparse
import time
import random
import math
from struct import pack
from Crypto.Cipher import *
from Crypto.PublicKey import RSA
from Crypto.Hash import HMAC

# TODO: - Add login time limit (See python-crontab? https://pypi.python.org/pypi/python-crontab)
#       - Should files all be in one directory and when a user is
#         logged in, each file in it's current directory is just a
#         symlink?

# NOTE: How this is going to work:
#       - Each file is hidden (has a leading dot)
#       - Each user has a private key (derived from login and password)
#         and a public key (generated on creation from private key, stored with other user information, encrypted)
#       - When a user tries to connect:
#         - Check valid connexion
#         - Store plain public key in an hidden (for what it's worth...) file
#         - Use private key (currently public key is used) to try to decrypt every file
#         - If it works and there are not dummy files
#         - Remove leading dot. TODO?: Instead, create symlink to file
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

# NOTE: cookie stores the following: (everything is accessible via get_info_current_user())
#       - Connexion date encrypted by the user's private key.
#       - Current directory on connexion encrypted by the user's private key.
#       - User's public key.
YAPM_CURRENT_USER_COOKIE = os.path.join(YAPM_DIRECTORY, ".user_cookie")

if (os.name != "nt") and (os.name != "posix"):
    print("This platform is not currently supported!")
    quit()

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
        
def user_already_registered(login, password):
    database = get_user_db("rb+")

    if (database is None):
        print("Can not access database.")
        return False

    all_lines = database.readlines()

    for line in all_lines:
        line = line[:-1].split(b"$")
        salt = b'salt'
        b_rest_line = b''.join(line)

        pwd_key = password_key(password, salt)
        pwd_enc = AES.new(pwd_key)
        decrypted_login = unpad(pwd_enc.decrypt(b_rest_line).decode(errors="ignore"))

        if (login == decrypted_login):
            return True, pwd_enc
        
    database.close()
    
    return False, None

# TODO: Allow empty logins/passwords?
def prompt_user(login = None):
    if (login is None):
        login = input("Login: ")
    password = getpass.getpass()

    if ((len(login) == 0) or
        (len(password) == 0)):
        return False, None, None, None

    valid, enc = user_already_registered(login, password)
    return valid, enc, login, password

def prompt_create_new_user(login = None):
    already_registered, enc, login, password = prompt_user(login)
    
    if (already_registered):
        print("User already registered.")
        return False
    
    if (login == None):
        print("Invalid indentifiers")
        return False

    database = get_user_db("ab")
    database.seek(0, os.SEEK_SET)

    # TODO: Use real salt and save it somewhere.
    salt = b'salt'
    password_key(password, salt)

    pwd_key = password_key(password)
    
    pwd_enc = AES.new(pwd_key)
    encrypted_login = pwd_enc.encrypt(pad(login, 16))

    database.write(encrypted_login)
    database.write(b'\n')
    database.close()
    
    return True

def generate_user_rsa(login, password):
    pwd_hash = HMAC.new(password.encode("utf-8")).digest()
    rng = PRNG(login.encode("utf-8") + pwd_hash)

    return RSA.generate(1024, rng)


def get_file_dummy_check(filename):
    try:
        with open(filename, "r") as enc_file:
            first_line = enc_file.readline()[:-1]
        return first_line
    except:
        return None

def check_dummy_check(name_test, ref, public_key):
    # FIXME: Find a better check than filename + const. Could be
    # easily found by an outsider, knowing the public_key
    # (which is the point).
    check = name_test + YAPM_DUMMY_CHECK
    enc_dummy_check = public_encrypt(public_key, check + "0")
        
    if (enc_dummy_check == ref):
        return name_test
    
def is_displayed_file_mine(filename, public_key):
    dummy_check = get_file_dummy_check(filename)

    if (dummy_check is None):
        return False

    return check_dummy_check(filename, dummy_check, public_key)

# TODO: Currently, filename is check as is then decrypted if no
#       corresponding category is found.  Should we just check
#       according to user's preferences?
def get_category(filename, private_key):
    category = filename
            
    if (category.startswith(".")):
        category = filename[1:]
                
    dummy_check = get_file_dummy_check(filename)

    if (dummy_check is None):
        return None

    # NOTE: First check if filename as is.
    if (check_dummy_check(category, dummy_check, private_key.publickey())):
        return category

    # NOTE: Finally, check decrypted filename.
    category = private_decrypt(private_key, category)

    if (category is None):
        return None
    
    if (check_dummy_check(category, dummy_check, private_key.publickey())):
        return category
    
    return None

def display_non_dummy_files(private_key):
    for root, dirs, files in os.walk(os.getcwd()):
        for f in files:
            category = get_category(f, private_key)
            
            if (category != None):
                file_path = os.path.join(root, f)
                shutil.move(file_path, category)
                

def connect_as_user(login = None):
    valid_user, enc, login, password = prompt_user(login)
    
    if (valid_user):
        key = generate_user_rsa(login, password)
        display_non_dummy_files(key)

        cookie = get_yapm_file(YAPM_CURRENT_USER_COOKIE, "wb+")
        
        enc_current_time = private_encrypt(key, str(time.time()))
        enc_current_dir = private_encrypt(key, os.getcwd())
        
        cookie.write((enc_current_time + "\n").encode())
        cookie.write((enc_current_dir + "\n").encode())
        
        cookie.write(key.publickey().exportKey())
        
        cookie.close()
        
        return True

    return False

def get_info_current_user():
    enc_date = None
    enc_dir = None
    public_key = None
    
    try:
        with open(YAPM_CURRENT_USER_COOKIE, "rb") as cookie:
            enc_date = cookie.readline()
            enc_dir = cookie.readline()
            
            key = b""
            for l in cookie:
                key += l

        public_key = RSA.importKey(key)

        return public_decrypt(public_key, enc_date), public_decrypt(public_key, enc_dir), public_key
    except:
        return None, None, None

def get_date_current_user():
    date, directory, key = get_info_current_user()

    return date

def get_directory_current_user():
    date, directory, key = get_info_current_user()

    return directory

def get_public_key_current_user():
    date, directory, key = get_info_current_user()

    return key


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
    for root, dirs, files in os.walk(directory):
        for f in files:
            # f_path = os.path.join(root, f)
            
            if (is_displayed_file_mine(f, public_key)):
                # TODO: f may need to be encrypted (with public_key).
                category_path = os.path.join(root, f)
                encrypted_filename_path = os.path.join(root, "." + f)

                shutil.move(category_path, encrypted_filename_path)

def revive_current_user_if_needed():
    public_key = get_public_key_current_user()
    
    if (public_key is None):
        # TODO: Check if any file is still visible or find a way
        # to know if files still need to be hidden (file database, ...).
        if (not(connect_as_user())):
            print("Access denied.")
            quit()

    return public_key
                
def disconnect_current_user():
    # public_key = revive_current_user_if_needed()
    date, directory, public_key = get_info_current_user()
    
    if (not(public_key is None)):
        if (directory is None):
            directory = os.getcwd()
            
        hide_user_files(public_key, directory)
        os.remove(YAPM_CURRENT_USER_COOKIE)

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
    
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="User authentification parser.")
    parser.add_argument("--add-user", metavar="USER", dest="new_user", type=str, nargs=1,
                        help="Add a new user and exit.")
    parser.add_argument("-u", "--user", metavar="USER", dest="user", type=str, nargs=1,
                        help="Connect as user and exit.")
    parser.add_argument("-k", "--stop-session", dest="disconnect", action="store_const",
                        const=True,
                        help='Stop current user session and exit.')

    args = parser.parse_args()

    if (args.disconnect):
        disconnect_current_user()
        quit()
    
    if (not(args.new_user is None)):
        new_user = args.new_user[0]
        
        prompt_create_new_user(new_user)
        quit()
        
    if (not(args.user is None)):
        disconnect_current_user()

        if (not(connect_as_user(args.user[0]))):
            print("Access denied.")
            quit()

    public_key = revive_current_user_if_needed()

    ## TODO: Uncomment below when user/group is done.
    # all_users = [p.pw_name for p in pwd.getpwall()]
    
    # if (not(YAPM_USER_NAME) in all_users):
    #     print("Yapm user needs to be present.")
    #     quit()

    
    ## Generate (non-)dummy files.
    # login = "login"
    # password = "toto"
    
    # key = generate_user_rsa(login, password)

    # public_key = key.publickey()

    # all_files = ["toto", "tata"]

    # for f in all_files:
    #     with open(f, "w+") as toto:
    #         is_dummy = str(random.getrandbits(1))
    #         dummy_file = f + "__dummy:" + is_dummy
    #         print(dummy_file)
    #         enc_mess = public_encrypt(public_key, dummy_file)
    #         toto.write(enc_mess + "\n")
