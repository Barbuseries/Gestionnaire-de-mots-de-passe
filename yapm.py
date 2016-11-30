#!/usr/bin/python3
# -*- coding: utf-8 -*-
# PYTHON_ARGCOMPLETE_OK

import argcomplete
from user_identification import *
from enum import Enum

class CategoryStatus(Enum):
    do_not_exist = 0
    exist = 1
    inaccessible = 2

def is_arg_set(arg):
    return not(arg is None)

# FIXME: RSA encryption returns a filename way too long.
#        Find shorter way of encrypting.
#        See int_to_cust and cust_to_int in user_identification.py.
# TODO: Make final_name be dependent on password.
#       Generate dummy files as well.
def create_category(name, public_key, password, add_to_completion = True):
    if (not(get_file_from_category(name, public_key) is None)):
        return False, CategoryStatus.exist
    
    final_name = int_to_cust(int(public_encrypt(public_key, name), 16))

    try:
        file_path = os.path.join(YAPM_FILE_DB, "." + final_name)
        
        with open(file_path, "w+") as category:
            # TODO: Change check to juxst be name? (+ seed)            
            enc_check = public_encrypt(public_key, generate_dummy_check(name))
            category.write(enc_check + "\n")
            
            # # TODO: At least, add some salt.
            # category.write(password_hash(password) + "\n")

        open(os.path.join(YAPM_USER_CATEGORIES_DIRECTORY, name), "w+").close()

        return True, CategoryStatus.exist
    except Exception as e:
        return False, CategoryStatus.inaccessible

# TODO: Take password as parameter, or make name be dependent on
# password.
def delete_category(name, public_key):
    file_path = get_file_from_category(name, public_key)

    if (file_path is None):
        return False, CategoryStatus.do_not_exist

    try:
        os.remove(file_path)
        os.remove(os.path.join(YAPM_USER_CATEGORIES_DIRECTORY, name))
    except:
        return False, CategoryStatus.inaccessible
    
    return True, CategoryStatus.do_not_exist

# NOTE: Do not forget to close it.
# TODO: Take password as parameter, or make name be dependent on
# password.
def open_category(name, public_key, flags):
    file_path = get_file_from_category(name, public_key)
    
    if (file_path is None):
        eprint("Failed to access category '%s': does not exist." % name)
        return False, None
    
    encrypted_file = open(file_path, flags)
    # User ownership check.
    encrypted_file.readline()

    return True, encrypted_file

def CategoryCompleter(prefix, **kwargs):
    return (c for c in os.listdir(YAPM_USER_CATEGORIES_DIRECTORY))

# NOTE: pad wth '#' until length of m is a multiple of s.
# If r, pad right, else, pad left.
def pad(m, s, r = True, isBytes = False):
    if (not(isBytes)):
        m = "_" * (not(r)) + m + "_" * (r)
    else:
        m = b"_" * (not(r)) + m + b"_" * (r)
    size_m = len(m)
    
    if (size_m % s):
        if (not(isBytes)):
            return (m * (r)) + '#' * (s * ((size_m // s) + 1) - size_m) + (m * (not(r)))
        else:
            return (m * (r)) + b'#' * (s * ((size_m // s) + 1) - size_m) + (m * (not(r)))
            
    return m

def unpad(m, r = True, isBytes = False):
    if (r):
        if (not(isBytes)):
            start_pad = m.rfind("_")
        else:
            start_pad = m.rfind(b"_")

        if (start_pad == -1):
            return m
        
        return m[:start_pad]

    if (not(isBytes)):
        start_pad = m.find("_")
    else:
        start_pad = m.find(b"_")

    if (start_pad == -1):
        return m

    return m[(start_pad + 1):]

def get_line_enc_content(enc_line, pwd_key):
    fields = None
    enc = None
    dec = None

    try:
        enc_line = base64.b64decode(enc_line, altchars=b'-_')
                
        salt = enc_line[:AES.block_size]

        # FIXME: When setting a mode (and a salt), decrypting
        # does not yield the correct value.
        # enc = AES.new(pwd_key, AES.MODE_CBC, salt)
        # dec = AES.new(pwd_key, AES.MODE_CBC, salt)
        enc = AES.new(pwd_key)
        dec = AES.new(pwd_key)

        line = unpad(dec.decrypt(enc_line[AES.block_size:]), 16, isBytes = True)

        if (line.startswith(b"valid+")):
            fields = line.split(b"+")[1:]
    except:
        pass
    
    return fields, enc, dec

def main():
    if (not(check_platform(["posix", "nt"]))):
        quit()
        
    parser = argparse.ArgumentParser()
    
    user_id_group = parser.add_argument_group("User identification", "Options related to user identification.")
    user_id_group.add_argument("--add-user", metavar="USER", dest="new_user", type=str, nargs=1,
                               help="Add a new user and exit.")
    user_id_group.add_argument("-u", "--user", metavar="USER", dest="user", type=str, nargs=1,
                               help="Connect as user and exit.")
    user_id_group.add_argument("-t", "--time", metavar="TIME", dest="time", type=int, nargs=1,
                               help="Connect, indicate to stay logged in for TIME seconds and exit. (TIME >= 0, default 0 (no limit))")
    user_id_group.add_argument("--dump-user-info", dest="dump_user_info", action="store_const",
                               const=True,
                               help='Display all user-related information and exit.')
    user_id_group.add_argument("--show-categories", dest="show_categories", action="store_const",
                               const=True,
                               help='Display all user\'s categories and exit.')
    user_id_group.add_argument("-k", "--stop-session", dest="disconnect", action="store_const",
                               const=True,
                               help='Stop current user session and exit.')
    
    category_group = parser.add_argument_group("Categories", "Options related to categories.")
    category_group.add_argument("categories", metavar='CATEGORY', type=str, nargs='*',
                                help="Operate on CATEGORY").completer = CategoryCompleter
    category_group.add_argument("-c", "--create-category", dest="to_create",
                                action="store_const", const=True,
                                help="Create CATEGORY if it does not already exist.")
    # category_group.add_argument("-e", "--set-hidden", dest="hide", action="store_const",
    #                             const=True,
    #                             help='Do not add category to autocompletion.')
    category_group.add_argument("-d", "--delete-category", dest="to_delete",
                                action="store_const", const=True,
                                help="Delete CATEGORY if it exists.")
    category_group.add_argument('-w', '--show-category', dest='to_show',
                                action="store_const", const=True,
                                help='Display content of CATEGORY if it exists.')

    pairs_group = parser.add_argument_group("Pairs", "Options related to pairs.")
    pairs_group.add_argument('-s', '--set-pair', dest='set_pairs', metavar='KEY:VALUE', type=str, nargs='+',
                             help='Add a new KEY-VALUE pair in CATEGORY.')
    pairs_group.add_argument('-g', '--get-value', dest='get_pairs', metavar='KEY', type=str, nargs='+',
                             help='Get the VALUE from KEY.')
    pairs_group.add_argument('-r', '--remove-pair', dest='remove_pairs', metavar='KEY', type=str, nargs='+',
                             help='Remove the KEY-VALUE pair in CATEGORY.')

    argcomplete.autocomplete(parser)
    
    args = parser.parse_args()

    to_create = False
    to_delete = False
    to_show = False
    to_set = False
    to_get = False
    to_remove = False

    if (is_arg_set(args.to_create)):
        to_create = args.to_create

    if (is_arg_set(args.to_delete)):
        to_delete = args.to_delete

    if (is_arg_set(args.to_show)):
        to_show = True

    if (is_arg_set(args.set_pairs)):
        to_set = True

    if (is_arg_set(args.get_pairs)):
        to_get = True

    if (is_arg_set(args.remove_pairs)):
        to_remove = True
        
    # Default
    if (sum([to_create, to_delete, to_set, to_get, to_remove]) == 0):
        to_show = True

    # user_id_group options checking
    if (args.disconnect):
        disconnect_current_user()
        quit()
        
    if (is_arg_set(args.new_user)):
        new_user = args.new_user[0]
        
        prompt_create_new_user(new_user)
        quit()

    time_limit = 0

    if (is_arg_set(args.time)):
        if (check_platform(["posix"], "ignored: -t|--time: only supported on linux.")):
            time_limit = args.time[0]

            if (time_limit < 0):
                print("error: -t|--time: TIME must be positive.")
                quit()
            disconnect_current_user()

    
    if (is_arg_set(args.user)):
        disconnect_current_user()

        if (not(connect_as_user(args.user[0], time_limit))):
            print("Access denied.")
            quit()

    public_key = revive_current_user_if_needed(time_limit)

    if (args.dump_user_info):
        dump_user_info()
        quit()

    if (args.show_categories):
        dump_user_categories()
        quit()

    # category_modif_group option checking
    if (to_create):
        add_to_completion = True
        # if (args.hide):
        #     add_to_completion = False
        for category in args.categories:
            if (not(get_file_from_category(category, public_key) is None)):
                eprint("Failed to create category '%s': already exists." % category)
                continue

            category_pwd = enter_password_and_confirm(category + "'s password:")

            if (category_pwd is None):
                eprint("Failed to create category '%s': invalid password." % category)
                continue
            
            success, status = create_category(category, public_key, category_pwd)
            
            if (not(success)):
                eprint("Failed to create category '%s': could not access database." % category, end="")
                continue
                    
    if (to_delete):
        for category in args.categories:
            success, status = delete_category(category, public_key)
            
            if (not(success)):
                eprint("Failed to delete category '%s': " % category, end="")
                
                if (status == CategoryStatus.do_not_exist):
                    eprint("does not exist.", prog_name=False)
                else:
                    eprint("could not access database.", prog_name=False)

    # pairs_group option checking
    if (to_set):
        kv = [i.split(":") for i in args.set_pairs]

        result = []
        index = 0
        for i in kv:
            while ((len(i) < 2) or (i[1] == "")):
                i = [i[0], getpass.getpass(i[0] + ":")]

            if (len(i) > 2):
                eprint("Malformed KEY:VALUE pair '%s'." % ":".join(i))
            elif (i[0] == ""):
                eprint("VALUE '%s' is missing a KEY." % i[1])
            else:
                result.append(i)
                
            index += 1

        # FIXME: Current implementation does not allow salt!
        for category in args.categories:
            all_enc_pairs = {}
            all_old_lines = []
            
            success, encrypted_file = open_category(category, public_key, "r+b")

            if (not(success)):
                continue

            pwd_key = password_key(getpass.getpass(category + "'s password:"))

            for enc_line in encrypted_file:
                fields, enc, dec = get_line_enc_content(enc_line, pwd_key)
            
                if (not(fields) is None):
                    all_enc_pairs[fields[0]] = fields[1]
                else:
                    all_old_lines.append(enc_line)

            encrypted_file.seek(0, os.SEEK_SET)
            encrypted_file.readline()

            for l in all_old_lines:
                encrypted_file.write(l)

            salt = os.urandom(AES.block_size)
            
            enc = AES.new(pwd_key)
            
            for i in result:
                all_enc_pairs[enc.encrypt(pad(i[0], 16))] = enc.encrypt(pad(i[1], 16))

            for enc_k, enc_v in all_enc_pairs.items():
                line = pad(b"valid+" +
                           enc_k + b"+" + enc_v,
                           16, isBytes = True)
                
                enc_line = base64.b64encode(salt + enc.encrypt(line), altchars=b'-_')

                encrypted_file.write(enc_line + b"\n")

            if (encrypted_file):
                encrypted_file.close()
                
    if (to_show):
        for category in args.categories:
            success, encrypted_file = open_category(category, public_key, "rb")

            if (not(success)):
                continue
            else:
                pwd_key = password_key(getpass.getpass(category + "'s password:"))
                
                print("%s:" % category)
                for enc_line in encrypted_file:
                    fields, enc, dec = get_line_enc_content(enc_line, pwd_key)
                    if (not(fields) is None):
                        print("%s:%s" % (unpad(dec.decrypt(fields[0]), 16, isBytes = True).decode(),
                                         unpad(dec.decrypt(fields[1]), 16, isBytes = True).decode()))
                        
                if (encrypted_file):
                    encrypted_file.close()

    if (to_get):
        pass

    if (to_remove):
        pass

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("")
        pass
