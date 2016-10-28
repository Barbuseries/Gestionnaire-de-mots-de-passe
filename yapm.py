#!/usr/bin/python3
# -*- coding: utf-8 -*-

from user_identification import *
from enum import Enum

class CategoryStatus(Enum):
    do_not_exist = 0
    exist = 1
    inaccessible = 2

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
    
# FIXME: RSA encryption returns a filename way too long.
#        Find shorter way of encrypting.
#        See int_to_cust and cust_to_int in user_identification.py.
# TODO: Generate dummy files as well.
def create_category(name, public_key, encryt_filename = False):
    if (not(get_file_from_category(name, public_key) is None)):
        return False, CategoryStatus.exist
    
    if (encryt_filename):
        final_name = int_to_cust(int(public_encrypt(public_key, name), 16))
    else:
        final_name = name

    try:
        file_path = os.path.join(YAPM_FILE_DB, "." + final_name)
        
        with open(file_path, "w+") as category:
            # TODO: Change check to just be name? (+ seed)
            dummy_file = name + "__dummy:0"
            enc_check = public_encrypt(public_key, dummy_file)
            category.write(enc_check + "\n")

        os.system("ln -s " + file_path + " " + name)

        return True, CategoryStatus.exist
    except Exception as e:
        return False, CategoryStatus.inaccessible

def delete_category(name, public_key):
    file_path = get_file_from_category(name, public_key)

    if (file_path is None):
        return False, CategoryStatus.do_not_exist

    try:
        os.remove(file_path)
        os.remove(name)
    except:
        return False, CategoryStatus.inaccessible
    
    return True, CategoryStatus.do_not_exist
    

if __name__ == "__main__":
    if (not(check_platform(["posix"]))):
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
    user_id_group.add_argument("--dump-categories", dest="dump_categories", action="store_const",
                        const=True,
                        help='Display all user\'s categories and exit.')
    user_id_group.add_argument("-k", "--stop-session", dest="disconnect", action="store_const",
                        const=True,
                        help='Stop current user session and exit.')
    
    
    category_modif_group = parser.add_argument_group("Category modification", "Options related to category modification.")
    category_modif_group.add_argument("-n", "--new-category", metavar="CATEGORY", dest="new_categories", type=str, nargs='+',
                                      help="Create CATEGORY if it does not already exist.")
    category_modif_group.add_argument("-e", "--encrypt-filename", dest="encrypt_filename", action="store_const",
                                      const=True,
                                      help='Encrypt filename when creating category.')
    category_modif_group.add_argument("-d", "--delete-category", metavar="CATEGORY", dest="delete_categories", type=str, nargs='+',
                                      help="Delete CATEGORY if it exists.")
    
    args = parser.parse_args()

    # user_id_group options checking
    if (args.disconnect):
        disconnect_current_user()
        quit()
    
    if (not(args.new_user is None)):
        new_user = args.new_user[0]
        
        prompt_create_new_user(new_user)
        quit()

    time_limit = 0

    if (not(args.time is None)):
        if (check_platform(["posix"], "ignored: -t|--time: only supported on linux.")):
            time_limit = args.time[0]

            if (time_limit < 0):
                print("error: -t|--time: TIME must be positive.")
                quit()
            disconnect_current_user()

    
    if (not(args.user is None)):
        disconnect_current_user()

        if (not(connect_as_user(args.user[0], time_limit))):
            print("Access denied.")
            quit()

    if (args.dump_user_info):
        dump_user_info()
        quit()

    if (args.dump_categories):
        dump_user_categories()
        quit()

    public_key = revive_current_user_if_needed(time_limit)

    # category_modif_group option checking    
    if (not(args.new_categories is None)):
        encrypt_filename = False
        if (args.encrypt_filename):
            encrypt_filename = True
        for category in args.new_categories:
            success, status = create_category(category, public_key, encrypt_filename)
            
            if (not(success)):
                eprint("Failed to create category '%s': " % category, end="")
                
                if (status == CategoryStatus.exist):
                    eprint("already exists.", prog_name=False)
                else:
                    eprint("could not access database.", prog_name=False)


    if (not(args.delete_categories is None)):
        for category in args.delete_categories:
            success, status = delete_category(category, public_key)
            
            if (not(success)):
                eprint("Failed to delete category '%s': " % category, end="")
                
                if (status == CategoryStatus.do_not_exist):
                    eprint("does not exist.", prog_name=False)
                else:
                    eprint("could not access database.", prog_name=False)
