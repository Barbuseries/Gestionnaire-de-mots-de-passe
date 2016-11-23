#!/usr/bin/python3
# -*- coding: utf-8 -*-

from user_identification import *
from enum import Enum

class CategoryStatus(Enum):
    do_not_exist = 0
    exist = 1
    inaccessible = 2

def is_arg_set(arg):
    return not(arg is None)

def confirm_password(test_pwd, input_text = "Confirm password:"):
    confirm_pwd = getpass.getpass(input_text)
    
    if (confirm_pwd != test_pwd):
        print("Passwords do not match.")
        return False
    
    return True

def enter_password_and_confirm(input_text = "Password:", confirm_input_text = "Confirm password:"):
    test_pwd = getpass.getpass(input_text)

    if (confirm_password(test_pwd, confirm_input_text)):
        return test_pwd
    
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
            # TODO: Change check to juxst be name? (+ seed)            
            enc_check = public_encrypt(public_key, generate_dummy_check(name))
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
    user_id_group.add_argument("--show-categories", dest="show_categories", action="store_const",
                        const=True,
                        help='Display all user\'s categories and exit.')
    user_id_group.add_argument("-k", "--stop-session", dest="disconnect", action="store_const",
                        const=True,
                        help='Stop current user session and exit.')
    
    category_group = parser.add_argument_group("Categories", "Options related to categories.")
    category_group.add_argument("-c", "--create-category", metavar="CATEGORY", dest="categories_to_create", type=str, nargs='+',
                                help="Create CATEGORY if it does not already exist.")
    category_group.add_argument("-e", "--encrypt-filename", dest="encrypt_filename", action="store_const",
                                const=True,
                                help='Encrypt filename when creating category.')
    category_group.add_argument("-d", "--delete-category", metavar="CATEGORY", dest="categories_to_delete", type=str, nargs='+',
                                help="Delete CATEGORY if it exists.")
    category_group.add_argument('-w', '--show-category', metavar="CATEGORY", dest='categories_to_show', type=str, nargs='+',
                                help='Display content of CATEGORY.')

    # TODO: Add specification of category.
    #       Or add a separate --category option. That may require some tweaks with the options above...
    pairs_group = parser.add_argument_group("Pairs", "Options related to pairs.")
    pairs_group.add_argument('-s', '--set-pair', dest='set_pairs', metavar='KEY:VALUE', type=str, nargs='+',
                             help='Add a new KEY-VALUE pair in CATEGORY.')
    pairs_group.add_argument('-g', '--get-value', dest='get_pairs', metavar='KEY', type=str, nargs='+',
                             help='Get the VALUE from KEY.')
    pairs_group.add_argument('-r', '--remove-pair', dest='remove_pairs', metavar='KEY', type=str, nargs='+',
                             help='Remove the KEY-VALUE pair in CATEGORY.')
    
    args = parser.parse_args()

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
    if (is_arg_set(args.categories_to_create)):
        encrypt_filename = False
        if (args.encrypt_filename):
            encrypt_filename = True
        for category in args.categories_to_create:
            # TODO: Do not create category if password inputing fails.
            success, status = create_category(category, public_key, encrypt_filename)
            
            if (not(success)):
                eprint("Failed to create category '%s': " % category, end="")
                
                if (status == CategoryStatus.exist):
                    eprint("already exists.", prog_name=False)
                else:
                    eprint("could not access database.", prog_name=False)
            else:
                category_pwd = enter_password_and_confirm(category + "'s password:")

                if (category_pwd is None):
                    delete_category(category, public_key)

    if (is_arg_set(args.categories_to_delete)):
        for category in args.categories_to_delete:
            success, status = delete_category(category, public_key)
            
            if (not(success)):
                eprint("Failed to delete category '%s': " % category, end="")
                
                if (status == CategoryStatus.do_not_exist):
                    eprint("does not exist.", prog_name=False)
                else:
                    eprint("could not access database.", prog_name=False)

    if (is_arg_set(args.categories_to_show)):
        for category in args.categories_to_show:
            file_path = get_file_from_category(category, public_key)

            if (file_path is None):
                eprint("Failed to display category '%s: does not exist." % category)
            else:
                print("%s:" % category)
                with open(file_path, "rb") as encrypted_file:
                    # User ownership check.
                    encrypted_file.readline()
                    
                    for line in encrypted_file:
                        print(line)
            

    if (is_arg_set(args.set_pairs)):
        kv = [i.split(":") for i in args.set_pairs]

        index = 0
        for i in kv:
            while ((len(i) < 2) or (i[1] == "")):
                i = [i, getpass.getpass(i[0] + ":")]

            if (len(i) > 2):
                eprint("Malformed KEY:VALUE pair '%s'." % ":".join(i))
                del kv[index]
            elif (i[0] == ""):
                eprint("VALUE '%s' is missing a KEY." % i[1])
                del kv[index]
                
            index += 1

            

    if (is_arg_set(args.get_pairs)):
        pass

    if (is_arg_set(args.remove_pairs)):
        pass
