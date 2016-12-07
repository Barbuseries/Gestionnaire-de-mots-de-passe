#!/usr/bin/python3
# -*- coding: utf-8 -*-
# PYTHON_ARGCOMPLETE_OK

import argcomplete
from user_identification import *
from enum import Enum
from collections import OrderedDict

# TODO?: Instead of just saving hash of password key, create
#        public/private RSA keys to sign file.

class CategoryStatus(Enum):
    do_not_exist = 0
    exist = 1
    inaccessible = 2

class PairStatus(Enum):
    same_as_before = -1
    public = 0
    private = 1

def is_arg_set(arg):
    return not(arg is None)

# FIXME: RSA encryption returns a filename way too long.
#        Find shorter way of encrypting.
#        See int_to_cust and cust_to_int in user_identification.py.
# TODO:  Generate dummy files as well.
def create_category(name, public_key, password, add_to_completion = True):
    if (not(get_file_from_category(name, public_key) is None)):
        return False, CategoryStatus.exist
    
    final_name = int_to_cust(int(public_encrypt(public_key, name), 16))

    try:
        file_path = os.path.join(YAPM_FILE_DB, "." + final_name)

        # TODO: Change check to just be name? (+ seed)
        enc_check = public_encrypt(public_key, generate_dummy_check(name))
    
        with open(file_path, "wb+") as category:
            category.write(enc_check.encode() + b"\n")
        
            salt = os.urandom(16).hex().encode()
            pwd_keyhash = password_hash(password, salt)
            category.write(salt + b"$" + pwd_keyhash.encode() + b"\n")

        open(os.path.join(YAPM_USER_CATEGORIES_DIRECTORY, name), "w+").close()

        return True, CategoryStatus.exist
    except Exception as e:
        return False, CategoryStatus.inaccessible

def delete_category(name, public_key):
    file_path = get_file_from_category(name, public_key)

    if (file_path is None):
        return False, CategoryStatus.do_not_exist

    try:
        os.remove(file_path)
        
        categoryname_path = os.path.join(YAPM_USER_CATEGORIES_DIRECTORY, name)
        
        if (os.path.exists(categoryname_path)):
            os.remove(categoryname_path)
    except:
        return False, CategoryStatus.inaccessible
    
    return True, CategoryStatus.do_not_exist

# NOTE: Do not forget to close it.
def open_category(name, public_key, flags):
    file_path = get_file_from_category(name, public_key)
    
    if (file_path is None):
        eprint("failed to access category '%s': does not exist." % name)
        return False, None, None
    
    encrypted_file = open(file_path, flags)
    # User ownership check.
    encrypted_file.readline()
    
    salt, pwd_keyhash = encrypted_file.readline()[:-1].split(b"$")
    pwd_key = password_key(getpass.getpass(name + "'s password:"), salt)

    if (password_keyhash(pwd_key, salt).encode() == pwd_keyhash):
        return True, encrypted_file, pwd_key

    print("Access denied.")
    return False, None, None

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
            start_pad = m.rfind("_#")
        else:
            start_pad = m.rfind(b"_#")

        if (start_pad == -1):
            return m

        return m[:start_pad]

    if (not(isBytes)):
        start_pad = m.find("_#")
    else:
        start_pad = m.find(b"_#")

    if (start_pad == -1):
        return m

    return m[(start_pad + 1):]

def get_line_enc_content(enc_line, pwd_key):
    enc_k, enc_v, enc_t = None, None, None
    is_private = False
    enc = None
    dec = None

    try:
        enc_line = unpad(base64.b64decode(enc_line, altchars=b'-_'), isBytes = True)
                
        salt = enc_line[:AES.block_size]

        # FIXME: When setting a mode (and a salt), decrypting
        # does not yield the correct value.
        # enc = AES.new(pwd_key, AES.MODE_CBC, salt)
        # dec = AES.new(pwd_key, AES.MODE_CBC, salt)
        enc = AES.new(pwd_key)
        dec = AES.new(pwd_key)

        line = dec.decrypt(enc_line[AES.block_size:])

        if (line.startswith(base64.b64encode(b"valid") + b"$")):
            is_private = False
        elif (line.startswith(base64.b64encode(b"Valid") + b"$")):
            is_private = True
        else:
            return None, None, None, None, None, None
        
        fields = line.split(b"$")[1:]
        enc_k, enc_v = [base64.b64decode(f) for f in fields[:2]]
        enc_t = [base64.b64decode(f) for f in fields[2:]]
    except:
        pass
    
    return enc_k, enc_v, enc_t, is_private, enc, dec

def remove_duplicates(thing):
    if (not(thing) is None):
        thing = list(OrderedDict.fromkeys(thing))
    return thing

def copy_list(thing):
    if (not(thing) is None):
        return thing[:]
    return None

def encrypt_pair_element(enc, element):
    return enc.encrypt(pad(element.encode("utf-8"), 16, isBytes=True))

def decrypt_pair_element(dec, element):
    return unpad(dec.decrypt(element), 16, isBytes = True).decode("utf-8")

def main():
    if (not(check_platform(["posix", "nt"]))):
        sys.exit(1)

    parser = argparse.ArgumentParser(formatter_class=argparse.RawTextHelpFormatter)
    
    user_id_group = parser.add_argument_group("User identification", "Options related to user identification.")
    user_id_group.add_argument("-a", "--add-user", metavar="USER", dest="new_user", type=str, nargs=1,
                               help="Add a new user and exit.")
    user_id_group.add_argument("-u", "--user", metavar="USER", dest="user", type=str, nargs=1,
                               help="Connect as user and exit.")
    user_id_group.add_argument("-t", "--time", metavar="TIME", dest="time", type=int, nargs=1,
                               help="Connect, indicate to stay logged in for TIME seconds and exit.\n(TIME >= 0, default 0 (no limit))")
    user_id_group.add_argument("--dump-user-info", dest="dump_user_info", action="store_const",
                               const=True,
                               help='Display all user-related information and exit.')
    user_id_group.add_argument("-k", "--stop-session", dest="disconnect", action="store_const",
                               const=True,
                               help='Stop current user session and exit.')
    
    category_group = parser.add_argument_group("Categories", "Options related to categories.")
    category_group.add_argument("categories", metavar='CATEGORY', type=str, nargs='*',
                                help="Operate on CATEGORY.").completer = CategoryCompleter
    category_group.add_argument("-l", "--list-categories", dest="list_categories", action="store_const",
                                const=True,
                                help='Display all user\'s categories and exit.')
    category_exclusive = category_group.add_mutually_exclusive_group()
    category_exclusive.add_argument("-c", "--create-category", dest="to_create",
                                    action="store_const", const=True,
                                    help="Create CATEGORY if it does not already exist.")
    category_exclusive.add_argument("-d", "--delete-category", dest="to_delete",
                                    action="store_const", const=True,
                                    help="Delete CATEGORY if it exists.")
    # category_group.add_argument("-e", "--set-hidden", dest="hide", action="store_const",
    #                             const=True,
    #                             help='Do not add category to autocompletion.')
    category_group.add_argument('-w', '--show-category', dest='to_show',
                                action="store_const", const=True,
                                help='Display content of CATEGORY if it exists.\nThe VALUE of private pairs are replaced by \'****\'.\n(Default)')
    # category_group.add_argument('--purge', dest='to_purge',
    #                             action="store_const", const=True,
    #                             help='Purge content of CATEGORY if it exists.')
    pairs_group = parser.add_argument_group("Pairs", "Options related to pairs.")
    pairs_group.add_argument('-g', '--get-pair', dest='get_pairs', metavar='KEY', type=str, nargs='+',
                             help='Get the KEY-VALUE pair associated with KEY in CATEGORY.')
    pairs_group.add_argument('-r', '--remove-pair', dest='remove_pairs', metavar='KEY', type=str, nargs='+',
                             help='Remove the KEY-VALUE pair in CATEGORY.')
    pairs_group.add_argument('-s', '--set-pair', dest='set_pairs', metavar='KEY:VALUE:[:TAG]', type=str, nargs='+',
                             help='Add a new KEY-VALUE pair in CATEGORY.\nIf no VALUE is specified, you will be prompted.\n(By default, the prompt creates a private pair.)')
    
    pair_privacy_group = pairs_group.add_mutually_exclusive_group()
    pair_privacy_group.add_argument('-p', '--private-pair', dest='private_pairs', metavar='KEY', type=str, nargs='*',
                                    help='Set pair as private.\nIf a KEY is specified, sets an exisiting pair to private.\nOtherwhise, sets pair given by --set-pair.')
    pair_privacy_group.add_argument('-P', '--public-pair', dest='public_pairs', metavar='KEY', type=str, nargs='*',
                                    help='Set pair as public.\nIf a KEY is specified, sets an exisiting pair to public.\nOtherwhise, sets pair given by --set-pair.\n(Default)')
    pairs_group.add_argument('-m', '--multiline', dest='multi_line', action="store_const", const=True,
                             help='Changes prompt to input a multiline VALUE.')

    tags_group = parser.add_argument_group("Tags", "Options related to tags.")
    tags_group.add_argument('--get-tag', dest='get_tags', metavar='TAG', type=str, nargs='+',
                            help='Get the KEY-VALUE pairs associated with TAG in CATEGORY.')
    tags_group.add_argument('--remove-tag', dest='remove_tags', metavar='TAG[:KEY]', type=str, nargs='+',
                            help='Remove TAG from CATEGORY (only from KEY if it\'s specified).')
    tags_group.add_argument('--set-tag', dest='set_tags', metavar='TAG:KEY', type=str, nargs='+',
                            help='Associate the KEY-VALUE pair to TAG in CATEGORY.')
    # TODO; Tomorrow, because I'm tired....
    # tags_group.add_argument('--add-tag', dest='add_tags', metavar='TAG:KEY', type=str, nargs='+',
    #                         help='Add TAG to the KEY-VALUE pair CATEGORY.')

    argcomplete.autocomplete(parser)
    
    args = parser.parse_args()

    to_create = False
    to_delete = False
    
    to_show = False
    to_set = False
    to_get = False
    to_remove = False
    
    to_set_privacy = False
    to_set_new_privacy = False
    to_set_existing_privacy = False

    to_get_tag = False
    to_remove_tag = False
    to_set_tag = False
    
    is_multiline = False

    privacy_pairs = []
    privacy_status = PairStatus.same_as_before

    if (is_arg_set(args.to_create)):
        to_create = True

    if (is_arg_set(args.to_delete)):
        to_delete = True

    if (is_arg_set(args.to_show)):
        to_show = True

    if (is_arg_set(args.set_pairs)):
        to_set = True

    if (is_arg_set(args.get_pairs)):
        to_get = True

    if (is_arg_set(args.remove_pairs)):
        to_remove = True

    if (is_arg_set(args.private_pairs) or is_arg_set(args.public_pairs)):
        to_set_privacy = True
        
        if (is_arg_set(args.private_pairs)):
            privacy_status = PairStatus.private
            privacy_pairs = args.private_pairs
        else:
            privacy_status = PairStatus.public
            privacy_pairs = args.public_pairs

    if (is_arg_set(args.get_tags)):
        to_get_tag = True

    if (is_arg_set(args.remove_tags)):
        to_remove_tag = True

    if (is_arg_set(args.set_tags)):
        to_set_tag = True

    if (is_arg_set(args.multi_line)):
        is_multiline = True

    # NOTE: args.set_pairs does not go through the same process as it
    #       would require to only verify keys (and I can not be
    #       bothered to do it).
    args.categories = remove_duplicates(args.categories)
    
    args.get_pairs = remove_duplicates(args.get_pairs)
    args.remove_pairs = remove_duplicates(args.remove_pairs)
    
    privacy_pairs = remove_duplicates(privacy_pairs)

    args.get_tags = remove_duplicates(args.get_tags)

    if (is_arg_set(args.get_tags)):
        args.get_tags = sorted(args.get_tags)
        
    args.remove_tags = remove_duplicates(args.remove_tags)

    # Default
    if (sum([to_create, to_delete, to_set, to_get, to_remove, is_multiline, to_set_privacy,
             to_get_tag, to_remove_tag, to_set_tag]) == 0):
        to_show = (len(args.categories) > 0)

    # user_id_group options checking
    if (args.disconnect):
        disconnect_current_user()
        sys.exit(0)
        
    if (is_arg_set(args.new_user)):
        new_user = args.new_user[0]
        
        prompt_create_new_user(new_user)
        sys.exit(0)

    time_limit = 0

    if (is_arg_set(args.time)):
        if (check_platform(["posix"], "ignored: -t|--time: only supported on linux.")):
            time_limit = args.time[0]

            if (time_limit < 0):
                print("error: -t|--time: TIME must be positive.")
                sys.exit(0)
            disconnect_current_user()

    
    if (is_arg_set(args.user)):
        disconnect_current_user()

        if (not(connect_as_user(args.user[0], time_limit))):
            print("Access denied.")
            sys.exit(0)

    # User connection starts here.
    public_key = revive_current_user_if_needed(time_limit)

    if (args.dump_user_info):
        dump_user_info()
        sys.exit(0)

    if (args.list_categories):
        dump_user_categories()
        sys.exit(0)

    # NOTE: -p|--private-pair or -P|--public-pair can be used with -s|--set-pair.
    #       In that case, if keys were passed on to
    #       --private-pair|--public-pair, we treat them as 'existing'
    #       keys.  Otherwhise, we use the 'new' ones from --set-pair.
    if (to_set_privacy):
        if (len(privacy_pairs) == 0):
            if (to_set):
                to_set_new_privacy = True
        else:
            to_set_existing_privacy = True

    # NOTE: If at least one of them is set, we need to read the file.
    is_accessing_categories = sum([to_get, to_remove, to_set, to_show, to_set_privacy,
                                   to_get_tag, to_remove_tag, to_set_tag])

    if (is_accessing_categories and (len(args.categories) == 0)):
        eprint("no category specified.")

    # category_modif_group option checking
    # NOTE: --create-category and --delete-category can not be set at
    # the same time.
    if (to_create):
        # TODO: Allow categories not be autocompleted.
        add_to_completion = True
        # if (args.hide):
        #     add_to_completion = False
        for category in args.categories:
            if (not(get_file_from_category(category, public_key) is None)):
                eprint("failed to create category '%s': already exists." % category)
                continue

            category_pwd = enter_password_and_confirm(category + "'s password:")

            if (category_pwd is None):
                eprint("failed to create category '%s': invalid password." % category)
                continue
            
            success, status = create_category(category, public_key, category_pwd)
            
            if (not(success)):
                eprint("failed to create category '%s': could not access database." % category, end="")
                continue
                    
    if (to_delete):
        for category in args.categories:
            success, status = delete_category(category, public_key)
            
            if (not(success)):
                eprint("failed to delete category '%s': " % category, end="")
                
                if (status == CategoryStatus.do_not_exist):
                    eprint("does not exist.", prog_name=False)
                else:
                    eprint("could not access database.", prog_name=False)
                    
        # NOTE: Everything below is done on categories anyway.
        sys.exit(0)

    for category in copy_list(args.categories):
        file_path = get_file_from_category(category, public_key)
    
        if (file_path is None):
            eprint("failed to access category '%s': does not exist." % category)
            args.categories.remove(category)
                    
    # pairs_group option checking
    if (to_set):
        kv = [i.split(":") for i in args.set_pairs]

        new_pairs = []
        for i in kv:
            is_private = (privacy_status == PairStatus.private)

            # NOTE: If no value is given, prompt the user until it is.
            while ((len(i) < 2) or (i[1] == "")):
                # Private pair by default.
                prompt = i[0] + ":"
                if (not(is_multiline)):
                    i = [i[0], getpass.getpass(prompt)]
                    is_private = True
                else:
                    all_lines = []
                    line = input(prompt)
                    
                    while line:
                        all_lines.append(line)
                        line = input()

                    # NOTE: Indentation is added, it may be removed later on...
                    i = [i[0], ("\n" + " " * (len(i[0]) + 1)).join(all_lines)]

            if (len(i) > 3):
                eprint("malformed KEY:VALUE[:TAG] pair '%s'." % ":".join(i))
            elif (i[0] == ""):
                eprint("VALUE '%s' is missing a KEY." % i[1])
            else:
                if (len(i) < 3):
                    i.append("None")
                new_pairs.append([i[0], i[1], is_private, i[2]])
                
        args.set_pairs = new_pairs

    if (to_set_tag):
        tk = [i.split(":") for i in args.set_tags]

        new_tags = []
        for i in tk:
            if (len(i) > 2):
                eprint("malformed TAG:KEY pair '%s'." % ":".join(i))
            elif (i[0] == ""):
                eprint("KEY '%s' is missing a TAG." % i[1])
            elif (i[1] == ""):
                eprint("TAG '%s' is missing a KEY." % i[0])
            else:
                new_tags.append([sorted(i[0].split(",")), i[1]])
                
        args.set_tags = new_tags

    if (to_set_privacy and (len(privacy_pairs) == 0) and not(to_set)):
        if (privacy_status == PairStatus.private):
            eprint("--private-pair", end="")
        else:
            eprint("--public-pair", end="")
            
        eprint(": no key or pair specified.", prog_name=False)
    
    if (is_accessing_categories and len(args.categories)):
        # FIXME: Current implementation does not allow salt!
        for category in args.categories:
            is_category_modified = False
            all_enc_pairs = {}
            all_old_lines = []

            # NOTE: As check was moved above, it should always
            # succeed. Better be sure anyway...
            success, encrypted_file, pwd_key = open_category(category, public_key, "r+b")

            if (not(success)):
                continue

            # NOTE: To allow removing keys already seen across categories.
            get_pairs = copy_list(args.get_pairs)
            remove_pairs = copy_list(args.remove_pairs)
            
            privacy_pairs = copy_list(privacy_pairs)
            
            get_tags = copy_list(args.get_tags)
            remove_tags = copy_list(args.remove_tags)

            for enc_line in encrypted_file:
                enc_k, enc_v, enc_t, is_private, enc, dec = get_line_enc_content(enc_line, pwd_key)

                if (not(enc_k) is None):
                    skip = False

                    if (to_get):
                        for key in copy_list(get_pairs):
                            if (encrypt_pair_element(enc, key) == enc_k):
                                print("%s:%s" % (key, decrypt_pair_element(dec, enc_v)))
                                get_pairs.remove(key)

                    # TODO: Make tags separated by commas (',') be additive (all must be included).
                    if (to_get_tag):
                        if (any(encrypt_pair_element(enc, tag) in enc_t for tag in copy_list(args.get_tags))):
                            print("%s:%s" % (decrypt_pair_element(dec, enc_k),
                                             decrypt_pair_element(dec, enc_v)))

                    if (to_remove_tag):
                        for tag in remove_tags[:]:
                            tag_key = tag.split(":")

                            # No key specified.
                            if (len(tag_key) == 1):
                                enc_given_tag = encrypt_pair_element(enc, tag)
                                
                                if (enc_given_tag in enc_t):
                                    enc_t.remove(enc_given_tag)
                                    is_category_modified = True
                            # Key specified.
                            elif ((len(tag_key) == 2) and
                                  (encrypt_pair_element(enc, tag_key[1]) == enc_k)):
                                enc_given_tag = encrypt_pair_element(enc, tag_key[0])
                                
                                if (enc_given_tag in enc_t):
                                    enc_t.remove(enc_given_tag)
                                    is_category_modified = True
                                    remove_tags.remove(tag)

                    if (to_remove):
                        for key in remove_pairs[:]:
                            if (encrypt_pair_element(enc, key) == enc_k):
                                skip = True
                                remove_pairs.remove(key)

                    if (skip):
                        is_category_modified = True
                        continue
                                
                    all_enc_pairs[enc_k] = [enc_v, is_private, enc_t]
                    
                # NOTE: Allow fake pairs.
                else:
                    all_old_lines.append(enc_line)

            if (to_get):
                for key in get_pairs:
                    eprint("--get-pair: invalid key '%s'." % key)

            # TODO: Store if at least one found.
            # if (to_get_tag):
            #     for tag in get_tags:
            #         eprint("--get-tag: invalid tag '%s'." % tag)

            if (to_remove):
                for key in remove_pairs:
                    eprint("--remove-pair: invalid key '%s'." % key)

            # TODO: Store if at least one found.
            # if (to_remove_tag):
            #     for tag in remove_tags:
            #         eprint("--remove-tag: invalid tag '%s'." % tag)

            salt = os.urandom(AES.block_size)            
            enc = AES.new(pwd_key)

            # NOTE: Add new pairs and replace VALUEs of old ones.
            if (to_set):
                for i in args.set_pairs:
                    enc_k = encrypt_pair_element(enc, i[0])
                    enc_v = encrypt_pair_element(enc, i[1])
                    
                    # Separate each tag and encrypt them invidually. 
                    enc_t = [encrypt_pair_element(enc, tag) for tag in i[3].split(",")]

                    if ((enc_k in all_enc_pairs) and (privacy_status == PairStatus.same_as_before)):
                        all_enc_pairs[enc_k] = [enc_v, all_enc_pairs[enc_k][1], enc_t]
                    else:
                        all_enc_pairs[enc_k] = [enc_v, i[2], enc_t]
                    
                    is_category_modified = True
                    
            if (to_set_tag):
                for tags, key in args.set_tags:
                    enc_k = encrypt_pair_element(enc, key)

                    if (enc_k in all_enc_pairs):
                        all_enc_pairs[enc_k][2] = [encrypt_pair_element(enc, t) for t in tags]
                        is_category_modified = True
                    else:
                        eprint("--set-tag: invalid key '%s'." % key)

            # NOTE: Change privacy of given pairs.
            if (to_set_existing_privacy):
                for i in copy_list(privacy_pairs):
                    enc_k = encrypt_pair_element(enc, i)
                    
                    if (enc_k in all_enc_pairs):
                        all_enc_pairs[enc_k][1] = (privacy_status == PairStatus.private)
                        privacy_pairs.remove(i)
                    
                        is_category_modified = True

                for key in privacy_pairs:
                    if (privacy_status == PairStatus.private):
                        eprint("--private-pair", end="")
                    else:
                        eprint("--public-pair", end="")

                    eprint(": invalid key '%s'." % key, prog_name=False)
                    
            if (is_category_modified):
                encrypted_file.seek(0, os.SEEK_SET)
                encrypted_file.readline()
                encrypted_file.readline()
                
                for l in all_old_lines:
                    encrypted_file.write(l)
                        
                for enc_k, [enc_v, is_private, enc_t] in all_enc_pairs.items():
                    if (is_private):
                        integrity_check = b"Valid"
                    else:
                        integrity_check = b"valid"

                    if (len(enc_t) == 0):
                        enc_t = [encrypt_pair_element(enc, "None")]

                    line = pad(base64.b64encode(integrity_check) + b"$" + base64.b64encode(enc_k) + b"$" +\
                               base64.b64encode(enc_v) + b"$" + b"$".join([base64.b64encode(t) for t in enc_t]),
                               16, isBytes = True)

                    enc_line = base64.b64encode(salt + enc.encrypt(line), altchars=b'-_')

                    encrypted_file.write(enc_line + b"\n")

                encrypted_file.truncate()

            encrypted_file.close()
                
            if (to_show):
                for enc_k, [enc_v, is_private, enc_t] in all_enc_pairs.items():
                    if (is_private):
                        print("%s:**** (Tags: %s)" % (decrypt_pair_element(dec, enc_k), [decrypt_pair_element(dec, i) for i in enc_t]))
                    else:
                        print("%s:%s (Tags: %s)" % (decrypt_pair_element(dec, enc_k), decrypt_pair_element(dec, enc_v), [decrypt_pair_element(dec, i) for i in enc_t]))

            if (to_get or to_show or to_get_tag):
                print("")

if __name__ == "__main__":
    try:
        main()
    except (KeyboardInterrupt, EOFError):
        print("")
    # except Exception as e:
    #     print("\nAn exception has occurred, sorry.")
