#!/usr/bin/python3
# -*- coding: utf-8 -*-
# PYTHON_ARGCOMPLETE_OK

import argcomplete
from user_identification import *
from enum import Enum
from collections import OrderedDict

class CategoryStatus(Enum):
    do_not_exist = 0
    exist = 1
    inaccessible = 2

class PairStatus(Enum):
    same_as_before = -1
    public = 0
    private = 1

class Pair:
    def __init__(self, pwd_key, salt):
        self.enc_key = None
        self.enc_value = None
        
        self.enc_tag_list = []
        self.privacy_status = PairStatus
        
        self.salt = salt

        # Generate an AES key depending on the password for the
        # category and a salt.
        self.encryption_function = AES.new(bcrypt.kdf(password = pwd_key,
                                                      salt = salt,
                                                      desired_key_bytes = 32,
                                                      rounds=10))

    def set_key(self, key):
        self.enc_key = encrypt_pair_element(self.encryption_function, key)

    def set_value(self, value):
        self.enc_value = encrypt_pair_element(self.encryption_function, value)

    def set_tags(self, tags):
        self.enc_tag_list = [encrypt_pair_element(self.encryption_function, t) for t in tags]

    def add_tags(self, tags):
        count = 0
        
        for t in tags:
            count += add_tag(self.encryption_function, self.enc_tag_list, t)

        return count
        
    def get_key(self):
        return decrypt_pair_element(self.encryption_function, self.enc_key)

    def get_value(self):
        return decrypt_pair_element(self.encryption_function, self.enc_value)

    def get_tags(self):
        return sorted([decrypt_pair_element(self.encryption_function, t) for t in self.enc_tag_list])

    def key_equals(self, key):
        return (encrypt_pair_element(self.encryption_function, key) == self.enc_key)

    def has_tag(self, tag):
        return (encrypt_pair_element(self.encryption_function, tag) in self.enc_tag_list)

    def remove_tag(self, tag):
        return remove_tag(self.encryption_function, self.enc_tag_list, tag)

    def is_private(self):
        return (self.privacy_status == PairStatus.private)

    def set_private(self):
        self.privacy_status = PairStatus.private

    def set_public(self):
        self.privacy_status = PairStatus.public

    def encrypt(self):
        if (self.is_private()):
            integrity_check = b"Valid"
        else:
            integrity_check = b"valid"

        return base64.b64encode(self.salt +\
                                self.encryption_function.encrypt(pad(base64.b64encode(integrity_check) + b"$" + base64.b64encode(self.enc_key) + b"$" +\
                                                                     base64.b64encode(self.enc_value) + b"$" + b"$".join([base64.b64encode(t) for t in self.enc_tag_list]),
                                                                     16, isBytes = True)), altchars=b'-_')

def is_arg_set(arg):
    return not(arg is None)

def category_sign(category_key, content_list):
    # NOTE: For RSA only, K is not used.
    # K = CUN.getRandomNumber(128, os.urandom)
    K = ""
    return str(category_key.sign(SHA256.new(b"\n".join(content_list)).hexdigest().encode(), K)).encode()

# FIXME: RSA encryption returns a filename way too long.
#        Find shorter way of encrypting.
#        See int_to_cust and cust_to_int in user_identification.py.
# TODO:  Generate dummy files as well.
def create_category(name, public_key, password, add_to_completion = True):
    if (not(get_file_from_category(name, public_key) is None)):
        return False, CategoryStatus.exist
    
    final_name = int_to_cust(int(public_encrypt(public_key, name), 16))
    file_path = os.path.join(YAPM_FILE_DB, "." + final_name)
    
    try:
        
    
        with open(file_path, "wb+") as category:
            # TODO: Change check to just be name? (+ seed)
            enc_check = public_encrypt(public_key, generate_dummy_check(name))
            
            category_key = generate_rsa(name, password)

            salt = os.urandom(16).hex().encode()
            pwd_keyhash = password_hash(password, salt)
        
            lines = []
            lines.append(b"User check = " + enc_check.encode())
            lines.append(b"Password hash = " + salt + b"$" + pwd_keyhash.encode())
            lines.append(b"Content = ")
            
            signature = category_sign(category_key, lines)

            for l in lines[:-1]:
                category.write(l + b"\n")
                
            category.write(b"Signature = " + signature + b"\n")

            category.write(lines[-1] + b"\n")

        open(os.path.join(YAPM_USER_CATEGORIES_DIRECTORY, name), "w+").close()

        return True, CategoryStatus.exist
    except Exception as e:
        if (os.path.exits(file_path)):
            os.remove(file_path)
            
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

def get_file_bytes_after(f, start, end = b"\n"):
    return f.readline().split(start)[1].split(end)[0]

# NOTE: Do not forget to close it.
def open_category(name, public_key, flags):
    file_path = get_file_from_category(name, public_key)
    
    if (file_path is None):
        eprint("failed to access category '%s': does not exist." % name)
        return False, None, None

    try:
        encrypted_file = open(file_path, flags)

        check = encrypted_file.readline()[:-1]

        salt, pwd_keyhash = get_file_bytes_after(encrypted_file, b"Password hash = ").split(b"$")
        password = getpass.getpass(name + "'s password:")
        pwd_key = password_key(password, salt)

        if (password_keyhash(pwd_key, salt).encode() == pwd_keyhash):
            # Signature.
            category_key = generate_rsa(name, password)
            signature = make_tuple(get_file_bytes_after(encrypted_file, b"Signature = ").decode())

            content = get_file_bytes_after(encrypted_file, b"Content = ")

            toto = b"\n".join([check,
                               b"Password hash = " + salt + b"$" + pwd_keyhash,
                               b"Content = " + content])

            
            if (category_key.publickey().verify(SHA256.new(toto).hexdigest().encode(), signature)):
                if (len(content) == 0):
                    return True, encrypted_file, [], pwd_key, category_key
                else:
                    salt, enc_content = content.split(b"$")
                    salt = base64.b64decode(salt)
                    enc_content = base64.b64decode(enc_content)

                    dec = AES.new(pwd_key, AES.MODE_CBC, IV=salt)

                    return True, encrypted_file, unpad(dec.decrypt(enc_content), isBytes = True).split(b"\n"), pwd_key, category_key
            else:
                eprint("category '%s' was modified outside this program!" % name)
    except Exception as e:
        pass

    time.sleep(ACCESS_DENIED_WAIT_DELAY)
    print("Access denied.")
        
    return False, None, None, None, None

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
    try:
        enc_line = unpad(base64.b64decode(enc_line, altchars=b'-_'), isBytes = True)
                
        salt = enc_line[:AES.block_size]
        
        pair = Pair(pwd_key, salt)

        line = pair.encryption_function.decrypt(enc_line[AES.block_size:])

        if (line.startswith(base64.b64encode(b"valid") + b"$")):
            pair.privacy_status = PairStatus.public
        elif (line.startswith(base64.b64encode(b"Valid") + b"$")):
            pair.privacy_status = PairStatus.private
        else:
            return None
        
        fields = line.split(b"$")[1:]
        pair.enc_key, pair.enc_value = [base64.b64decode(f) for f in fields[:2]]
        pair.enc_tag_list = [base64.b64decode(f) for f in fields[2:]]

        return pair
    except:
        return None

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

def separate_group(all_expression, delimiter):
    return [expression.split(delimiter) for expression in all_expression]

def separate_two_groups(all_expressions, delimiter_general, delimiter_group_1, delimiter_group_2):
    result = []
    
    for g1_and_g2 in all_expressions:
        g1_g2 = g1_and_g2.split(delimiter_general)
            
        all_g1 = []
        all_g2 = []

        if (len(g1_g2) == 2):
            all_g2 = remove_duplicates(g1_g2[1].split(delimiter_group_2))
            
        all_g1 = remove_duplicates(g1_g2[0].split(delimiter_group_1))
        
        result.append([all_g1, all_g2])

    return result

def remove_tag(enc, enc_tag_list, tag):
    enc_tag = encrypt_pair_element(enc, tag)
                                    
    if (enc_tag in enc_tag_list):
        enc_tag_list.remove(enc_tag)
        
        if (len(enc_tag_list) == 0):
            enc_tag_list.append(encrypt_pair_element(enc, "None"))
            
        return True
        
    return False

def add_tag(enc, enc_tag_list, tag):
    if (tag == "None"):
        return False
    
    enc_tag = encrypt_pair_element(enc, tag)

    if ((len(enc_tag_list) == 1) and
        (enc_tag_list[0] == encrypt_pair_element(enc, "None"))):
        enc_tag_list.clear()
    
    if (not(enc_tag in enc_tag_list)):
        enc_tag_list.append(enc_tag)
            
        return True
        
    return False

def get_pair_from_key(all_pairs, key):
    for pair in all_pairs:
        if (pair.key_equals(key)):
            return pair

    return None


def CategoryCompleter(prefix, **kwargs):
    return (c for c in os.listdir(YAPM_USER_CATEGORIES_DIRECTORY))

def main():
    if (not(check_platform(["posix", "nt"]))):
        sys.exit(1)

    description="Personal data manager.\n\
Stores KEY-VALUE pairs in CATEGORIES owned by USERs.\n\
Each CATEGORY needs a password to be accessed.\n\
A pair can have an unlimited amount of TAGs.\n\n\
Accessing a CATEGORY is a simple as:\n yapm CATEGORY\n\n\
If no user is logged in, you will be prompted to do so."
        
    parser = argparse.ArgumentParser(formatter_class=argparse.RawTextHelpFormatter,
                                     description=description)
    
    user_id_group = parser.add_argument_group("User identification", "Options related to user identification.")
    user_id_group.add_argument("--add-user", metavar="USER", dest="new_user", type=str, nargs=1,
                               help="Add a new user and exit.")
    user_id_group.add_argument("-u", "--user", metavar="USER", dest="user", type=str, nargs=1,
                               help="Connect as user and exit.")
    user_id_group.add_argument("-t", "--time", metavar="TIME", dest="time", type=int, nargs=1,
                               help="Connect, indicate to stay logged in for TIME seconds and exit.\n(TIME >= 0, default 0 (no limit))")
    user_id_group.add_argument("--dump-user-info", dest="dump_user_info", action="store_const",
                               const=True,
                               help='Display all user-related information and exit.')
    user_id_group.add_argument("-l", "--list-categories", dest="list_categories", action="store_const",
                               const=True,
                               help='Display all user\'s categories and exit.')
    user_id_group.add_argument("-k", "--stop-session", dest="disconnect", action="store_const",
                               const=True,
                               help='Stop current user session and exit.')
    
    category_group = parser.add_argument_group("Categories", "Options related to categories.")
    category_group.add_argument("categories", metavar='CATEGORY', type=str, nargs='*',
                                help="Operate on CATEGORY.").completer = CategoryCompleter
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
    pairs_group = parser.add_argument_group("Pairs", "Options related to pairs.\n  (TAG => TAG[,TAG, ...])")
    pairs_group.add_argument('--get-pair', dest='get_pairs', metavar='KEY', type=str, nargs='+',
                             help='Get the KEY-VALUE pair associated with KEY in CATEGORY.')
    pairs_group.add_argument('--remove-pair', dest='remove_pairs', metavar='KEY', type=str, nargs='+',
                             help='Remove the KEY-VALUE pair in CATEGORY.')
    pairs_group.add_argument('--set-pair', dest='set_pairs', metavar='KEY:VALUE:TAG', type=str, nargs='+',
                             help='Add a new KEY-VALUE pair in CATEGORY.\nIf no VALUE is specified, you will be prompted.\n(This will set the pair as private)')
    
    pair_privacy_group = pairs_group.add_mutually_exclusive_group()
    pair_privacy_group.add_argument('-p', '--set-private', dest='private_pairs', metavar='KEY', type=str, nargs='*',
                                    help='Set pair as private.\nIf a KEY is specified, sets an exisiting pair to private.\nOtherwhise, sets pair given by --set-pair.')
    pair_privacy_group.add_argument('-P', '--set-public', dest='public_pairs', metavar='KEY', type=str, nargs='*',
                                    help='Set pair as public.\nIf a KEY is specified, sets an exisiting pair to public.\nOtherwhise, sets pair given by --set-pair.\n(Default)')
    pairs_group.add_argument('-m', '--multiline', dest='multi_line', action="store_const", const=True,
                             help='Changes prompt to input a multiline VALUE.')

    tags_group = parser.add_argument_group("Tags", "Options related to tags.\n  (TAG => TAG[,TAG, ...])\n  (KEY => KEY[,KEY, ...])")
    tags_group.add_argument('-g', '--get-tag', dest='get_tags', metavar='TAG', type=str, nargs='+',
                            help='Get the KEY-VALUE pairs associated with TAG in CATEGORY.')
    tags_group.add_argument('-r', '--remove-tag', dest='remove_tags', metavar='TAG[:KEY]', type=str, nargs='+',
                            help='Remove TAG from CATEGORY (only from KEY if it\'s specified).')
    tags_group.add_argument('-s', '--set-tag', dest='set_tags', metavar='TAG:KEY', type=str, nargs='+',
                            help='Associate the KEY-VALUE pair with TAG in CATEGORY.')
    tags_group.add_argument('-a', '--add-tag', dest='add_tags', metavar='TAG:KEY', type=str, nargs='+',
                            help='Add TAG to the KEY-VALUE pair CATEGORY.')

    argcomplete.autocomplete(parser, always_complete_options="long")
    
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
    to_add_tag = False
    
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

    if (is_arg_set(args.add_tags)):
        to_add_tag = True

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
    if (not(any([to_create, to_delete, to_set, to_get, to_remove, is_multiline, to_set_privacy,
                 to_get_tag, to_remove_tag, to_set_tag, to_add_tag]))):
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

    # If at least one of them is set, we need to read the file.
    is_accessing_categories = any([to_get, to_remove, to_set, to_show, to_set_privacy,
                                   to_get_tag, to_remove_tag, to_set_tag, to_add_tag])

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
                eprint("failed to create category '%s': could not access database." % category)
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
                    
        # Everything below is done on categories anyway.
        sys.exit(0)

    for category in copy_list(args.categories):
        file_path = get_file_from_category(category, public_key)
    
        if (file_path is None):
            eprint("failed to access category '%s': does not exist." % category)
            args.categories.remove(category)
                    
    # pairs_group option checking
    # args.set_pairs example: 1:foo 2:bar:baz 3::foobar,foobaz =>
    # KEY = 1, VALUE = foo, TAGs = ['None']
    # KEY = 2, VALUE = bar, TAGs = ['baz']
    # KEY = 3, VALUE = None yet (private), TAGs = ['foobar', 'foobaz']
    if (to_set):
        kv = [i.split(":") for i in args.set_pairs]

        new_pairs = []
        for i in kv:
            is_private = (privacy_status == PairStatus.private)

            tags = ["None"]

            if ((len(i) == 3) and
                (len(i[2]) != 0)):
                tags = i[2].split(",")

            # If no value is given, prompt the user until it is.
            while ((len(i) < 2) or (len(i[1]) == 0)):
                # Private pair by default.
                prompt = i[0] + ":"
                
                if (not(is_multiline)):
                    is_private = (privacy_status != PairStatus.public)

                    if (is_private):
                        i = [i[0], getpass.getpass(prompt)]
                    else:
                        i = [i[0], input(prompt)]
                else:
                    all_lines = []
                    line = input(prompt)
                    indentation = " " * (len(i[0]) + 1)
                    while line:
                        all_lines.append(line)
                        line = input(identation)

                    i = [i[0], ("\n" + indentation).join(all_lines)]

            if (len(i) > 3):
                eprint("malformed KEY:VALUE[:TAG] pair '%s'." % ":".join(i))
            elif (i[0] == ""):
                eprint("VALUE '%s' is missing a KEY." % i[1])
            else:
                new_pairs.append([i[0], i[1], is_private, tags])

        args.set_pairs = new_pairs

    # args.remove_tags example: foo,bar:1,2 => remove TAGs foo and bar
    # from pairs with KEY 1 and 2.
    if (to_remove_tag):
        remove_tags = separate_two_groups(args.remove_tags, ":", ",", ",")

    # args.get_tag example: foo bar,baz => get pairs if they have
    # either foo OR foo AND bar as TAGs.
    if (to_get_tag):
        # NOTE: Tags separated by commas (',') are anded.
        #       If they are separated by spaces, they are ored.
        args.get_tags = separate_group(args.get_tags, ",")

    # args.set_tag example: foo:1 bar,baz:2 foobar:3,4
    # pair with KEY 1, set TAGs to ['foo']
    # pair with KEY 2, set TAGs to ['bar', 'baz']
    # pairs with KEY 3 and KEY 4, set TAGs to ['foobar']
    if (to_set_tag):
        tags_keys = [i.split(":") for i in args.set_tags]

        new_tags = []
        for i in tags_keys:
            if (len(i) > 2):
                eprint("malformed TAG:KEY pair '%s'." % ":".join(i))
            elif (i[0] == ""):
                eprint("KEY '%s' is missing a TAG." % i[1])
            elif (i[1] == ""):
                eprint("TAG '%s' is missing a KEY." % i[0])
            else:
                new_tags.append([sorted(i[0].split(",")), sorted(i[1].split(","))])
                
        args.set_tags = new_tags

    # args.add_tag example: foo:1 bar,baz:2 foobar:3,4
    # pair with KEY 1, add TAG ['foo']
    # pair with KEY 2, add TAG['bar', 'baz']
    # pairs with KEY 3 and KEY 4, add TAGs ['foobar']
    if (to_add_tag):
        args.add_tags = separate_two_groups(args.add_tags, ":", ",", ",")
    
    if (to_set_privacy and (len(privacy_pairs) == 0) and not(to_set)):
        if (privacy_status == PairStatus.private):
            eprint("--private-pair", end="")
        else:
            eprint("--public-pair", end="")
            
        eprint(": no key or pair specified.", prog_name=False)
    
    if (is_accessing_categories and len(args.categories)):
        for category in args.categories:
            is_category_modified = False
            all_enc_pairs = []
            # all_old_lines = []

            # NOTE: As check was moved above, it should always
            # succeed. Better be sure anyway...
            success, encrypted_file, enc_content, pwd_key, category_key = open_category(category, public_key, "r+b")

            if (not(success)):
                continue

            # NOTE: To allow removing keys already seen across categories.
            get_pairs = copy_list(args.get_pairs)
            remove_pairs = copy_list(args.remove_pairs)
            
            privacy_pairs = copy_list(privacy_pairs)

            for enc_line in enc_content:
                pair = get_line_enc_content(enc_line, pwd_key)

                if (not(pair is None)):
                    skip = False

                    if (to_get):
                        for key in copy_list(get_pairs):
                            if (pair.key_equals(key)):
                                print("%s:%s (Tags: %s)" % (key, pair.get_value(), pair.get_tags()))
                                get_pairs.remove(key)

                    if (to_get_tag):
                        if (any([set(pair.enc_tag_list).issuperset([encrypt_pair_element(pair.encryption_function, tag) for tag in and_tags]) for and_tags in args.get_tags])):
                            print("%s:%s (Tags: %s)" % (pair.get_key(), pair.get_value(), pair.get_tags()))
                                
                    if (to_remove_tag):
                        for tag_pair in remove_tags[:]:
                            all_tags, all_keys = tag_pair

                            # No key specified.
                            if (len(all_keys) == 0):
                                for tag in all_tags:
                                    is_category_modified += pair.remove_tag(tag)
                            # Key(s) specified.
                            else:
                                for key in all_keys[:]:
                                    if (pair.key_equals(key)):
                                        for tag in all_tags:
                                            is_category_modified += pair.remove_tag(tag)
                                            
                                        all_keys.remove(key)

                                        if (len(all_keys) == 0):
                                            remove_tags.remove(tag_pair)
                                            
                        is_category_modified = (is_category_modified != 0)
                            
                    if (to_remove):
                        for key in remove_pairs[:]:
                            if (pair.key_equals(key)):
                                skip = True
                                remove_pairs.remove(key)

                    if (skip):
                        is_category_modified = True
                        continue
                                
                    all_enc_pairs.append(pair)

                # TODO: Just use different integrity check.
                # # NOTE: Allow fake pairs.
                # else:
                #     all_old_lines.append(enc_line)

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

            # NOTE: Add new pairs and replace VALUEs of old ones.
            if (to_set):
                for i in args.set_pairs:
                    pair = get_pair_from_key(all_enc_pairs, i[0])

                    if (pair is None):
                        pair = Pair(pwd_key, os.urandom(AES.block_size))
                        pair.set_key(i[0])

                        if (i[2]):
                            pair.set_private()
                        else:
                            pair.set_public()

                        all_enc_pairs.append(pair)
                    elif (privacy_status != PairStatus.same_as_before):
                        if (i[2]):
                            pair.set_private()
                        else:
                            pair.set_public()
                        
                    pair.set_value(i[1])
                    pair.set_tags(i[3])

                    is_category_modified = True
                    
            if (to_set_tag):
                for tags, all_keys in args.set_tags:
                    for key in all_keys:
                        pair = get_pair_from_key(all_enc_pairs, key)
                        
                        if (not(pair is None)):
                            pair.set_tags(tags)
                            is_category_modified = True
                        else:
                            eprint("--set-tag: invalid key '%s'." % key)

            if (to_add_tag):
                for tags, all_keys in args.add_tags:
                    for key in all_keys:
                        pair = get_pair_from_key(all_enc_pairs, key)
                        
                        if (not(pair is None)):
                            is_category_modified += (pair.add_tags(tags) != 0)
                        else:
                            eprint("--add-tag: invalid key '%s'." % key)

            # NOTE: Change privacy of given pairs.
            if (to_set_existing_privacy):
                for key in copy_list(privacy_pairs):
                    pair = get_pair_from_key(all_enc_pairs, key)
                    
                    if (not(pair is None)):
                        if (privacy_status == PairStatus.private):
                            pair.set_private()
                        else:
                            pair.set_public()
                            
                        privacy_pairs.remove(key)
                    
                        is_category_modified = True

                for key in privacy_pairs:
                    if (privacy_status == PairStatus.private):
                        eprint("--private-pair", end="")
                    else:
                        eprint("--public-pair", end="")

                    eprint(": invalid key '%s'." % key, prog_name=False)
                    
            if (is_category_modified):
                encrypted_file.seek(0, os.SEEK_SET)

                check = encrypted_file.readline()[:-1]
                pwd_hash = encrypted_file.readline()[:-1]

                # Old signature.
                encrypted_file.readline()
                
                # for l in all_old_lines:
                #     encrypted_file.write(l)

                salt = os.urandom(AES.block_size)
                enc = AES.new(pwd_key, AES.MODE_CBC, IV=salt)

                enc_content = b"\n".join([pair.encrypt() for pair in all_enc_pairs])

                content = base64.b64encode(salt) +\
                          b"$" +\
                          base64.b64encode(enc.encrypt(pad(enc_content,
                                                           16, isBytes = True)))

                lines = [check,
                         pwd_hash,
                         b"Content = " + content]

                signature = category_sign(category_key, lines)

                encrypted_file.seek(0, os.SEEK_SET)
                # Skip user check.
                encrypted_file.readline()
                # And password hash.
                encrypted_file.readline()

                encrypted_file.write(b"Signature = " + signature + b"\n")
                encrypted_file.write(b"Content = " + content + b"\n")
                
                encrypted_file.truncate()

            encrypted_file.close()
                
            if (to_show):
                for pair in all_enc_pairs:
                    if (pair.is_private()):
                        print("%s:**** (Tags: %s)" % (pair.get_key(), pair.get_tags()))
                    else:
                        print("%s:%s (Tags: %s)" % (pair.get_key(), pair.get_value(), pair.get_tags()))

            if (to_get or to_show or to_get_tag):
                print("")

if __name__ == "__main__":
    try:
        main()
    except (KeyboardInterrupt, EOFError):
        print("")
    # except Exception as e:
    #     print("\nAn exception has occurred, sorry.")
