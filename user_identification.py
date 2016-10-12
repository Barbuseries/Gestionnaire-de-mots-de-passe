#!/usr/bin/python
import bcrypt

def user_identification_test():
    password = b"super secret password"
    hashed = bcrypt.hashpw(password, bcrypt.gensalt())
    print password
    print hashed

if __name__ == "__main__":
    user_identification_test()
    
