import json
import csv
import os
import crypt
import getpass
import re
import socket
import time
from cryptography.fernet import Fernet
#from Crypto.PublicKey import RSA

#Constants
FILE_NAME = "data.csv"
_KEY = b'uuPZnnZRAj1ayEkh9EB9gZMlNCFjUB1N6Iol8XPw8v0='

def login_validation(database_name, user_data, has_account):
    '''
    if has_account is true user_data will be [email,password]
    (relavent indicies will be [0] and [1])
    otherwise user_data will be [username,email,password]
    (relavent indicies will be [1] and [2]

    type(user_data) = bytes
    type(row[x]) = str

    returns (True, username) if account is found in the database,
    and (False, None) otherwise.

    :can't compare hased inputs because of random aspect of hashing
    :need to eval to turn str --> bytes then unhash_input
    '''
    username = None
    
    if has_account:
        with open(database_name, mode='r') as csv_file:
            csv_reader = csv.reader(csv_file, delimiter=',')
            for row in csv_reader:
                if unhash_input(eval(row[1])) == unhash_input(user_data[0]) and unhash_input(eval(row[2])) == unhash_input(user_data[1]):
                    username = row[0]
                    return (True, username)
        print("No account with these credentials exists")
        return (False, username)
    else:
        with open(database_name, mode='r') as csv_file:
            csv_reader = csv.reader(csv_file, delimiter=',')
            for row in csv_reader:
                if unhash_input(eval(row[1])) == unhash_input(user_data[1]) and unhash_input(eval(row[2])) == unhash_input(user_data[2]):
                    username = row[0]
                    return (True, username)
        print("No account with these credentials exists")
        return (False, username)

def email_validation(database_name, email):
    '''
    returns True if email is in use,
    False otherwise

    type(row[x]) = str
    type(email) = bytes

    :can't compare hased inputs because of random aspect of hashing
    :need to eval to turn str --> bytes then unhash_input
    '''
    with open(database_name, mode='r') as csv_file:
        csv_reader = csv.reader(csv_file, delimiter=',')
        for row in csv_reader:
            #print("row = {}\nemail = {}".format(row[1], unhash_input(email))) ###
            #print(row[1] == str(email))
            if unhash_input(eval(row[1])) == unhash_input(email):
                print("Email is already in use!")
                return True
        return False

def username_validation(database_name, username):
    '''
    returns True if username is in use,
    False otherwise
    '''
    with open(database_name, mode='r') as csv_file:
        csv_reader = csv.reader(csv_file, delimiter=',')
        for row in csv_reader:
            if row[0] == username:
                print("Username is already in use!")
                return True
        return False

def friend_validation(database_name, username):
    '''
    returns True if friend exists,
    False otherwise
    '''
    with open(database_name, mode='r') as csv_file:
        csv_reader = csv.reader(csv_file, delimiter=',')
        for row in csv_reader:
            if row[0] == username:
                return True
        return False

def detect_user_response():
    '''
    returns True if user has account,
    False otherwise
    '''
    while True:
        _answer = input().lower()
        if _answer == 'exit':
            quit()
        if _answer == 'yes':
            return True
            break
        elif _answer == 'no':
            return False
        else:
            print("please input either 'yes' or 'no'")

def invalid_input(input):
    '''
    returns True if input error detected,
    False otherwise
    '''
    b_invalid = False
    if input == 'exit' or input == 'EXIT':
        quit()
    if input.isspace():
        b_invalid = True
    if input == '':
        b_invalid = True
    if b_invalid:
        print("please give a valid input")
    return b_invalid

def password_regex(input):
    '''
    returns True if re.search()  is not None,
    False if otherwise
    :_regex: pattern to detect an uppercase, lowercase, special character(@#$), number and >8 chars
    '''
    _regex = r"^(?=.*[\d])(?=.*[A-Z])(?=.*[a-z])(?=.*[@#$])[\w\d@#$]{8,}$"
    _result = re.search(_regex, input)
    if _result:
        return True
    else:
        print("please give a password using an Uppercase, Lowercase, special character(@#$), and greater than 8 characters")
        return False

def create_database(database_name):
    '''
    creates csv file database if it doesn't exist
    '''
    file_path = os.getcwd() + "/{database}".format(database = database_name)
    if os.path.exists(file_path) == False:
        with open(database_name,"w+") as csv_file:
            print("Creating database")

def append_database(database_name, user_data):
    '''
    Append new user data to the database
    '''
    print("Appending")
    with open(database_name,"a") as csv_file:
        csv_writer = csv.writer(csv_file, delimiter = ",")
        csv_writer.writerow(user_data)

def hash_input(input):
    #return crypt.crypt(input, crypt.METHOD_SHA512)
    cipher = Fernet(_KEY)
    return cipher.encrypt(input)
    #plain_text = cipher.decrypt(cipher_text)

def unhash_input(input):
    cipher = Fernet(_KEY)
    return cipher.decrypt(input)

def add_friend(file_name, user_name, friend_name):
    '''
    creates a temp csv, copying line by line until we find the user's data,
    the appends friend to the user's friend list.
    returns True if successful and False otherwise
    '''
    with open(file_name) as in_file, open("temp_"+file_name, "w") as out_file:
        reader = csv.reader(in_file)
        writer = csv.writer(out_file)
        for row in reader:
            if row[0] == user_name:
                friend_list = eval(row[3])
                if friend_name in friend_list:
                    print("User is already in friend list")
                    return False
                else:
                    friend_list.append(friend_name)
                    row[3] = friend_list
                    writer.writerow(row)
                break
            else:
                writer.writerow(row)
        writer.writerows(reader)
        os.remove('data.csv')
        os.rename('temp_data.csv', 'data.csv')
        return True

def view_friends(file_name, user_name):
    '''
    returns friends list
    '''
    with open(file_name, mode='r') as csv_file:
        csv_reader = csv.reader(csv_file, delimiter=',')
        for row in csv_reader:
            if row[0] == user_name:
                return row[3]

def username_error(username):
    '''
    returns true if username has an error,
    false otherwise
    '''
    regex = r"^[A-Za-z0-9_-]{3,10}$"
    if re.match(regex, username):
        return False
    else:
        print("username must be between 3 and 10 characters and have no special characters")
        return True

def encode_byte(input):
    '''
    changes string to bytes
    '''
    return bytes(input, 'utf-8')

def decode_byte(input):
    '''
    changes string to bytes
    '''
    return input.decode('utf-8')

def menu_input():
    while True:
        user_input = input()
        if user_input == "exit":
            quit()
        #print("user input type: {}".format(type(user_input))) ###
        try:
            #print("in try statement")
            choice = int(user_input)
            if 1 <= choice <= 4:
                #print("in if  statement") ###
                return choice
            else:
                #print("in else statement") ###
                print("please input a valid input (1-4)")
                continue
        except:
            #print("in except statement") ###
            print("please input a valid number")
            continue


if __name__ == "__main__":
    '''
    string = 'email@email.com'
    b_string = encode_byte(string)
    hash_string = hash_input(b_string)
    print(hash_string)
    #key = Fernet.generate_key()
    cipher = Fernet(_KEY)
    cipher_text = cipher.decrypt(hash_string)
    print(cipher_text)
    #plain_text = cipher.decrypt(cipher_text)
    #print(plain_text)
    quit()
    '''
    print("**********************************************************")
    print("*********** REMINDER: type 'exit' at any time to quit ***********")
    print("**********************************************************")
    print("Do you have an account? (yes/no)")
    has_account = detect_user_response()

    login_status = False
    user_data = []
    current_user = None
    
    if not has_account:
        create_database(FILE_NAME)
        
        while True:
            print("Enter a username for your account:")
            username = input()
            if invalid_input(username):
                continue
            if username_error(username):
                continue
            #user_data.append(username)
            username_used = username_validation(FILE_NAME, username)
            if not username_used:
                user_data.append(username) #!
                break
            
        while True:
            print("Enter an email for your account:")
            email = input()
            if invalid_input(email):
                continue
            #user_data.append(hash_input(user_email))
            hashed_email = hash_input(encode_byte(email))
            email_used = email_validation(FILE_NAME, hashed_email)
            if not email_used:
                user_data.append(hashed_email)
                break
            
        while True:
            password = getpass.getpass("enter desired password:")
            if not password_regex(password):
                continue
            hashed_password = hash_input(encode_byte(password))
            user_data.append(hashed_password)
            break

        #Add friends list
        user_data.append([])

        
        append_database(FILE_NAME, user_data)
        login_status, current_user = login_validation(FILE_NAME, user_data, has_account)
        if not login_status:
            print("Database failed to update for unknown reason. Login Failed.")
            quit()

    else:
        attempts = 0
        while True:
            if attempts > 3:
                print("Exceeded number of acceptable attempts. Login Failed.")
                quit()
            print("Enter your email:")
            user_email = input()
            if invalid_input(user_email):
                continue
            user_data.append(hash_input(encode_byte(user_email)))
            password = getpass.getpass("Enter your password:")
            if invalid_input(password):
                continue
            user_data.append(hash_input(encode_byte(password)))

            try:
                login_status, current_user = login_validation(FILE_NAME, user_data, has_account)
                if login_status:
                    break
                else:
                    attempts += 1
                    print("Please retry your credentials")
                    continue
            except:
                print("Error: database doesn't exist. Create account first.")
                quit()

    print("Login successful")    
    while True:
        print("---------------------------------------------------------------------")
        print("Would you like to:\n 1: view friend's list\n 2: Add a friend\n 3: Send a message\n 4: Exit")
        if current_user == None:
            print("Error: current user is unknown. exiting.")
            quit()
        choice = menu_input()
        #print("choice = {} and choice type =  {}".format(choice,type(choice))) ###
        if choice == 1:
            print("Friends List: ")
            print(view_friends(FILE_NAME, current_user))
            continue
        elif choice == 2:
            while True:
                print("Enter the Friend's username.")
                new_friend = input();
                if username_error(new_friend):
                    continue
                if friend_validation(FILE_NAME, current_user):
                    add_status = add_friend(FILE_NAME, current_user, new_friend)
                    if add_status:
                        print("{} successfully added to your friends list".format(new_friend))
                        break
                    else:
                        print("{} failed to be added to your friends list".format(new_friend))
                        break
                else:
                    print("{} does not exist in the database".format(new_friend))
                    break                    
        elif choice == 3:
            print("to do")
            continue
        elif choice == 4:
            print("Exiting.")
            quit()
    #key = RSA.generate(2048)
    #private_key = key.export_key()
    #file_out = open("private.pem", "wb")
    #file_out.write(private_key)
    #print(key)
    #test if files append when you already have an account, and that login only occurs when account is found.
    #end
    quit()
