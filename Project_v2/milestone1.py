import json
import csv
import os
import crypt
import getpass
import re
from Crypto.PublicKey import RSA

#Constants
FILE_NAME = "data.csv"

def login_validation(database_name, user_data, has_account):
    '''
    if has_account is true user_data will be [email,password]
    (relavent indicies will be [0] and [1])
    otherwise user_data will be [username,email,password]
    (relavent indicies will be [1] and [2]

    returns (True, username) if account is found in the database,
    and (False, None) otherwise.
    '''
    username = None
    
    if has_account:
        with open(database_name, mode='r') as csv_file:
            csv_reader = csv.reader(csv_file, delimiter=',')
            for row in csv_reader:
                if row[1] == user_data[0] and row[2] == user_data[1]:
                    username = row[0]
                    return (True, username)
        print("No account with these credentials exists")
        return (False, username)
    
    else:
        with open(database_name, mode='r') as csv_file:
            csv_reader = csv.reader(csv_file, delimiter=',')
            for row in csv_reader:
                if row[1] == user_data[1] and row[2] == user_data[2]:
                    username = row[0]
                    return (True, username)
        print("No account with these credentials exists")
        return (False, username)

def email_validation(database_name, email):
    '''
    returns True if email is in use,
    False otherwise
    '''
    with open(database_name, mode='r') as csv_file:
        csv_reader = csv.reader(csv_file, delimiter=',')
        for row in csv_reader:
            if row[1] == email:
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

def detect_user_response():
    '''
    returns True if user has account,
    False otherwise
    '''
    while True:
        _answer = input().lower()
        if _answer == 'quit':
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
    return crypt.crypt(input, crypt.METHOD_SHA512)

def add_friend(file_name, user_name, friend_name):
    '''
    creates a temp csv, copying line by line until we find the user's data,
    the appends friend to the user's friend list.
    returns True if successful and False otherwise
    '''
    with open(file_name) as in_file, open(file_name_ + "temp", "w") as out_file:
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

def username_error(username):
    '''
    returns true if username has an error,
    false otherwise
    '''
    if (3 <= len(username) <= 10):
        return False
    else:
        print("username must be between 3 and 10 characters")
        return True

if __name__ == "__main__":
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
            hashed_email = hash_input(email)
            email_used = email_validation(FILE_NAME, hashed_email)
            if not email_used:
                user_data.append(hashed_email)
                break
            
        while True:
            password = getpass.getpass("enter desired password:")
            if not password_regex(password):
                continue
            hashed_password = hash_input(password)
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
            user_data.append(hash_input(user_email))
            password = getpass.getpass("Enter your password:")
            if invalid_input(password):
                continue
            user_data.append(hash_input(password))

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
        print("Would you like to add a user to your friends list? (or quit)")
        answer = detect_user_response()
        if answer:
            print("input friend's user name.")
            new_friend = input();
            if username_validation:
                add_status = add_friend(FILE_NAME, current_user, new_friend)
                if add_status:
                    print("{friend} successfully added to your friends list".format(new_friend))
                else:
                    print("{friend}not added to your friends list".format(new_friend))
            else:
                print("{friend} does not exist in the database".format(new_friend))
        else:
            break
    #key = RSA.generate(2048)
    #private_key = key.export_key()
    #file_out = open("private.pem", "wb")
    #file_out.write(private_key)
    #print(key)
    #test if files append when you already have an account, and that login only occurs when account is found.
    #end
    quit()
