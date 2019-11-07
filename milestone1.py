import json
import os
import crypt
import getpass

#Constants
file_name = "data.json"

def login_validation(database_name, user_dict):
    '''
    returns True if account is found in the database,
    and False otherwise.
    '''
   # account_exists = False
    with open(database_name, 'r') as file:
        data = file.read()
    data += '\n]'
    info = json.loads(data)
    for account in info:
        if account['email'] == user_dict['email'] and account['password'] == user_dict['password']:
            return True
    print("email and password were not a match")
    return False

def email_validation(database_name, user_dict):
    '''
    returns True if email is in use,
    False otherwise
    '''
    with open(database_name, 'r') as file:
        data = file.read()
    data += '\n]'
    info = json.loads(data)
    for account in info:
        if account['email'] == user_dict['email']:
            print("Email is already in use!")
            return True
    return False

def detect_user_status():
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
    if input == 'exit':
        quit()
    if input.isspace():
        b_invalid = True
    if input == '':
        b_invalid = True
    if len(input) < 4:
        b_invalid = True
    if b_invalid:
        print("please give a valid non empty input >4 characters")
    return b_invalid

def database_handler(file_name, user_dictionary):
    '''
    creates database if the json file isn't created,
    and appends to database otherwise
    '''
    file_path = os.getcwd() + "/{}".format(file_name)
    if os.path.exists(file_path) == False:
        print("Creating new File")
        with open(file_name,"w+") as file:
            file.write('[\n')
            json.dump(user_dictionary, file, indent=4)
    else:
        print("Appending")
        with open(file_name,"a") as file:
            file.write(',\n')
            json.dump(user_dictionary, file, indent=4)

def hash_password(password):
    return crypt.crypt(password, crypt.METHOD_SHA512)

if __name__ == "__main__":
    print("**********************************************************")
    print("*********** REMINDER: type 'exit' at any time to quit ***********")
    print("**********************************************************")
    print("Do you have an account? (yes/no)")
    has_account = detect_user_status()

    user_dictionary = {"email":"", "password":""}
    if not has_account:
        while True:
            print("Enter an email for your account:")
            user_dictionary['email'] = input()
            if invalid_input(user_dictionary['email']):
                continue
            email_used = email_validation(file_name, user_dictionary)
            if not email_used:
                break
        while True:
            user_dictionary['password'] = getpass.getpass("enter desired password:")
            if invalid_input(user_dictionary['password']):
                continue
            user_dictionary['password'] = hash_password(user_dictionary['password'])
            database_handler(file_name, user_dictionary)
            break
    else:
        while True:
            print("Enter your email:")
            user_dictionary['email'] = input()
            if invalid_input(user_dictionary['email']):
                continue
            user_dictionary['password'] = getpass.getpass("Enter your password:")
            if invalid_input(user_dictionary['password']):
                continue
            user_dictionary['password'] = hash_password(user_dictionary['password'])
            break

    login_status = login_validation(file_name, user_dictionary)
    if login_status:
        print("Login successful")
    else:
        print("Login failed. Exiting")

    #test if files append when you already have an account, and that login only occurs when account is found.
    #end
    quit()
