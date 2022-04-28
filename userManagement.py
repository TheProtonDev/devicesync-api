#!/usr/bin/python3
import os
import string
import random
import json  # Import json to comprehend the local user_data.json file
from user import User
from datetime import datetime  # Import date time for logging time when necessary
import colorama
import bcrypt

def load_users():
    """
    @return: Returns the config for the server, creates one if one does not exist and returns a blank dict
    """
    # Check if file exists
    try:
        # If the file exists: load contents into dict by opening the config file for this server and using
        # json.load()
        with open("user_data.json", 'r') as user_data:
            return json.load(user_data)  # Return the loaded json as a dict
    except FileNotFoundError as error:
        # If the file doesn't exist: create the file and a blank dict to be added to it on the next save_config()
        os.system("touch user_data.json")
        return {}  # Return blank dict
    except json.JSONDecodeError as error:
        # Log the error
        print(colorama.Fore.RED+"Error Reading user_data.json file\nReturning blank dict for user operations"+colorama.Fore.RESET)
        print(colorama.Fore.RED+str(error)+colorama.Fore.RESET)
        # If the file is blank, return an empty dict to be used with it
        return {}  # Return blank dict


class UserManagement:
    """
    This class has methods that manage users
    """

    def __init__(self):
        # Try to load the user_data.json file
        self.user_file = load_users()

    """
    Methods Managing User Data
    """

    def save_userdata(self):
        """
        :return: Saves the changes in self.user_file to the user_data.json file
        """
        with open("user_data.json", "w") as user_data:
            json.dump(self.user_file, user_data, indent=4, sort_keys=True)
            return True

    def get_user_obj(self, user):
        """
        :param user: The user to get
        :return: Returns a dict with the name of the user and all their data as the value
        """
        # Iterate through the user_data
        for item, value in self.user_file.items():
            if item == user:
                return User({item: value})

    """
    Methods relating to user sign in and sign up
    """

    def add_new_auth_token(self, user: str, password: str = None, new_user=False):
        """
        :param new_user: Whether the user the token is being added for is new
        :param user: The user to add a new auth token for
        :param password: The password for the user if new
        :return: Handles the creation of new user auth tokens, and adds them to the valid auth token list for that user
        """
        auth_token = self.generate_auth_token()
        if not new_user:
            self.user_file[user]["auth_tokens"].append({datetime.now().strftime("%m/%d/%Y"): auth_token})
            self.save_userdata()
            return {"username": user, "auth_token": auth_token}
        else:
            self.user_file.update(
                {user: {"password": password,'profile-picture': f"https://avatars.dicebear.com/api/identicon/{user}.svg" ,"auth_tokens": [{datetime.now().strftime("%m/%d/%Y"): auth_token}]}})
            # Write to user_data.json
            self.save_userdata()
            return {"username": user, "auth_token": auth_token}

    def generate_auth_token(self):
        """
        :return: String with 32 random letters and numbers
        """
        # Create a chars list with all possible alphabetical characters and numbers
        chars = string.ascii_uppercase + string.digits
        generated_id = ''.join(random.choice(chars) for _ in range(32))
        return generated_id

    def does_user_exist(self, username):
        """
        :param username: The username to check if exists
        :return: Whether an account with the input username already exists
        """
        user_exists = False
        if not os.path.exists("user_data.json"):
            file = open("user_data.json", 'w')
        else:
            for user in self.user_file:
                if username == user:
                    user_exists = True
        return user_exists

    def check_auth_validity(self, username, auth_token):
        if not self.user_file == {}:
            if self.does_user_exist(username):
                found = False
                for session in self.user_file[username]['auth_tokens']:
                    for date, token in session.items():
                        if token == auth_token:
                            found = True
                if found:
                    return {"Success": "Authentication Token Valid"}
                else:
                    return {"Error": "Authentication Session Is Invalid"}
            else:
              return {"Error": "Authentication Session Is Invalid"}
        else:
            return {"Error": "No accounts exist"}

    def create_user(self, user, password):
        """
        :param user: The username of the account being created
        :param user: The password for the account being created
        :return: Creates a user with the specified information, returns the auth token and user for this login session
        """
        # Check if the username already exists
        username_already_exists = self.does_user_exist(user)
        if not username_already_exists:
            # If the username doesn't exist, follow through with the registration
            user_login_session = self.add_new_auth_token(user, password=password, new_user=True)
            # Create user data directory
            return user_login_session
        return {"Error": "User already exists"}

    def signin(self, username: str, password: str):
        """
        :param username: The username of the user signing in
        :param password: The password of the user signing in
        :return: Check if the input login combo is valid, if so returns an access token, if else then false
        """
        login_correct = False
        # Iterate through the valid logins and check if the user and password are valid
        for user in self.user_file:
            if user == username:
                correct_password = self.user_file[user]["password"]
                # As far as I know (I'm not a cryptography genius.) this is a secure comparison between the stored password hash and the password being tried
                if bcrypt.checkpw(password.encode('utf8'), correct_password.encode('utf8')):
                    login_correct = True

        if login_correct:
            # Add auth token to user valid auth tokens values
            added_auth_token = self.add_new_auth_token(username)
            return added_auth_token
        else:
            return False

    def logout(self, username: str, auth_token_to_remove: str):
        """
        :param username: The username of the user logging out
        :param auth_token_to_remove: The auth token of the current session being left
        :return: Logs out the user
        """
        # If userfile is not blank
        if not self.user_file == {}:
            # If the userfile is not blank, proceed with removing the user login session using the input auth_token
            # Iterate through the auth sessions and find the one with the corresponding auth_token
            counter = 0
            found = False
            for session in self.user_file[username]["auth_tokens"]:
                for session_date, session_token in session.items():
                    if session_token == auth_token_to_remove:
                        found = True
                    if found:
                        break
                    counter += 1
            if found:
                self.user_file[username]["auth_tokens"].pop(counter)
                self.save_userdata()
                return {"Success": f"Successfully Signed Out {username} and invalidated {auth_token_to_remove}"}
            if not found:
                return {"Error": "That authentication session does not exist"}

        else:
            return {"Error": "No accounts exist"}
