#!/usr/bin/python3
import os
import json

class User:
    def __init__(self, build_from: dict):
        """
        User class, used to represent a user and their properties
        :param build_from: Dict with username and user properties like: {"Test": {"uuid": "ABC123"}}
        """
        # Iterate through data for this user
        for name, config in build_from.items():
            self.raw_dict = build_from
            self.user_properties = config
            self.username = name
            self.auth_tokens = self.user_properties["auth_tokens"]
            self.pfp = self.user_properties["profile-picture"]
            # Get the user's pastes if any
            self.paste_history = {}
            # If the user has existing pastes
            if os.path.exists(f"data/{self.username}"):
                # Then iterate through those pastes and add them to the users paste history
                for file in os.listdir(f"data/{self.username}"):
                    with open(f"data/{self.username}/{file}", 'r') as paste_file:
                        self.paste_history.update({file: paste_file.read()})
    def save_theme(self, theme: dict, auth_token):
      if self.auth_valid(auth_token):
        self.raw_dict[self.username].update({'theme': theme})
        self.save_user_info()
        return {"Success": f"Set New Theme For {self.username}"}
      else:
        return {"Error": "Auth Token Not Valid"}

    def get_theme(self, auth_token):
      if self.auth_valid(auth_token):
        # Check if a theme is already set
        try:
          theme = self.raw_dict[self.username]['theme']
          return theme
        except KeyError:  # If no theme already set
          return {"Error": "No Theme Set"}
      else:
        return {"Error": "Auth Token Not Valid"}
  
    def save_user_info(self):
      """
        return: Saves the changes in self.raw_dict to the user_data.json file
      """
      with open("user_data.json", "r") as data:
        global userdata
        userdata = json.load(data)
      with open("user_data.json", "w") as user_data:
        userdata.update(self.raw_dict)
        json.dump(userdata, user_data, indent=4, sort_keys=True)
        return True
      
    def auth_valid(self, token: str):
        """
        :param token: The token to check if valid
        :return: Returns if the auth token is valid or not
        """
        token_valid = False
        for token_obj in self.auth_tokens:
            if token in token_obj.values():
                token_valid = True
        if token_valid:
            return True
        else:
            return False

    def upload(self, auth_token: str, title: str, content: str):
        """
        :param auth_token: The auth token from the login session
        :return: Uploads the input text to the user's clipboard, on fail it returns False

        """
        # Check if user authentication token is valid
        if self.auth_valid(auth_token):
            # If valid then continue with the text upload
            # Create the data directory if needed
            
            if not os.path.isdir("data"):
                os.makedirs("data")
            # Create the user's data directory if needed
            if not os.path.isdir(f"data/{self.username}"):
                os.makedirs(f"data/{self.username}")
            # If a file already exists under that name return error
            if os.path.exists(f"data/{self.username}/{title}.txt"):
                return {"Error": "Paste under that title already exists"}
            else:
                # Remove Quotation Marks If Any
                if '"' in title:
                    while '"' in title:
                        title = title.replace('"', '')
                if '"' in content:
                    while '"' in content:
                        content = content.replace('"', '')

                with open(f"data/{self.username}/{title}.txt", 'w') as new_data_upload:
                    new_data_upload.write(content)
                return {"Success": "Paste has uploaded successfully"}
        else:
            return {"Error": "Auth Token Not Valid"}

    def delete_paste(self, auth_token: str, title: str):
        """
        :param auth_token: The auth token from the login session
        :return: Uploads the input text to the user's clipboard, on fail it returns False

        """
        # Check if user authentication token is valid
        if self.auth_valid(auth_token):
            if os.path.exists(f"data/{self.username}/{title}.txt"):
                os.remove(f"data/{self.username}/{title}.txt")
                return {"Success": "Paste removed!"}
            else:
                return {"Error": "Paste doesn't exist"}
        else:
            return {"Error": "Auth Token Not Valid"}

    def get(self, auth_token: str, paste_title: str = None, fetch_most_recent_paste: bool = False):
        """
        :param auth_token: The auth token from the login session
        :param paste_title: The title of the paste to grab
        :param fetch_most_recent_paste: Whether to just fetch most recent paste
        :return: Returns the input paste from a users pastes, otherwise an error
        """
        if self.auth_valid(auth_token):
            if paste_title:
                # Check if the user actually has any valid pastes
                paste_found = False
                if self.paste_history:
                    for title, contents in self.paste_history.items():
                        title = title.replace(".txt", '')
                        if title == paste_title:
                            paste_found = True
                            return {title: contents}
                else:
                    return {"Error": "You have no existing pastes"}
        else:
            return {"Error": "Auth Token Not Valid"}
