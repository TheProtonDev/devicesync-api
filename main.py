#!/usr/bin/python3
# Production Server Imports:
from gevent import monkey
monkey.patch_all() # Makes async stuff gevent friendly for the production server
from flask_compress import Compress
from gevent.pywsgi import WSGIServer
# Server imports
from flask import Flask, render_template, jsonify, request, redirect
from flask_cors import CORS, cross_origin
from werkzeug.utils import secure_filename
# Other needed imports
import os
from userManagement import UserManagement
import json


#############################################################
# Useful functions
#############################################################

def is_img(filename: str):
    """
    @param filename: The name of the file to check the extension of
    @return: Whether the input file is an image file
    """
    valid_extensions = ['png', 'jpg', 'jpeg']  # List of valid image extensions
    # Return whether the file has an extension AND has a valid image extension in the list
    return '.' in filename and filename.split('.', 1)[1].lower() in valid_extensions

def is_json(filename: str):
    """
    @param filename: The name of the file to check the extension of
    @return: Whether the input file is an json file
    """
    # Return whether the file has an extension AND has a json extension
    return '.' in filename and filename.split('.', 1)[1].lower() == "json"

def is_missing_needed_arg(args: dict):
    """
    @param args: Request args dict: {"value_name": request.args.get('value_name')}
    @return: Checks if a set of required parameters input through a dict are all filled out in a API request
    """
    missing_args = ""
    missing = 0
    for arg, value in args.items():
        if not value:
            if missing != 0:
                missing_args += f", {arg}"
                missing += 1
            else:
                missing_args += f"{arg}"
                missing += 1
    if missing != 0:
        missing_msg = f"Missing {missing} out of {len(args)} required arguments. You are missing " + missing_args
        return missing_msg
    else:
        return False


#############################################################
# Flask Setup
#############################################################

# Initialize Flask Application
app = Flask("app")
CORS(app)  # Enable Cross-Origin Resource Sharing

# Production Server Code
compress = Compress()
compress.init_app(app)

#############################################################
# Flask Routes
#############################################################

@app.route("/")
@cross_origin()
def index():
    """
    @return: Index page of application
    """
    return render_template("index.html")


# TODO: DOCUMENTATION!!!
@app.route("/docs")
@cross_origin()
def docs():
    """
    @return: Redirects user to what will eventually be the API documentation
    """
    return redirect("https://github.com/TheProtonDev/DeviceSyncApp/blob/main/API_Usage.md", code=302)


#############################################################
# DeviceSync API Functions
#############################################################

@app.route("/status")
@cross_origin()
def status():
    """
    Function used in the web app to check the status of DeviceSync
    """
    return "API Status: Up"


#############################################################
# DeviceSync Profile Picture Endpoints
#############################################################

# TODO: Work On Set PFP Endpoint

@app.route("/getpfpfor", methods=['GET', 'POST'])
@cross_origin()
def getpfpfor():
    """
    @return: JSON Object containing profile picture for user
    Input:
    username: The name of the user to get the profile picture for
    """
    # Get username arg
    username = request.args.get('username')

    # Check for missing args
    missing_args = is_missing_needed_arg({"username": username})
    if not missing_args:
        user_manager = UserManagement()  # Initialize instance of UserManagement class
        user_valid = user_manager.does_user_exist(username)  # Check if the username is valid
        if user_valid:  # If the user is valid go through with signing in
            # Try to sign in using the input username and password
            user = user_manager.get_user_obj(username)
            return {"pfp": user.pfp}
        else:
            return {"Error": f"{username} Doesn't Exist"}
    else:  # API errors on missing argument
        return {"Error": missing_args}


# TODO: FINISH UPLOADPFP
@app.route("/setpfp", methods=["GET", "POST"])
@cross_origin()
def setpfp():
    """
    @return:
    Input:
    username: The name of the user to set the profile picture for
    auth_token: The auth token from the user's authentication tokenWh
    """
    username = request.args.get('username')
    auth_token = request.args.get('auth_token')
    # Credit to: https://roytuts.com/python-flask-rest-api-file-upload/
    # This part was annoying

    # If file not included
    if 'file' not in request.files:
        resp = jsonify({'Error': 'No file included in the request'})
        resp.status_code = 400
        return resp

    file = request.files['file']
    # If the file was blank
    if file.filename == '':
        resp = jsonify({'Error': 'No file selected for uploading'})
        resp.status_code = 400
        return resp
    # If the file seems valid, proceed
    if file and is_img(file.filename):
        filename = secure_filename(file.filename)
        name, file_extension = os.path.splitext(filename)
        file.save(os.path.join("static", "pfps", f"{name}{file_extension}"))
        # Process Image
        resp = jsonify({'Success': ""})
        resp.status_code = 201
        return resp
    else:
        resp = jsonify({'Error': 'Allowed file types are png, jpg, jpeg'})
        resp.status_code = 400
        return resp

#############################################################
# DeviceSync Account Authorization Endpoints
#############################################################
@app.route("/isAuthValid", methods=["GET", "POST"])
@cross_origin()
def is_auth_valid():
    username = request.args.get('username')
    auth_token = request.args.get('auth_token')
    missing_args = is_missing_needed_arg({"username": username, "auth_token": auth_token})
    if not missing_args:
        return UserManagement().check_auth_validity(username, auth_token)
    else:  # API errors on missing argument
        return {"Error": missing_args}


@app.route("/signup", methods=["GET", "POST"])
@cross_origin()
def signup():
    """
    @return: Attempts to sign a user up if all requirements are met(not an existing user and has a secure password)
    Input:
    username: The name of the user signing up
    password: The password being set for the account being created
    """
    username = request.args.get('username')
    password = request.args.get('password')

    missing_args = is_missing_needed_arg({"username": username, "password": password})
    if not missing_args:
        user_manager = UserManagement()
        # If the API signup function is called
        # Load the valid users to check if the username is valid
        user_already_exists = user_manager.does_user_exist(username)
        # If the user doesn't already exist then go through with account creation
        if not user_already_exists:
            if len(password) < 8:
                return {"Error": "Please make sure your password is at least 8 characters long"}
            else:
                create_user = user_manager.create_user(user=username, password=password)
                if create_user:  # If the user is successfully created
                    return create_user
        else:
            return {"Error": "User Already Exists Under That Name!"}
    else:  # API errors on missing argument
        return {"Error": missing_args}


@app.route("/signin", methods=['GET', 'POST'])
@cross_origin()
def signin():
    """
    @return: Attempts to sign a user in if all requirements are met(an existing user and is valid password)
    Input:
    username: The name of the user signing in
    password: The password being set for the account being signed into
    """
    # Get username and password args, if any
    username = request.args.get('username')
    password = request.args.get('password')

    # Check for missing args
    missing_args = is_missing_needed_arg({"username": username, "password": password})
    if not missing_args:
        user_manager = UserManagement()  # Initialize instance of UserManagement class
        user_valid = user_manager.does_user_exist(username)  # Check if the username is valid
        if user_valid:  # If the user is valid go through with signing in
            # Try to sign in using the input username and password
            signin = user_manager.signin(username, password)
            return signin or {"Error": "Invalid Password"}  # If the signin fails return "Invalid Login"
        else:
            return {"Error": f"{username} Doesn't Exist"}
    else:  # API errors on missing argument
        return {"Error": missing_args}


@app.route("/logout", methods=['GET', 'POST'])
@cross_origin()
def logout():
    """
    @return: Attempts to log a user out
    Input:
    username: The name of the user signing up
    auth_token: The authentication token to revoke and invalidate
    """
    # Get username and uuid args, if any
    username = request.args.get('username')
    auth_token = request.args.get('auth_token')
    missing_args = is_missing_needed_arg({"username": username, "auth_token": auth_token})
    # If the username and uuid are both input by the user
    if not missing_args:
        user_manager = UserManagement()  # Initialize instance of UserManagement class
        user_valid = user_manager.does_user_exist(username)  # Check if the username is valid
        if user_valid:  # If the user is valid go through with signing in
            # Try to sign in using the input username and UUID
            signout = user_manager.logout(username, auth_token)
            return signout or {"Error": "Invalid auth token"}
        else:
            return {"Error": "User does not exist"}
    else:
        return {"Error": missing_args}


#############################################################
# DeviceSync Theming Endpoints | To Be Used In Future Update
#############################################################
@app.route("/settheme", methods=["GET", "POST"])
@cross_origin()
def settheme():
    """
    Method that sets a theme for a user
    """
    username = request.args.get("username")
    auth_token = request.args.get("auth_token")
    # Load input theme, if error occurs, then return the error
    try:
        theme_json = request.get_json()
        if theme_json == None:
          return {'Error': "No Theme Input"}
    except json.JSONDecodeError as error:
        return {'Error': f"Error Parsing Input Theme: {error}"}

    missing_args = is_missing_needed_arg(
        {"username": username, "auth_token": auth_token})

    user_manager = UserManagement()
    if not missing_args:
        user = user_manager.get_user_obj(username)
        return user.save_theme(theme_json, auth_token)
    else:
        return {"Error": missing_args}


@app.route("/gettheme", methods=["GET", "POST"])
@cross_origin()
def gettheme():
    """
    Method that uploads and removes data for a user
    """
    username = request.args.get("username")
    auth_token = request.args.get("auth_token")
    missing_args = is_missing_needed_arg({"username": username, "auth_token": auth_token})
    user_manager = UserManagement()
    if not missing_args:
        user = user_manager.get_user_obj(username)
        return user.get_theme(auth_token)
    else:
        return {"Error": missing_args}


#############################################################
# DeviceSync Paste Management Endpoints
#############################################################


@app.route("/delete", methods=["GET", "POST"])
@cross_origin()
def delete():
    """
    @return: Deletes the input paste if parameters are valid
    Input:
    username: The name of the user to remove the paste for
    auth_token: The authentication token for the user
    paste_title: Title of the paste to remove
    """
    username = request.args.get("username")
    auth_token = request.args.get("auth_token")
    paste_title = request.args.get("paste_title")

    missing_args = is_missing_needed_arg({"username": username, "auth_token": auth_token, "paste_title": paste_title})

    user_manager = UserManagement()
    if username and auth_token and paste_title:
        if paste_title:
            user = user_manager.get_user_obj(username)
            return user.delete_paste(auth_token, paste_title)
    else:
        return {"Error": missing_args}


@app.route("/upload", methods=["GET", "POST"])
@cross_origin()
def upload():
    """
    @return: Uploads input paste for user if parameters are valid
    Input:
    username: The name of the user uploading the paste
    auth_token: The authentication token of the user uploading the paste
    paste_title: The title of the paste to upload
    paste: The contents of the paste to upload
    """
    username = request.args.get("username")
    auth_token = request.args.get("auth_token")
    paste_title = request.args.get("paste_title")
    paste = request.args.get("paste")

    user_manager = UserManagement()

    missing_args = is_missing_needed_arg(
        {"username": username, "auth_token": auth_token, "paste_title": paste_title, "paste": paste})

    if not missing_args:
        if paste and paste_title:
            user = user_manager.get_user_obj(username)
            if user:
                uploaded = user.upload(auth_token=auth_token, title=paste_title, content=paste)
                if uploaded:
                    # If the upload succeeded
                    return uploaded
                else:
                    return {"Error:": "Upload Error: Does a paste already exist under that name?"}
            else:
                return {"Error": f"{username} does not exist"}
    else:
        return {"Error": missing_args}


@app.route("/get", methods=["GET", "POST"])
@cross_origin()
def get():
    """
    @return: Gets the input paste object by name
    Input:
    username: The name of the user to retrieve the paste for
    auth_token: The authentication token of the user uploading the paste
    history: Boolean whether to just return all the user's pastes
    """
    username = request.args.get("username")
    auth_token = request.args.get("auth_token")
    history = request.args.get("history")
    paste_title = request.args.get("paste_title")

    user_manager = UserManagement()
    missing_args = is_missing_needed_arg(
        {"username": username, "auth_token": auth_token, "paste_title": paste_title})

    if not missing_args and not history:
        user = user_manager.get_user_obj(username)
        if not user:
            return {"Error:": "User does not exist"}
        else:
            try_get = user.get(auth_token=auth_token, paste_title=paste_title)
            return try_get
    elif history and username and auth_token:
        user = user_manager.get_user_obj(username)
        if not user:
            return {"Error:": "User does not exist"}
        else:
            if user.auth_valid(auth_token):
                formatted_paste_history = {}
                for paste_title, paste in user.paste_history.items():
                    formatted_paste_history.update({paste_title.replace(".txt", ''): paste})
                return formatted_paste_history or {"Error": f"{username} has no existing pastes"}
            else:
                return {"Error:": "Invalid Auth Token"}
    else:
        return {"Error": missing_args}

@app.route("/searchPastes", methods=["GET", "POST"])
@cross_origin()
def search_pastes():
    """
    @return: Gets paste objects that match search query
    Input:
    username: The name of the user to retrieve the paste for
    auth_token: The authentication token of the user uploading the paste
    query: The string to find in paste titles
    """
    username = request.args.get("username")
    auth_token = request.args.get("auth_token")
    query = request.args.get("query")

    user_manager = UserManagement()
    missing_args = is_missing_needed_arg(
        {"username": username, "auth_token": auth_token, "query": query})

    if not missing_args:
        user = user_manager.get_user_obj(username)
        if not user:
            return {"Error:": "User does not exist"}
        else:
            if user.auth_valid(auth_token):
                formatted_paste_history = {}
                for paste_title, paste in user.paste_history.items():
                    formatted_paste_history.update({paste_title.replace(".txt", ''): paste})
                # Search for query substring
                if formatted_paste_history:
                  search_results = formatted_paste_history.copy()
                  for paste_title, paste in formatted_paste_history.items():
                    # Remove paste if neither fields contain query substring
                    if query.lower() not in paste_title.lower() and query.lower() not in paste.lower():
                      search_results.pop(paste_title)
                return search_results or {"Error": f"No Pastes Were Found Containing '{query}'"}
            else:
                return {"Error:": "Invalid Auth Token"}
    else:
        return {"Error": missing_args}
      
# Runs program
if __name__ == "__main__":
    # Dev Server
    # app.run(host='0.0.0.0', port=8080)
  
    # Production Server
    http_server = WSGIServer(('0.0.0.0', 8080), app)
    http_server.serve_forever()
