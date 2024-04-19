from flask import Flask, request, jsonify,session, abort, redirect, request
from flask_cors import CORS
import requests
from flask_pymongo import PyMongo
import json
import pathlib
import os
# from dotenv import load_dotenv, find_dotenv
import openai
from google.oauth2 import id_token
from google_auth_oauthlib.flow import Flow
from pip._vendor import cachecontrol
import google.auth.transport.requests
import jwt
import json
from flask import Flask 
from flask.wrappers import Response
from flask.globals import request, session
import requests
from werkzeug.exceptions import abort
from werkzeug.utils import redirect
from google.oauth2 import id_token
from google_auth_oauthlib.flow import Flow
import os, pathlib
import google
import jwt
from flask_cors import CORS




os.environ["OPENAI_API_KEY"] = "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"

 
# Initialize Flask app

app = Flask(__name__)
CORS(app)
app.config['Access-Control-Allow-Origin'] = '*'
app.config["Access-Control-Allow-Headers"]="Content-Type"

app.config["MONGO_URI"] = "mongodb://localhost:27017/openai"
mongo = PyMongo(app)
app.secret_key = "CodeSpecialist.com"
os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"
GOOGLE_CLIENT_ID = "988079925262-vtnchngt8f779f2tb92qj2ta2uiqbtsp.apps.googleusercontent.com"
client_secrets_file = os.path.join(pathlib.Path(__file__).parent, "client_secret.json")
 

flow = Flow.from_client_secrets_file(
    client_secrets_file=client_secrets_file,
    scopes=[
        "https://www.googleapis.com/auth/userinfo.profile",
        "https://www.googleapis.com/auth/userinfo.email",
        "openid",
    ],
    redirect_uri="http://127.0.0.1:5000/callback",
)


# wrapper
def login_required(function):
    def wrapper(*args, **kwargs):
        encoded_jwt=request.headers.get("Authorization").split("Bearer ")[1]
        if encoded_jwt==None:
            return abort(401)
        else:
            return function()
    return wrapper


def Generate_JWT(payload):
    encoded_jwt = jwt.encode(payload, app.secret_key, algorithm='HS256')
    return encoded_jwt


@app.route("/callback")
def callback():
    flow.fetch_token(authorization_response=request.url)
    credentials = flow.credentials
    request_session = requests.session()
    token_request = google.auth.transport.requests.Request(session=request_session)

    id_info = id_token.verify_oauth2_token(
        id_token=credentials._id_token, request=token_request,
        audience=GOOGLE_CLIENT_ID
    )
    session["google_id"] = id_info.get("sub")
    
    # removing the specific audience, as it is throwing error
    del id_info['aud']
    jwt_token=Generate_JWT(id_info)
    data={
        'name':id_info.get('name'),
        'email':id_info.get('email'),
        'picture':id_info.get('picture')
    }
    mongo.db.users.insert_one(data)
    return redirect(f"http://localhost:5173/chat?jwt={jwt_token}")
    """ return Response(
        response=json.dumps({'JWT':jwt_token}),
        status=200,
        mimetype='application/json')
    ) """


@app.route("/auth/google")
def login():
    authorization_url, state = flow.authorization_url()
    # Store the state so the callback can verify the auth server response.
    session["state"] = state
    return Response(
        response=json.dumps({'auth_url':authorization_url}),
        status=200,
        mimetype='application/json'
    )


@app.route("/logout")
def logout():
    #clear the local storage from frontend
    session.clear()
    return Response(
        response=json.dumps({"message":"Logged out"}),
        status=202,
        mimetype='application/json'
    )


@app.route("/home")
@login_required
def home_page_user():
    encoded_jwt=request.headers.get("Authorization").split("Bearer ")[1]
    try:
        decoded_jwt=jwt.decode(encoded_jwt, app.secret_key, algorithms=['HS256',])
        print(decoded_jwt)
    except Exception as e: 
        return Response(
            response=json.dumps({"message":"Decoding JWT Failed", "exception":e.args}),
            status=500,
            mimetype='application/json'
        )
    return Response(
        response=json.dumps(decoded_jwt),
        status=200,
        mimetype='application/json')


@app.route('/get_response', methods=['POST'])
def chatgpt():
    # Get data from the request
    data = request.get_json()
    user_input = data.get("user_input")  # Extract the user input from the JSON data
    # Create a response using the OpenAI API
    response = openai.Completion.create(
        engine="text-davinci-003",  # Use "text-davinci-003" as the engine
        prompt=user_input,
        max_tokens=3000,  # Limit the response to a certain number of tokens
        temperature=0.7  # Adjust the temperature parameter
    )
    reply={
            "user_input":user_input,
            "response":response.choices[0].text
        }
    # Extract and return the response text
    return jsonify(reply),201

@app.route('/get-history',methods=['GET'])
def get_history():
    userd = mongo.db.test.find({})
    serialized_user_data = []
    for user in userd:
        user['_id'] = str(user['_id'])
        serialized_user_data.append(user)
    return jsonify(serialized_user_data), 201

@app.route('/save-history',methods=['POST'])
def save_history():
    try:
        # Get JSON data from the request
        response_data = request.get_json()
        if not response_data:
            print("Error: The response_data list is empty.")
        else:
    # Proceed with processing the data
            json_dict = {'chatd':response_data}
            print(json_dict)
            mongo.db.test.insert_one(json_dict)
            # Return a JSON response indicating success
        return jsonify({'message': 'Data inserted successfully'}), 201
    except Exception as e:
        # Handle exceptions (e.g., invalid JSON, database errors)
        return jsonify({'error': str(e)}), 500
 

if __name__ == '__main__':

    app.run(host='0.0.0.0', port=5000, debug=True)