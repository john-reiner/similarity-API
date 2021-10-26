from flask import Flask, jsonify, request
from flask_restful import Api, Resource
from pymongo import MongoClient
import bcrypt
import spacy

app = Flask(__name__)
api = Api(app)

client = MongoClient("mongodb://db:27017")
db = client.SZimilarityDB
users = db["Users"]

def user_exists(username):
    if users.find({"username":username}).count() == 0:
        return False
    else:
        return True 

def verify_password(username, password):
    if not user_exists(username):
        return False

    hashed_password = users.find({"username": username})[0]["password"]

    if bcrypt.hashpw(password.encode('utf8'), hashed_password) == hashed_password:
        return True
    else: 
        return False

def count_tokens(username):
    tokens = users.find({"username": username})[0]["tokens"]
    return tokens

class Register(Resource):
    def post(self):
        posted_data = request.get_json()

        username = posted_data["username"]
        password = posted_data["password"]

        if user_exists(username):
            return_json = {
                "status" : 301,
                "message" : "Username already exists"
            }
            return return_json

        hashed_password = bcrypt.hashpw(password.encode('utf8'), bcrypt.gensalt())

        users.insert({
            "username": username,
            "password" : hashed_password,
            "tokens" : 6
        })

        return_json = {
            "status" : 200, 
            "message" : "Signup successful!"
        }

        return return_json

class Detect(Resource):
    def post(self):
        posted_data = request.get_json()

        username = posted_data["username"]
        password = posted_data["password"]
        text_1 = posted_data["text_1"]
        text_2 = posted_data["text_2"]

        if not user_exists(username):
            return_json = {
                "status": 301,
                "message": "Invalid Username or Password"
            }
            return jsonify(return_json)

        correct_password = verify_password(username, password)

        if not correct_password:
            return_json = {
                "status" : 302,
                "message" : "Invalid Username or Password"
            }
            return jsonify(return_json)

        token_count = count_tokens(username)

        if token_count <= 0: 
            return_json = {
                "status": 303,
                "message": "Please purchase more tokens"
            }
            return jsonify(return_json)

        nlp = spacy.load("en_core_web_sm")

        text_1 = nlp(text_1)
        text_2 = nlp(text_2)

        ratio = text_1.similarity(text_2)

        return_json = {
            "status": 200,
            "similarity": ratio,
            "message": "Score calculated successful"
        }

        users.update({
            "username": username,

        },{
            "$set": {
                "tokens": token_count - 1 
            }
        })

        return jsonify(return_json)

class Refill(Resource):
    def post(self):
        posted_data = request.get_json()

        username = posted_data["username"]
        password = posted_data["password"]

        refill_amount = posted_data["refill"]

        if not user_exists(username):
            return_json = {
                "status": 301,
                "message": "Invalid Username or Password"
            }
            return jsonify(return_json)

        correct_password = "iamanadmin"

        if not correct_password:
            return_json = {
                "status" : 302,
                "message" : "Invalid Username or Password"
            }
            return jsonify(return_json)

        token_count = count_tokens(username)
        users.update({
            "username": username
        },{"$set":{
            "tokens": refill_amount + token_count
        }})

        return_json = {
            "status" : 200,
            "message" : "refill successful"
        }

        return jsonify(return_json)

class CheckUserTokens(Resource):
    def post(self):
        posted_data = request.get_json()
        if not verify_password(posted_data["username"], posted_data["password"]):
            return_json = {
                "status": 301,
                "message": "Invalid Username or Password"
            }
            return jsonify(return_json)
        else: 
            return_json = {
                "status": 200,
                "message": posted_data["username"] + " has " + str(count_tokens(posted_data["username"])) + " tokens"
            }
            return jsonify(return_json)
        

api.add_resource(Register, '/register')
api.add_resource(Detect, '/detect')
api.add_resource(Refill, '/refill')
api.add_resource(CheckUserTokens, '/tokens')

if __name__ == "__main__":
    app.run(host="0.0.0.0")