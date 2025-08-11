from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin
from pymongo import MongoClient
from bson.objectid import ObjectId

client = MongoClient('mongodb+srv://yzhang850:a237342160@cluster0.cficuai.mongodb.net/?retryWrites=true&w=majority&authSource=admin')
db = client.cti_platform

class User(UserMixin):
    def __init__(self, user_doc):
        self.id = str(user_doc['_id'])
        self.username = user_doc['username']
        self.password_hash = user_doc['password']
        self.role = user_doc.get('role', 'public')
        self.interests = user_doc.get('interests', [])

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

def get_user_by_username(username):
    user_doc = db.users.find_one({'username': username})
    return User(user_doc) if user_doc else None

def get_user_by_id(user_id):
    user_doc = db.users.find_one({'_id': ObjectId(user_id)})
    return User(user_doc) if user_doc else None

def create_user(username, password, role='public', interests=None):
    if db.users.find_one({'username': username}):
        return False
    hashed = generate_password_hash(password)
    db.users.insert_one({
        'username': username,
        'password': hashed,
        'role': role,
        'interests': interests or []
    })
    return True