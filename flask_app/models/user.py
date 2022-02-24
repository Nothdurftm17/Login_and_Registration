from flask import flash
from flask_bcrypt import Bcrypt
from flask_app.config.mysqlconnection import connectToMySQL

import re 

EMAIL_REGEX = re.compile(r'^[a-zA-Z0-9.+_-]+@[a-zA-Z0-9._-]+\.[a-zA-Z]+$')

class User:
    def __init__(self,data):
        self.id = data['id']
        self.first_name = data['first_name']
        self.last_name = data['last_name']
        self.email = data['email']
        self.password = data['password']
        self.created_at = data['created_at']
        self.updated_at = data['updated_at']

        self.teams = []

#========================================================================
#validates the registration entry
    @staticmethod
    def validate_User(user):
        is_valid = True
        if len(user['first_name']) < 5:
            flash("First name must be at least five characters.")
            is_valid = False
            
        if len(user['last_name']) < 5:
            flash("Last name must be at least five characters.")
            is_valid = False
        if not EMAIL_REGEX.match(user['email']):
            flash("That email is invalid.")
            is_valid = False
        if len(user['password']) < 8:
            flash("Password must be at least eight characters.")
            is_valid = False
        if ( user['confirm_password']!= user['password']):
            flash("Passwords don't match")
            is_valid = False

        return is_valid

#========================================================================

#========================================================================
#Method to save our user
    @classmethod
    def save(cls,data):
        query = "INSERT INTO users (first_name, last_name, email, password, created_at, updated_at) VALUES (%(first_name)s,%(last_name)s,%(email)s,%(password)s,NOW(),NOW());"
        results = connectToMySQL("login_and_registration_schema").query_db(query,data)
        return results
#========================================================================

#========================================================================
#Method to grab user by email

    @classmethod
    def get_by_email(cls,data):
        query= "SELECT * FROM users WHERE email = %(email)s;"
        result = connectToMySQL("login_and_registration_schema").query_db(query,data)
        #check to see if there is no email already existing in result
        if len(result) < 1:
            return False
        return cls(result[0])

#========================================================================

#========================================================================
# Method to grab user by id

    @classmethod
    def get_by_id(cls,data):
        query= "SELECT * FROM users WHERE id = %(id)s;"
        result = connectToMySQL("login_and_registration_schema").query_db(query,data)
        return cls( result[0] )

#========================================================================