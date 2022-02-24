from flask_app import app

from flask_bcrypt import Bcrypt

from flask import render_template, redirect, request, session, flash
bcrypt = Bcrypt(app)

from flask_app.models.user import User

#=============================================================
#landing page for login and reg
@app.route("/")
def log_reg():
    return render_template("log_reg.html")

#=============================================================
#Proccessing registration

@app.route("/register", methods=['POST'])
def register():
    #Validate the FORM
    if not User.validate_User(request.form):
        return redirect("/")
#check to see if
    data = {
        "email" : request.form['email']
    }
    if User.get_by_email(data):
        flash("Email already taken")
        return redirect("/")
    pw_hash = bcrypt.generate_password_hash(request.form['password'])

    data = {
        "first_name" :request.form['first_name'],
        "last_name" :request.form['last_name'],
        "email" :request.form['email'],
        "password" : pw_hash
    }

    print(pw_hash)
    user_id = User.save(data)
    session['user_id'] = user_id
    return redirect(f"/user/{user_id}")
#=============================================================

#=============================================================
#Processing Login
@app.route("/login", methods = ['POST'])
def login():
    #Check to see user is in the email (by email)
    data = {
        "email" : request.form['email']
    }

    user_in_db = User.get_by_email(data)
    if not user_in_db:
        flash("User doesn't exist")
        return redirect("/")

    if not bcrypt.check_password_hash(user_in_db.password,request.form['password']):
        flash("I am salty, get a password")
        return redirect("/")
    
    session["user_id"] = user_in_db.id

    return redirect(f"/user/{user_in_db.id}")

#=============================================================

@app.route("/user/<int:user_id>")
def show_user(user_id):
    data = {
        "id" : user_id
    }
    user = User.get_by_id(data)
    return render_template("user_page.html", user = user)

#=============================================================
@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")
