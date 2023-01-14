import sqlite3

from flask import Flask, redirect, url_for, render_template, request, session, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, login_required, logout_user, current_user, LoginManager
from sqlalchemy.sql import func
from os import path
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import uuid as uuid
import os

app = Flask(__name__)
app.secret_key = 'secretkey'

db = SQLAlchemy(app)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.sqlite3'
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
db.init_app(app)

UPLOAD_FOLDER = 'static/images/'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER


def create_database(app):
    if not path.exists('pythonProject/users.sqlite3'):
        db.create_all(app=app)
        print('Created Database!')


class Users(db.Model, UserMixin):
    id = db.Column("id", db.Integer, primary_key=True)
    name = db.Column(db.String(100))
    surname = db.Column(db.String(100))
    username = db.Column(db.String(100), unique=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    notes = db.relationship('Note')
    about = db.Column(db.String(500), nullable=True)
    profile_pic = db.Column(db.String(), nullable=True)


class Note(db.Model):
    id = db.Column("id", db.Integer, primary_key=True)
    title = db.Column(db.String(250))
    content = db.Column(db.String(10000))
    tag = db.Column(db.String(1000))
    # date = db.Column(db.DateTime(timezone=True), default=func.now())
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    username = db.Column(db.String(100))
    profile_pic = db.Column(db.String(), nullable=True)


login_manager = LoginManager()
login_manager.login_view = 'login'
login_manager.init_app(app)


@login_manager.user_loader
def load_user(id):
    return Users.query.get(int(id))


@app.route('/')
@login_required
def home():
    con = sqlite3.connect("users.sqlite3")
    cur = con.cursor()
    cur.execute("SELECT * FROM note ORDER BY id desc ")
    notes = cur.fetchall()
    return render_template("index.html", notes=notes, user=current_user, users=users)


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        userLoggedin = Users.query.filter_by(username=username).first()
        if userLoggedin:
            if check_password_hash(userLoggedin.password, password):
                flash('logged in successfully!', category='success')
                login_user(userLoggedin, remember=True)
                return redirect(url_for('home'))
            else:
                flash('incorrect password! Try again.', category='error')
        else:
            flash('Username does not exist!', category='error')

    return render_template("login.html", user=current_user)


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        name = request.form.get('name')
        surname = request.form.get('surname')
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')

        userLoggedin = Users.query.filter_by(email=email).first()
        userLoggedin2 = Users.query.filter_by(username=username).first()

        if userLoggedin:
            flash('Email already exists!', category='error')
        elif userLoggedin2:
            flash('Username already exists!', category='error')

        elif len(name) < 2:
            flash('Name  must be greater than 1 characters', category='error')

        elif len(surname) < 2:
            flash('Surname  must be greater than 1 characters', category='error')

        elif len(username) < 3:
            flash('Username  must be greater than 2 characters', category='error')

        elif len(email) < 4:
            flash('Email  must be greater than 3 characters', category='error')

        elif len(password) < 6:
            flash('Password must be at least 6 characters', category='error')

        else:
            new_user = Users(name=name, surname=surname, username=username, email=email,
                             password=generate_password_hash(password, method='sha256'))
            db.session.add(new_user)
            db.session.commit()
            login_user(userLoggedin2, remember=True)
            flash('Account created!', category='success')
            return redirect(url_for('home'))
            # add user to the database

    return render_template("register.html", user=current_user)


@app.route('/user', methods=['GET', 'POST'])
@login_required
def user():
    selected_id = current_user.id
    # update_profile = Users.query.get(selected_id)

    update_profile_name = ""
    update_profile_surname = ""
    update_profile_username = ""
    update_profile_email = ""
    update_profile_about = ""
    update_profile_password = ""
    update_profile_profile_pic = ""

    if request.method == 'POST':
        update_profile_name = request.form.get('update_name')
        update_profile_surname = request.form.get('update_surname')
        update_profile_username = request.form.get('update_username')
        update_profile_email = request.form.get('update_email')
        update_profile_about = request.form.get('update_about')
        update_profile_profile_pic = request.files.get('update_profile_pic')
        update_profile_password = request.form.get('update_password')

        # userLogged = Users.query.filter_by(email=update_profile.email)
        userLoggedin = Users.query.filter_by(email=update_profile_email).all()
        userLoggedin2 = Users.query.filter_by(username=update_profile_username).all()

        emailvar = False
        usernamevar = False
        passwordvar = False

        if userLoggedin:
            for found_email in userLoggedin:
                if ((current_user.id != found_email.id) & (update_profile_email == found_email.email)):
                    emailvar = True
                    # flash('Email already exists!', category='error')

        if userLoggedin2:
            for found_username in userLoggedin2:
                if ((current_user.id != found_username.id) & (update_profile_username == found_username.username)):
                    usernamevar = True
                    # flash('Username already exists!', category='error')

        # check for profile pic
        if request.files.get('update_profile_pic'):
            update_profile_profile_pic = request.files.get('update_profile_pic')
            # Grab image name
            pic_filename = secure_filename(update_profile_profile_pic.filename)
            # Set uuid
            pic_name = str(uuid.uuid1()) + "_" + pic_filename
            # Save the image
            saver = request.files.get('update_profile_pic')
            # change it to string
            update_profile_profile_pic = pic_name

            try:
                saver.save(os.path.join(app.config['UPLOAD_FOLDER'], pic_name))

            except:
                flash('There is an error about Profile Picture!', category='error')
                update_profile = Users.query.get(selected_id)
                return render_template("user.html", update_profile=update_profile, user=current_user)

        if update_profile_password != "":
            passwordvar = True

        if passwordvar:
            if len(update_profile_password) < 6:
                flash('Password must be at least 6 characters', category='error')
                update_profile = Users.query.get(selected_id)
                return render_template("user.html", update_profile=update_profile, user=current_user)
            else:
                update_profile_password = generate_password_hash(update_profile_password, method='sha256')

        if ((emailvar == False) & (usernamevar == False)):
            update_profile = Users.query.get(selected_id)
            update_profile.name = update_profile_name
            update_profile.surname = update_profile_surname
            update_profile.username = update_profile_username
            update_profile.email = update_profile_email
            update_profile.about = update_profile_about
            # update_profile.profile_pic = pic_name
            update_profile.password = update_profile_password
            db.session.commit()
            flash('Account updated!', category='success')
            update_profile = Users.query.get(selected_id)
            return render_template("user.html", update_profile=update_profile, user=current_user)
        else:
            if (emailvar == True):
                flash('Email already exists!', category='error')

            if (usernamevar == True):
                flash('Username already exists!', category='error')

    else:
        update_profile = Users.query.get(selected_id)
        return render_template("user.html", update_profile=update_profile, user=current_user)

    return render_template("user.html", user=current_user)


@app.route('/other-users')
@login_required
def users():
    con = sqlite3.connect("users.sqlite3")
    cur = con.cursor()
    cur.execute("SELECT * FROM users")
    users = cur.fetchall()
    return render_template("showUsers.html", users=users, user=current_user)


@app.route('/add-note', methods=['GET', 'POST'])
@login_required
def addNote():
    if request.method == 'POST':
        title = request.form.get('title')
        content = request.form.get('content')
        tag = request.form.get('tag')
        username = current_user.username
        profile_pic = current_user.profile_pic

        if len(title) < 1:
            flash('Title is too short!', category='error')
        elif len(content) < 1:
            flash('Content is too short!', category='error')

            # FINISH THE TAG CHECK
        # elif :
        #  flash('Please choose a tag!', category='error')

        else:
            new_note = Note(title=title, content=content, tag=tag, user_id=current_user.id,
                            username=username, profile_pic=profile_pic)
            db.session.add(new_note)
            db.session.commit()
            flash('Note added!', 'success')
    return render_template("create-post.html", user=current_user)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash(f"you have been logged out succesful!", "success")
    return redirect(url_for("login"))


if __name__ == "__main__":
    db.create_all()
    app.run(port=8080, debug=True)
