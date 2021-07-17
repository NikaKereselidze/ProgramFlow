from flask import Flask, render_template, url_for, redirect, request, session, flash
from flask_sqlalchemy import SQLAlchemy
from flask_admin import Admin
from flask_admin.contrib.sqla import ModelView
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
import smtplib
import json
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///sqlite.db'

db = SQLAlchemy(app)

admin = Admin(app)

def send_mail():
    with smtplib.SMTP('smtp.gmail.com', 587) as smtp:
        email_address = 'emailpython17@gmail.com'
        passwd = 'vtvvutjvppuxjktk'
        receiver = ('nika17nikalai@gmail.com', 'nikakereselidze17@gmail.com', 'nikochopikashvili@yahoo.com', 'giooku.com@gmail.com')
        smtp.starttls()
        smtp.login(email_address, passwd)
        sub = '{} contacted you from your website'.format(request.form['email'])
        body = {
            'Name':'{}'.format(request.form['name']),
            'Email':'{}'.format(request.form['email']),
            'Message':'{}'.format(request.form['message'])
            }
        msg = 'Subject: {0}\n\n{1}'.format(sub, json.dumps(body))
        smtp.sendmail(email_address, receiver, msg)


@app.route('/')
def home():
    if 'user' in session:
        return render_template('home.html', condition='True', username=session['user'])
    else:
        return render_template('home.html', condition='False')


@app.route('/login', methods=['GET', 'POST']) 
def login():
    if request.method == "POST":
        email = request.form['email']
        password = request.form['password']
        user = User.query.filter_by(email=email).first()
        if 'user' in session:
            return redirect(url_for('logged'))
        if user:
            if check_password_hash(user.password, password):
                flash('Successfully logged in!')
                session['user'] = user.username
                return redirect(url_for('home'))
            elif not check_password_hash(user.password, password):
                flash('Incorrect password.. Try again.')
                return redirect(url_for('login'))
        if not user:
            flash('This Email does not exist.. Try again.')
            return redirect(url_for('login'))

    return render_template("login.html")

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == "POST":
        username = request.form['username']
        password = request.form['password']
        email = request.form['email']
        created_user = User(username=username, password=generate_password_hash(password, method='sha256'), email=email)
        db.session.add(created_user)
        db.session.commit()

        return redirect(url_for('home'))
    
    return render_template("signup.html")

@app.route('/logout')
def logout():
    if 'user' in session:
        flash('Successfully logged out')
    elif not 'user' in session:
        flash('You are not logged in')
    session.pop('user', None)
    return redirect(url_for('login'))


@app.route('/contact')
def contact():
    return render_template('contact.html')

@app.route('/58ff672ea1ba72c2478600cba7c94579c6d96fc5', methods=['POST', 'GET'])
def send_contact():
    if request.method == 'POST':
        send_mail()
        return render_template('contact_succeed.html')
    else:
        return render_template('contact_failed.html')


@app.errorhandler(404)
def error(e):
    return render_template('404.html'), 404

@app.errorhandler(500)
def error(e):
    return render_template('404.html'), 500


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(16), nullable=False)

class Questions(db.Model):
    question_id = db.Column(db.Integer, primary_key=True)
    question = db.Column(db.String(5000))

admin.add_view(ModelView(User, db.session))
admin.add_view(ModelView(Questions, db.session))

port = os.getenv('PORT', 5000)

if __name__ == '__main__':
    app.run(port=int(port), debug=True)