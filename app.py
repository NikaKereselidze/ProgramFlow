from flask import Flask, render_template, request, session
from flask_sqlalchemy import SQLAlchemy
from flask_admin import Admin
from flask_admin.contrib.sqla import ModelView
import smtplib
import json

app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///sqlite.db'

db = SQLAlchemy(app)

admin = Admin(app, url='/2d457c9471be33362fd6fsa7sa89asdf7a0fsaf0')

def send_mail():
    with smtplib.SMTP('smtp.gmail.com', 587) as smtp:
        email_address = 'emailpython17@gmail.com'
        passwd = 'vtvvutjvppuxjktk'
        receiver = ('nika17nikalai@gmail.com', 'nika17nikolai@gmail.com')
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
    return render_template('home.html')

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

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100))
    question = db.Column(db.String(1024))

admin.add_view(ModelView(User, db.session))

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0')
