from flask import Flask, render_template, url_for, redirect, request, session, flash
from flask_sqlalchemy import SQLAlchemy
from flask_admin import Admin
from flask_admin.contrib.sqla import ModelView
from flask_login import UserMixin, login_required, current_user, LoginManager
from werkzeug.security import generate_password_hash, check_password_hash
import smtplib
import json
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = 'secretkey'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'


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
        return render_template('home.html', condition='True', username=session['username'])
    else:
        return render_template('home.html', condition='False')


@app.route('/login', methods=['GET', 'POST']) 
def login():
    if request.method == "POST":
        email = request.form['email']
        password = request.form['password']
        user = User.query.filter_by(email=email).first()
        if user:
            if check_password_hash(user.password, password):
                flash('წარმატებით შეხვედით ექაუნთზე..', category='success')
                session['username'] = user.username
                session['user'] = user.email
                return redirect(url_for('home'))
            elif not check_password_hash(user.password, password):
                flash('ეს პაროლი არასწორია. გთხოვთ სცადოთ ახლიდან..', category='error')
                return redirect(url_for('login'))
        if not user:
            flash('ეს ემაილი არ არსებობს. გთხოვთ სცადოთ ახლიდან..', category='error')
            return redirect(url_for('login'))
    if 'user' in session:
        flash('უკვე შესული ხართ..', category='error')
        return redirect(url_for('home'))
    return render_template("login.html")

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if 'user' in session:
        flash('უკვე შესული ხართ..', category='error')
        return redirect(url_for('home'))
    if request.method == "POST":
        username = request.form['username']
        password = request.form['password']
        email = request.form['email']
        created_user = User(username=username, password=generate_password_hash(password, method='sha256'), email=email)
        db.session.add(created_user)
        db.session.commit()
        flash('წარმატებით შეიქმნა ექაუნთი..', category='success')
        return redirect(url_for('home'))
    
    return render_template("signup.html")

@app.route('/logout')
def logout():
    if 'user' in session:
        flash('წარმატებით გამოხვედით ექაუნთიდან..', category='success')
    elif not 'user' in session:
        flash('არ ხართ შესული ექაუნთზე..', category='error')
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


@app.route('/posts', methods=['POST', 'GET'])
def posts():
    if request.method == 'POST':
        search = request.form['search']
        if search == '':
            return redirect(url_for('posts'))
        elif search != '':
            posts = Posts.query.filter(Posts.post.contains(search))
    else:
        posts = Posts.query.all()
    if 'user' in session:
        return render_template('posts.html', posts=posts)
    else:
        return redirect(url_for('home'))

@app.route('/posts/add', methods=['POST', 'GET'])
def add_post():
    if 'user' in session:
        if request.method == 'POST':
            title = request.form['title']
            error = request.form['error']
            created_post = Posts(post=title, error=error, author=session['user'])
            db.session.add(created_post)
            db.session.commit()
            flash('წარმატებით შეიქმნა პოსტი..', category='success')
            return redirect(url_for('posts'))
        else:
            return render_template('add_post.html')
    else:
        return redirect(url_for('home'))

@app.route('/posts/<int:id>')
def post_page(id):
    post_data = Posts.query.get(id)
    if 'user' in session:
        if post_data:
            return render_template('post_page.html', post_data=post_data, current_user=session['user'])
        else:
            flash('ERROR: ვერ ჩამოიტვირთა მონაცემები..', category='error')
            return redirect(url_for('posts'))
    else:
        return redirect(url_for('home'))

@app.route('/posts/update1/<int:id>', methods=['POST', 'GET'])
def update_title(id):
    if request.method == 'POST':
        post_update = Posts.query.get(id)
        post_update.post = request.form['update']
        db.session.commit()
        return redirect(url_for("posts"))
    return render_template('update_post.html')

@app.route('/posts/update2/<int:id>', methods=['POST', 'GET'])
def update_code(id):
    if request.method == 'POST':
        post_update = Posts.query.get(id)
        post_update.error = request.form['update']
        db.session.commit()
        return redirect(url_for("posts"))
    return render_template('update_post.html')


@app.route('/posts/delete/<int:id>')
def delete(id):
    post_delete = Posts.query.get(id)
    if post_delete.author != session['user']:
        flash('ვერ მოხერხდა პოსტის წაშლა. თქვენ არ ხართ ამ პოსტის ავტორი..', category='error')
        return redirect(url_for('posts'))
    try:
        db.session.delete(post_delete)
        db.session.commit()
        flash('წარმატებით წაიშალა პოსტი..', category='success')
        return redirect(url_for('posts'))
    except:
        flash("პოსტი ვერ წაიშალა..", category='error')
        return redirect(url_for('posts'))


@app.errorhandler(404)
def error(e):
    return render_template('404.html'), 404


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(16), nullable=False)

class Posts(db.Model):
    post_id = db.Column(db.Integer, primary_key=True)
    author = db.Column(db.String(10000))
    post = db.Column(db.Text)
    error = db.Column(db.Text)

admin.add_view(ModelView(User, db.session))
admin.add_view(ModelView(Posts, db.session))

port = os.getenv('PORT', 5000)

if __name__ == '__main__':
    app.run(port=int(port), debug=True)
