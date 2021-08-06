from flask import Flask, render_template, url_for, redirect, request, session, flash
from flask_sqlalchemy import SQLAlchemy
from flask_admin import Admin
from flask_admin.contrib.sqla import ModelView
from werkzeug.security import generate_password_hash, check_password_hash
import smtplib
import json
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = 'secretkey'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'


db = SQLAlchemy(app)
admin = Admin(app)

def contact_mail():
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
        return render_template('home.html', condition='True', session=session, darkmode=session['darkmode'])
    else:
        return render_template('home.html', condition='False', session=session, darkmode=session['darkmode'])

@app.route('/darkmode')
def dark_mode():
    session['darkmode']=True
    flash('Dark mode initiated..', category='success')
    return redirect(url_for('home'))

@app.route('/defaultmode')
def default_mode():
    session['darkmode']=False
    flash('Default mode initiated..', category='success')
    return redirect(url_for('home'))

@app.route('/login', methods=['GET', 'POST']) 
def login():
    if request.method == "POST":
        email = request.form['email']
        password = request.form['password']
        user = User.query.filter_by(email=email).first()
        if user:
            if check_password_hash(user.password, password):
                flash('წარმატებით შეხვედით ექაუნთზე..', category='success')
                session['user'] = user.email
                session['username'] = user.username
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
        return redirect(url_for('login'))
    
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
        try:
            contact_mail()
        except:
            flash('ვერ მოხერხდა მფლობელთან დაკავშირება. გთხოვთ სცადოთ ახლიდან..')
            return redirect(url_for('home'))
        flash('წარმატებით დაუკავშირდით მფლობელს..')
        return redirect(url_for('home'))
    else:
        flash('ვერ მოხერხდა მფლობელთან დაკავშირება. გთხოვთ სცადოთ ახლიდან..')
        return redirect(url_for('home'))


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
        return render_template('posts.html', posts=posts, session=session)
    else:
        flash('არ ხარ შესული ექაუნთზე..', category='error')
        return redirect(url_for('home'))

@app.route('/posts/add', methods=['POST', 'GET'])
def add_post():
    if 'user' in session:
        if request.method == 'POST':
            title = request.form['title']
            code = request.form['code']
            created_title = Posts(post=title, code=code, author=session['user'], author_name=session['username'], votes=0)
            db.session.add(created_title)
            db.session.commit()
            flash('წარმატებით შეიქმნა პოსტი..', category='success')
            return redirect(url_for('posts'))
        else:
            return render_template('add_post.html', session=session)
    else:
        return redirect(url_for('home'))

@app.route('/posts/<int:id>', methods=['POST', 'GET'])
def post_page(id):
    post_data = Posts.query.get(id)
    answer_data = Answers.query.get(id)
    if request.method == 'POST':
        if 'user' in session:
            upvoter = request.form.get('upvoter')
            downvoter = request.form.get('downvoter')
            session['upvoted'] = True
            session['downvoted'] = False

            if upvoter == 'up':
                vote_author = session['user']
                votes = post_data.votes
                if vote_author not in str(post_data.vote_authors):
                    post_data.vote_authors = f'{post_data.vote_authors},{vote_author}'
                    if session['downvoted'] == True:
                        votes+=2
                        session['upvoted'] = True
                    else:
                        votes+=1
                        session['upvoted'] = True
                elif vote_author in str(post_data.vote_authors):
                    post_data.vote_authors = post_data.vote_authors.replace(vote_author, '')
                    votes-=1
                    session['upvoted'] = False
                    session['downvoted'] = False
                post_data.votes = votes
                db.session.commit()
                if 'user' in session:
                    if post_data:
                        return render_template('post_page.html', post_data=post_data, current_user=session['user'], upvoted=session['upvoted'], session=session)
                    else:
                        flash('ERROR: ვერ ჩამოიტვირთა მონაცემები..', category='error')
                        return redirect(url_for('posts'))
                else:
                    return redirect(url_for('home'))
            elif downvoter == 'dwn':
                vote_author = session['user']
                votes = post_data.votes

                if vote_author not in str(post_data.vote_authors):
                    post_data.vote_authors = f'{post_data.vote_authors}-{vote_author}'
                    if session['upvoted'] == False:
                        votes-=1
                        session['downvoted'] = True
                    elif session['upvoted'] == True:
                        votes-=2
                        session['upvoted'] = False
                        session['downvoted'] = True

                elif vote_author in str(post_data.vote_authors):
                    post_data.vote_authors = post_data.vote_authors.replace(f'{vote_author}-', '')
                    if session['upvoted'] == False:
                        votes+=1
                    session['downvoted'] = False
                    session['upvoted'] = False

                post_data.votes = votes
                db.session.commit()
                if 'user' in session:
                    if post_data and answer_data:
                        return render_template('post_page.html', post_data=post_data, answer_data=answer_data, current_user=session['user'], downvoted=session['downvoted'], session=session)
                    elif post_data:
                        return render_template('post_page.html', post_data=post_data, current_user=session['user'], downvoted=session['downvoted'], session=session)
                    else:
                        flash('ERROR: ვერ ჩამოიტვირთა მონაცემები..', category='error')
                        return redirect(url_for('posts'))
                else:
                    return redirect(url_for('home'))
            if request.form.get('answer'):
                answer = request.form.get('answer')
                created_answer = Answers(answer_id=post_data.post_id, answer_author=session['user'], answer_username=session['username'], answer=answer, votes=0)
                db.session.add(created_answer)
                db.session.commit()
                return render_template('post_page.html', post_data=post_data, answer_data=answer_data, current_user=session['user'], downvoted=session['downvoted'], session=session)

        else:
            flash('არ ხართ შესული ექაუნთზე..')
            return redirect(url_for('home'))

    else:
        if 'user' in session:
            if post_data:
                return render_template('post_page.html', post_data=post_data, answer_data=answer_data, current_user=session['user'], session=session)
            else:
                flash('ERROR: ვერ ჩამოიტვირთა მონაცემები..', category='error')
                return redirect(url_for('posts'))
        else:
            return redirect(url_for('home'))


@app.route('/posts/post_settings/<int:id>', methods=['POST', 'GET'])
def post_settings(id):
    post_settings = Posts.query.get(id)
    if post_settings.author != session['user']:
        flash('ვერ მოხერხდა პარამეტრების ნახვა. თქვენ არ ხართ ამ პოსტის ავტორი..', category='error')
        return redirect(url_for('posts'))
    else:
        return render_template('post_settings.html', post_data=post_settings, session=session)


@app.route('/posts/update1/<int:id>', methods=['POST', 'GET'])
def update_title(id):
    post_update = Posts.query.get(id)
    if post_update.author != session['user']:
        flash('ვერ მოხერხდა პოსტის განახლება. თქვენ არ ხართ ამ პოსტის ავტორი..', category='error')
        return redirect(url_for('posts'))
    if request.method == 'POST':
        post_update.post = request.form['update']
        db.session.commit()
        return redirect(url_for("posts"))
    return render_template('update_post.html', update_info='სათაურის განახლება', update_class='updateTitle', session=session)

@app.route('/posts/update2/<int:id>', methods=['POST', 'GET'])
def update_code(id):
    if request.method == 'GET':
        post_update = Posts.query.get(id)
        if post_update.author != session['user']:
            flash('ვერ მოხერხდა პოსტის განახლება. თქვენ არ ხართ ამ პოსტის ავტორი..', category='error')
            return redirect(url_for('posts'))
    if request.method == 'POST':
        post_update = Posts.query.get(id)
        post_update.code = request.form['update']
        db.session.commit()
        return redirect(url_for("posts"))
    return render_template('update_post.html', update_info='კოდის განახლება', update_class='updateCode', session=session)


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
    return render_template('404.html', session=session), 404


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(16), nullable=False)

class Posts(db.Model):
    post_id = db.Column(db.Integer, primary_key=True)
    author = db.Column(db.String(10000), nullable=False)
    author_name = db.Column(db.String(10000), nullable=False)
    post = db.Column(db.Text, nullable=False)
    code = db.Column(db.Text, nullable=False)
    votes = db.Column(db.Integer, nullable=False)
    vote_authors = db.Column(db.Text)

class Answers(db.Model):
    post_id = db.Column(db.Integer, primary_key=True)
    answer_id = db.Column(db.Integer, nullable=False)
    answer_author = db.Column(db.Text, nullable=False)
    answer_username = db.Column(db.Text, nullable=False)
    answer = db.Column(db.Text, nullable=False)
    votes = db.Column(db.Integer, nullable=False)
    vote_authors = db.Column(db.Text)

admin.add_view(ModelView(User, db.session))
admin.add_view(ModelView(Posts, db.session))
admin.add_view(ModelView(Answers, db.session))

port = os.getenv('PORT', 5000)

if __name__ == '__main__':
    app.run(port=int(port), debug=True)
