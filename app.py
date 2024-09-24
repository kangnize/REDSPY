from flask import Flask, render_template, redirect, url_for, request, session, flash
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = 'your_secret_key'  # Replace with your secret key
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(128), nullable=False)

with app.app_context():
    db.create_all()

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = generate_password_hash(request.form['password'], method='pbkdf2:sha256')

        new_user = User(username=username, email=email, password=password)

        try:
            db.session.add(new_user)
            db.session.commit()
            flash('Registration successful! You can now log in.', 'success')
            return redirect(url_for('login'))
        except Exception as e:
            flash('Error: Username or email already exists.', 'danger')
            db.session.rollback()

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()

        if user and check_password_hash(user.password, password):
            session['username'] = user.username
            flash('Login successful!', 'success')
            return redirect(url_for('account'))
        else:
            flash('Login failed. Check your username and/or password.', 'danger')

    return render_template('login.html')

@app.route('/account', methods=['GET', 'POST'])
def account():
    if 'username' in session:
        username = session['username']
        user = User.query.filter_by(username=username).first()

        if request.method == 'POST':
            new_username = request.form['username']
            new_email = request.form['email']
            new_password = request.form['password']

            user.username = new_username
            user.email = new_email

            if new_password:
                user.password = generate_password_hash(new_password, method='pbkdf2:sha256')

            db.session.commit()
            flash('Account updated successfully!', 'success')

        return render_template('account.html', username=user.username, email=user.email)

    return redirect(url_for('login'))

@app.route('/logout')
def logout():
    session.pop('username', None)
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

@app.route('/payment')
def payment():
    return render_template('payment.html')

@app.route('/demo')
def demo():
    return render_template('demo.html')

@app.route('/chats')
def chats():
    return render_template('chats.html')

if __name__ == '__main__':
    app.run(debug=True)

