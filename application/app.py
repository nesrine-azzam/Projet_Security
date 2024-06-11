from flask import Flask, render_template, url_for, redirect, flash, session, make_response, send_file
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from forms import LoginForm, RegisterForm
from http_logger import log_and_protect, detect_metasploit
import logging
import threading
from scapy.all import sniff
from flask_limiter import Limiter
from io import BytesIO
from captcha.image import ImageCaptcha
from flask_limiter.util import get_remote_address
import random
import string
from datetime import timedelta
from flask_mail import Mail, Message
from werkzeug.security import generate_password_hash, check_password_hash

def run_sniffer():
    sniff(filter="tcp port 4444 or tcp port 4445", prn=detect_metasploit)

logging.basicConfig(filename='http_requests.log',
                    level=logging.INFO,
                    format='%(asctime)s [%(levelname)s] - %(message)s',
                    datefmt='%Y-%m-%d %H:%M:%S')



app = Flask(__name__, template_folder='templates')
app.config['SECRET_KEY'] = 'mysecretkey'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
mail = Mail(app)

limiter = Limiter(
    key_func=get_remote_address, # Utilise l'adresse IP du client pour limiter le débit
    default_limits=["200 per day", "50 per hour"] # Limite le nombre de requêtes par jour et par heure
)
limiter.init_app(app)

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/', methods=['GET', 'POST'])
@limiter.limit("15 per minute")  # Limite le nombre de requêtes par minute
@log_and_protect
def login():
    form = LoginForm()
    if session.get('login_attempts') is not None:
        if session['login_attempts'] >= 8:
            session['show_captcha'] = True
        session['login_attempts'] += 1
    else:
        session.clear()  # Supprime le contenu de la session
        session.pop('_flashes', None)  # Supprime les messages flash de la session
        session['login_attempts'] = 1
        session['show_captcha'] = False
    if form.validate_on_submit():
        if 'captcha' in session and form.captcha.data.upper() != session['captcha']:
            flash('Invalid CAPTCHA. Please try again.', 'danger')
            return render_template('login.html', form=form)
        user = User.query.filter_by(username=form.username.data).first()
        if user and check_password_hash(user.password, form.password.data):
            login_user(user)
            session['login_attempts'] = 0
            session.clear
            session['show_captcha'] = False
            return redirect(url_for('dashboard'))
        else:
            flash('Login Unsuccessful. Please check username and password', 'danger')
    return render_template('login.html', form=form)

# @app.route('/register', methods=['GET', 'POST'])
# @log_and_protect
# def register():
#     form = RegisterForm()
#     if form.validate_on_submit():
#         hashed_password = generate_password_hash(form.password.data)
#         new_user = User(username=form.username.data, password=hashed_password)
#         db.session.add(new_user)
#         db.session.commit()
#         flash(f'Account created for {form.username.data}!', 'success')
#         return redirect(url_for('login'))
#     return render_template('register.html', form=form)

@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html', current_user=current_user)
    
@app.route('/logout')
@login_required
def logout():
    logout_user()
    session.clear()  # Supprime le contenu de la session
    session.pop('_flashes', None)  # Supprime les messages flash de la session
    return redirect(url_for('login'))

@app.route('/captcha')
def captcha():
    captcha_text = ''.join(random.choices(string.ascii_uppercase + string.digits, k=6))
    session['captcha'] = captcha_text
    
    image = ImageCaptcha()
    data = BytesIO()
    image.write(captcha_text, data)
    data.seek(0)
    
    response = make_response(send_file(data, mimetype='image/png'))
    response.cache_control.no_cache = True
    response.cache_control.no_store = True
    response.cache_control.must_revalidate = True
    response.expires = 0
    response.pragma = 'no-cache'

    return response

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Vous devez être connecté pour accéder à cette page.', 'danger')
            return redirect(url_for('login', next=request.url))
        return f(*args, **kwargs)
    return decorated_function


if __name__ == '__main__':
    with app.app_context():
   	 db.create_all()
    sniffer_thread = threading.Thread(target=run_sniffer)
    sniffer_thread.start()
    # app.run(debug=True)
    app.run(host='0.0.0.0', debug=True)

