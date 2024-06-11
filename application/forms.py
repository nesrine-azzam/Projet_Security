from flask import session
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, ValidationError
from wtforms.validators import DataRequired, Length, EqualTo, Regexp
# ORM
def validate_captcha(self, field):
    # Si l'utilisateur a échoué moins de 8 tentatives de connexion, le captcha est facultatif
    if session.get('login_attempts', 0) < 8:
        return
    if 'captcha' not in session or field.data.upper() != session['captcha']:
        raise ValidationError('Invalid CAPTCHA')
    
class LoginForm(FlaskForm):
    username = StringField('', validators=[DataRequired(), Length(min=2, max=20)], render_kw={"placeholder": "Username", "required": True})
    password = PasswordField('', validators=[DataRequired()], render_kw={"placeholder": "Password", "required": True})
    captcha = StringField('', validators=[ validate_captcha], render_kw={"placeholder": "Captcha"})
    submit = SubmitField('Login')

class RegisterForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=2, max=20)])
    password = PasswordField('Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Sign Up')