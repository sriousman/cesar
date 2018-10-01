from flask_wtf import Form

from wtforms.fields.html5 import DateField
from wtforms import (
    StringField, PasswordField, TextAreaField, DateTimeField, IntegerField,
    FormField, FieldList
    )

from wtforms.validators import (
                            DataRequired, Regexp, ValidationError, Email,
                            Length, EqualTo, URL)

from models import User


def name_exists(form, field):
    if User.select().where(User.username == field.data).exists():
        raise ValidationError('User with that name already exists.')


def email_exists(form, field):
    if User.select().where(User.email == field.data).exists():
        raise ValidationError('User with that email already exists.')


class RegisterForm(Form):
    username = StringField(
        'Username',
        validators=[
            DataRequired(),
            Regexp(
                r'^[a-zA-Z0-9_]+$',
                message=("Username should be one word, letters, "
                         "numbers, and underscores only.")
            ),
            name_exists
        ])
    email = StringField(
        'Email',
        validators=[
            DataRequired(),
            Email(),
            email_exists
        ])
    password = PasswordField(
        'Password',
        validators=[
            DataRequired(),
            Length(min=2),
            EqualTo('password2', message='Passwords must match')
        ])
    password2 = PasswordField(
        'Confirm Password',
        validators=[DataRequired()]
    )


class LoginForm(Form):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])


class NewEntryForm(Form):
    title = StringField('Title', validators=[DataRequired()])
    date = DateField('Date', validators=[DataRequired()])
    time_spent = IntegerField('Time Spent', validators=[DataRequired()])
    learned = TextAreaField('What I Learned', validators=[DataRequired()])
    resources = TextAreaField('Resources', validators=[DataRequired()])


class EditForm(Form):
    title = StringField('Title')
    date = DateField('Date')
    time_spent = IntegerField('Time Spent')
    learned = TextAreaField('What I Learned')
    resources = TextAreaField('Resources')
