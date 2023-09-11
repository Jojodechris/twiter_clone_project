from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, TextAreaField
from wtforms.validators import DataRequired, Email, Length


class MessageForm(FlaskForm):
    """Form for adding/editing messages."""

    text = TextAreaField('text', validators=[DataRequired()])


class UserAddForm(FlaskForm):
    """Form for adding users."""

    username = StringField('Username', validators=[DataRequired()])
    email = StringField('E-mail', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[Length(min=6)])
    image_url = StringField('(Optional) Image URL')
    location=StringField('Enter your location', validators=[DataRequired()])
    bio=StringField('write something for your bio', validators=[DataRequired()])
    header_image_url=StringField('(Optional) Background Image URL')

class EditPassword(FlaskForm):
     """Form for editing users."""
     Current_password = PasswordField('Current Password', validators=[Length(min=6)])
     new_password=PasswordField('New Password', validators=[Length(min=6)])
     confirm_password=PasswordField('confirm your password', validators=[Length(min=6)])



class LoginForm(FlaskForm):
    """Login form."""

    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[Length(min=6)])
