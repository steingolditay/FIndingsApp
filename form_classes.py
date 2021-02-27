from flask_wtf import FlaskForm
from wtforms import StringField, SelectField
from wtforms.validators import InputRequired, Length, DataRequired
from wtforms.widgets import TextArea, Select


select_field_choices = [("נמוכה", "נמוכה"), ("בינונית", "בינונית"), ("גבוהה", "גבוהה")]


class SearchFrom(FlaskForm):
    hidden = StringField('hidden', validators=[InputRequired()])
    tags = StringField('tags')


class PublishForm(FlaskForm):
    title = StringField('title', validators=[InputRequired(), Length(min=6)])
    finding_description = StringField('finding_description', validators=[InputRequired(), Length(min=6)])
    risk_probability = SelectField('risk_probability', widget=Select, choices=select_field_choices,
                                   validators=[DataRequired()])
    risk_severity = SelectField('risk_severity', widget=Select, choices=select_field_choices,
                                validators=[DataRequired()])
    risk_level = SelectField('risk_level', widget=Select, choices=select_field_choices, validators=[DataRequired()])
    risk_description = StringField('risk_description', widget=TextArea(), validators=[InputRequired(), Length(min=6)])
    risk_recommendations = StringField('risk_recommendations', widget=TextArea(),
                                       validators=[InputRequired(), Length(min=6)])
    tags = StringField('tags')


class SubmitForm(FlaskForm):
    title = StringField('title', validators=[InputRequired(), Length(min=6)])
    content = StringField('content', validators=[InputRequired(), Length(min=20)])


class User:
    def __init__(self, uid, name, last_name, email, admin, editor):
        self.uid = uid
        self.name = name
        self.last_name = last_name
        self.email = email
        self.admin = admin
        self.editor = editor



