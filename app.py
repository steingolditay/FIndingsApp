from flask import Flask, render_template, request, redirect, flash
from flask_wtf import FlaskForm
import boto3
from boto3.dynamodb.conditions import Attr, Key
from uuid import uuid4
import os
import time
from wtforms import StringField, SubmitField, SelectField
from wtforms.validators import InputRequired, Length, DataRequired
from wtforms.widgets import TextArea, Select
import datetime
from flask_wtf import CSRFProtect


select_field_choices = [("Low", "Low"), ("Medium", "Medium"), ("High", "High")]

app = Flask(__name__)
app.secret_key = os.urandom(24)
csrf = CSRFProtect()
csrf.init_app(app)


dynamodb = boto3.resource('dynamodb')
submissions_table = dynamodb.Table('submissions')
findings_table = dynamodb.Table('findings')


class PublishForm(FlaskForm):
    title = StringField('title', validators=[InputRequired(), Length(min=6)])
    finding_description = StringField('finding_description', validators=[InputRequired(), Length(min=6)])
    risk_probability = SelectField('risk_probability', widget=Select, choices=select_field_choices, validators=[DataRequired()])
    risk_severity = SelectField('risk_severity', widget=Select, choices=select_field_choices, validators=[DataRequired()])
    risk_level = SelectField('risk_level', widget=Select, choices=select_field_choices, validators=[DataRequired()])
    risk_description = StringField('risk_description', widget=TextArea(), validators=[InputRequired(), Length(min=6)])
    risk_recommendations = StringField('risk_recommendations', widget=TextArea(), validators=[InputRequired(), Length(min=6)])
    hidden = StringField('hidden')


class SubmitForm(FlaskForm):
    title = StringField('title', validators=[InputRequired(), Length(min=6)])
    content = StringField('content', validators=[InputRequired(), Length(min=20)])


@app.route('/')
def home():
    response = findings_table.scan(
        FilterExpression=Attr('Published').eq(True)
    )
    items = response['Items']
    ordered_items = sorted(items, key=lambda k: k['CreatedAt'], reverse=True)
    for item in ordered_items:
        timestamp = item['CreatedAt']
        real_time = str(datetime.datetime.fromtimestamp(float(timestamp)//1000.0))
        item['CreatedAt'] = real_time
    # make a list of recent approved findings only
    return render_template('index.html', items=ordered_items)


# Submit new findings
@app.route('/submit', methods=['GET', 'POST'])
def submit_new_finding():
    form = SubmitForm(request.form)
    # validates input and csrf token
    if form.validate_on_submit():
        submissions_table.put_item(
              Item={
                  'Uid': str(uuid4()),
                  'CreatedBy': "logged_user_uid",
                  'CreatedAt': str(round(time.time()*1000)),
                  'Title': form.title.data,
                  'Content': form.content.data,
                  'Reviewed': False,
                  'ReviewedBy': "",
                  'Deleted': False
              }
            )
        if request.form['submit'] == "Submit":
            return redirect('/')
        elif request.form['submit'] == "Submit and create another":
            return redirect('/submit')
        else:
            return redirect('/')
    return render_template('submit.html', form=form)


# Submission waiting for review
@app.route('/review', methods=['GET', 'POST'])
def review_list():
    response = submissions_table.scan(
        FilterExpression=Attr('Reviewed').eq(False)
    )

    # on button click
    i = 0
    items = response['Items']
    ordered_items = sorted(items, key=lambda k: k['CreatedAt'], reverse=True)
    for item in ordered_items:
        if item['Deleted']:
            i += 1
            items.remove(item)
        timestamp = item['CreatedAt']
        real_time = str(datetime.datetime.fromtimestamp(float(timestamp)//1000.0))
        item['CreatedAt'] = real_time

    return render_template('review.html', items=items, trash=i)


# Delete a submission - remove it from the review page and move to trash
@app.route('/submission/delete=<Uid>by=<CreatedBy>')
def delete_submission(Uid, CreatedBy):
    submissions_table.update_item(
        Key={
            'Uid': Uid,
            'CreatedBy': CreatedBy
        },
        UpdateExpression='SET Deleted = :val1',
        ExpressionAttributeValues={
            ':val1': True
        }
    )
    return redirect('/review')


# Review a submission
@app.route('/review/submission=<Uid>by=<CreatedBy>', methods=["GET", "POST"])
def review_submission(Uid, CreatedBy):
    form = PublishForm(request.form)
    response = submissions_table.get_item(
        Key={
            'Uid': Uid,
            'CreatedBy': CreatedBy
        }
    )
    item = response['Item']

    if form.validate_on_submit():
        findings_table.put_item(
              Item={
                  'Uid': Uid,
                  'CreatedBy': CreatedBy,
                  'CreatedAt': item['CreatedAt'],
                  'ReviewedBy': "ReviewerId",
                  'ReviewedAt': str(round(time.time() * 1000)),
                  'Approved': False,
                  'Title': form.title.data,
                  'Description': form.finding_description.data,
                  'RiskDetails': form.risk_description.data,
                  'Probability': form.risk_probability.data,
                  'Severity': form.risk_severity.data,
                  'OverallRisk': form.risk_level.data,
                  'Recommendations': form.risk_recommendations.data,
                  'Published': True,
                  'Deleted': False,
                  'Tags': form.hidden.data
              }
            )
        submissions_table.update_item(
            Key={
                'Uid': Uid,
                'CreatedBy': CreatedBy
            },
            UpdateExpression="SET Reviewed = :val1, ReviewedAt = :val2, ReviewedBy = :val3",
            ExpressionAttributeValues={
                ':val1': True,
                ':val2': str(round(time.time() * 1000)),
                ':val3': 'ReviewerId'
            }
        )
        return redirect('/review')

    return render_template("review_submission.html", item=item, form=form)


# View a specific published finding
@app.route('/findings/view/finding=<Uid>by=<CreatedBy>')
def view_finding(Uid, CreatedBy):
    response = findings_table.get_item(
        Key={
            'Uid': Uid,
            'CreatedBy': CreatedBy
        }
    )
    item = response['Item']

    return render_template("view_finding.html", item=item)


@app.route('/search', methods=["GET", "POST"])
def search():
    return render_template("search.html")


if __name__ == '__main__':
    app.run(debug=True)
