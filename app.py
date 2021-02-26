from flask import Flask, render_template, request, redirect, jsonify, make_response, url_for, session
import boto3
from boto3.dynamodb.conditions import Attr
from uuid import uuid4
import os
import time
import datetime
from flask_wtf import CSRFProtect
from helpers import search_results, tag_list, public_key, private_key
from form_classes import SearchFrom, PublishForm, SubmitForm, User
from flask_awscognito import AWSCognitoAuthentication, exceptions
from flask_jwt_extended import JWTManager, get_jwt_identity, verify_jwt_in_request, decode_token
from flask_jwt_simple import decode_jwt
import jwt as jwt_lib
import calendar

tag_list.sort()

app = Flask(__name__)
app.secret_key = os.urandom(24)
csrf = CSRFProtect()
csrf.init_app(app)

app.config['AWS_DEFAULT_REGION'] = 'eu-west-2'
app.config['AWS_COGNITO_DOMAIN'] = 'https://findingsapp.auth.eu-west-2.amazoncognito.com'
app.config['AWS_COGNITO_USER_POOL_ID'] = 'eu-west-2_CgBNp3mRF'
app.config['AWS_COGNITO_USER_POOL_CLIENT_ID'] = '6asbffr0d7ne202o8c5v9vstoh'
app.config['AWS_COGNITO_USER_POOL_CLIENT_SECRET'] = '9drrhmu1jkl4hk1afcc3kqduakbkp7bsodsknegmfqgtaplurkc'
app.config['AWS_COGNITO_REDIRECT_URL'] = 'http://localhost:5000/aws_redirect'
app.config['JWT_TOKEN_LOCATION'] = ['cookies', 'headers']
app.config['JWT_IDENTITY_CLAIM'] = 'sub'
app.config['JWT_ALGORITHM'] = 'RS256'
app.config['JWT_COOKIE_CSRF_PROTECT'] = False
app.config['JWT_CSRF_IN_COOKIES'] = False
app.config['JWT_ACCESS_CSRF_HEADER_NAME '] = "X-CSRF-TOKEN-ACCESS"
app.config['JWT_PRIVATE_KEY'] = private_key
app.config['JWT_DECODE_ALGORITHMS'] = 'RS256'
app.config['JWT_PUBLIC_KEY'] = public_key
app.config['JWT_DECODE_AUDIENCE'] = None


aws_auth = AWSCognitoAuthentication(app)
jwt = JWTManager(app)

dynamodb = boto3.resource('dynamodb')
submissions_table = dynamodb.Table('submissions')
findings_table = dynamodb.Table('findings')
client = boto3.client('cognito-idp')


# refresh tokens if less than 30 mins left
@app.after_request
def refresh_expiring_jwts(response):
    try:
        gmt = time.gmtime()
        now = calendar.timegm(gmt)

        if request.cookies.get("state"):
            args = {"state": request.cookies.get("state")}
            current_access_token = request.cookies.get('access_token_cookie')
            decoded = jwt_lib.decode(current_access_token, options={"verify_signature": False})
            token_timestamp = int(decoded['exp'])
            if token_timestamp < now + 1800:
                refresh_token = request.cookies.get('refresh_token_cookie')
                tokens = aws_auth.get_refreshed_access_token(request_args=args, refresh_token=refresh_token)
                response.set_cookie("access_token_cookie", tokens['access_token'], httponly=True)
                response.set_cookie("refresh_token_cookie", tokens['refresh_token'], httponly=True)
        return response
    except (RuntimeError, KeyError):
        # Case where there is not a valid JWT. Just return the original respone
        return response


@app.route('/sign_out')
def sign_out():
    response = make_response(redirect(url_for('.sign_in')))
    response.set_cookie("access_token_cookie", "",  expires=0)
    response.set_cookie("refresh_token_cookie", "", expires=0)
    response.set_cookie("admin", " ", expires=0)
    response.set_cookie("username", "", expires=0)
    response.set_cookie("email", "", expires=0)
    response.set_cookie("uid", "", expires=0)
    response.set_cookie("state", "", expires=0)
    response.headers['X-CSRF-TOKEN-ACCESS'] = ""
    return response


def get_data_from_session(user_request):
    data = {"uid": user_request.cookies.get('uid'),
            "username": user_request.cookies.get('username'),
            "email": user_request.cookies.get('email'),
            "admin": user_request.cookies.get("admin")}

    return data


@app.route('/sign_in')
def sign_in():
    return redirect(aws_auth.get_sign_in_url())


@app.route('/aws_redirect')
def aws():
    # if someone tries to access this page directly,
    # redirect them to the sign in page
    # otherwise, get the Cognito access token and create a response
    # insert the token into a secured cookie and add a csrf header


    try:
        # get tokens
        tokens = aws_auth.get_access_token(request.args)
        access_token = tokens["access_token"]
        id_token = tokens["id_token"]
        refresh_token = str(tokens["refresh_token"]).encode('utf-8').strip()
        csrf_token = request.args['state']

        # decode tokens
        decoded_access_token = jwt_lib.decode(access_token, options={"verify_signature": False})

        # print(x)

        # check if admin and set data to session
        uid = decoded_access_token['sub']
        name = ""
        last_name = ""
        email = ""
        admin = ('admins' in decoded_access_token['cognito:groups'])

        # get user from cognito
        user = client.admin_get_user(
            UserPoolId='eu-west-2_CgBNp3mRF',
            Username=str(decoded_access_token['username'])
        )
        # get user attributes
        for attr in user['UserAttributes']:
            if attr['Name'] == "name":
                name = attr['Value']
            elif attr['Name'] == 'family_name':
                last_name = attr['Value']
            elif attr['Name'] == 'email':
                email = attr['Value']

        # create user object
        user = User(uid=uid, name=name, last_name=last_name, email=email, admin=admin)

        # create response object
        response = make_response(redirect(url_for('.home')))
        response.set_cookie("access_token_cookie", access_token, httponly=True)
        response.set_cookie("refresh_token_cookie", refresh_token, httponly=True)
        response.set_cookie("admin", str(admin), httponly=True)
        response.set_cookie("username", str(user.name + " " + user.last_name), httponly=True)
        response.set_cookie("email", str(user.email), httponly=True)
        response.set_cookie("uid", str(user.uid), httponly=True)
        response.set_cookie("state", request.args.get("state"))
        response.headers['X-CSRF-TOKEN-ACCESS'] = csrf_token
        response.headers['csrf_token'] = csrf_token

        return response
    except exceptions.FlaskAWSCognitoError:
        return redirect(url_for('.sign_in'))


@app.route('/')
def login():
    access_token = request.cookies.get("access_token_cookie")
    if access_token:
        return redirect(url_for('.home'))

    else:
        return redirect(url_for('.sign_in'))


@app.route('/home')
def home():
    verify_jwt_in_request()
    data = get_data_from_session(user_request=request)

    if get_jwt_identity():
        # make a list of recent approved findings only

        response = findings_table.scan(
            FilterExpression=Attr('Published').eq(True)
        )
        items = response['Items']
        ordered_items = sorted(items, key=lambda k: k['CreatedAt'], reverse=True)

        # replace timestamp with real time
        for item in ordered_items:
            timestamp = item['CreatedAt']
            real_time = str(datetime.datetime.fromtimestamp(float(timestamp) // 1000.0))
            item['CreatedAt'] = real_time

        return render_template('index.html', items=ordered_items, data=data)
    else:
        return url_for('.sign_in')


# Submit new findings
@app.route('/submit', methods=['GET', 'POST'])
def submit_new_finding():
    verify_jwt_in_request()
    data = get_data_from_session(user_request=request)

    form = SubmitForm(request.form)
    # validates input and csrf token
    if form.validate_on_submit():

        submissions_table.put_item(
            Item={
                'Uid': str(uuid4()),
                'CreatedBy': data['username'],
                'CreatedAt': str(round(time.time() * 1000)),
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
    return render_template('submit.html', form=form, data=data)


# Submission waiting for review
@app.route('/review', methods=['GET', 'POST'])
def review_list():
    verify_jwt_in_request()
    data = get_data_from_session(user_request=request)

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
        real_time = str(datetime.datetime.fromtimestamp(float(timestamp) // 1000.0))
        item['CreatedAt'] = real_time

    return render_template('review.html', items=items, trash=i, data=data)


# Delete a submission - remove it from the review page and move to trash
@app.route('/submission/delete=<Uid>by=<CreatedBy>')
def delete_submission(Uid, CreatedBy):
    verify_jwt_in_request()


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
    verify_jwt_in_request()
    data = get_data_from_session(user_request=request)

    form = PublishForm(request.form)
    response = submissions_table.get_item(
        Key={
            'Uid': Uid,
            'CreatedBy': CreatedBy
        }
    )
    item = response['Item']

    if form.validate_on_submit():
        tags = request.form['tags'].split(",")

        findings_table.put_item(
            Item={
                'Uid': Uid,
                'CreatedBy': CreatedBy,
                'CreatedAt': item['CreatedAt'],
                'ReviewedBy': data['username'],
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
                'Tags': tags
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
                ':val3': data['username']
            }
        )
        return redirect('/review')

    return render_template("review_submission.html", item=item, form=form, tags=tag_list, data=data)


# View a specific published finding
@app.route('/findings/view/finding=<Uid>by=<CreatedBy>')
def view_finding(Uid, CreatedBy):
    verify_jwt_in_request()
    data = get_data_from_session(user_request=request)

    response = findings_table.get_item(
        Key={
            'Uid': Uid,
            'CreatedBy': CreatedBy
        }
    )
    item = response['Item']

    return render_template("view_finding.html", item=item, data=data)


# Search
@app.route('/search', methods=["GET", "POST"])
def search():
    verify_jwt_in_request()
    data = get_data_from_session(user_request=request)

    form = SearchFrom(request.form)
    items_list = []

    if request.method == "POST":
        keywords = [string.strip() for string in form.hidden.data.split(",")]
        tags_list = [string.strip() for string in form.tags.data.split(",")]

        response = findings_table.scan(
            FilterExpression=Attr('Published').eq(True)
        )
        items = response['Items']
        for item in items:
            if search_results(keywords=keywords, tags_list=tags_list, item=item):
                items_list.append(item)

    return render_template("search.html", items=items_list, form=form, tags=tag_list, data=data)


if __name__ == '__main__':
    app.run(debug=True)
