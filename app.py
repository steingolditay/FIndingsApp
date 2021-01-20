from flask import Flask, render_template, request, redirect
import boto3
from boto3.dynamodb.conditions import Attr, Key
from uuid import uuid4
from datetime import datetime
import time
app = Flask(__name__)

dynamodb = boto3.resource('dynamodb')
table = dynamodb.Table('posts')

# class Post:
#     def __init__(self, uid, poster_uid, content, timestamp, reviewed):
#         self.uid = uid
#         self.poster_uid = poster_uid
#         self.content = content
#         self.timestamp = timestamp
#         self.reviewed = reviewed


@app.route('/')
def home():
    return render_template('index.html')


@app.route('/posts', methods=['GET', 'POST'])
def post():
    if request.method == 'POST':
        table.put_item(
            Item={
                'uid': str(uuid4()),
                'poster_uid': "logged_user_uid",
                'content': request.form['content'],
                'timestamp': str(round(time.time()*1000)),
                'reviewed': False
            }
        )

    response = table.scan(
        FilterExpression=Attr('reviewed').eq(False)
    )
    items = response['Items']

    return render_template('posts.html', table=items)


@app.route('/posts/delete/<uid>/<poster_uid>')
def delete(uid, poster_uid):
    table.delete_item(
        Key={
            'uid': uid,
            'poster_uid': poster_uid
        }
    )
    return redirect('/posts')


if __name__ == '__main__':
    app.run(debug=True)
