from flask import Flask, render_template

app = Flask(__name__)


all_posts = [
    {
        'title': "Post One",
        'content': "This is the content of post one",
        'author': "itay steingold"
    },
    {
        'title': "Post Two",
        'content': "This is the content of post two",
        'author': "yana ar"
    }
]


@app.route('/')
def home():
    return render_template('index.html')


@app.route('/posts')
def post():
    return render_template('posts.html', posts=all_posts)


if __name__ == '__main__':
    app.run(debug=True)
