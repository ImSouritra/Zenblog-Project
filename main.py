import os.path
from functools import wraps

from flask import Flask, render_template, redirect, url_for, flash, request
from flask_bootstrap import Bootstrap
from flask_ckeditor import CKEditor
from datetime import datetime
from forms import CreatePostForm
from werkzeug.exceptions import abort
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from flask_gravatar import Gravatar

app = Flask(__name__)
app.config['SECRET_KEY'] = '8BYkEfBA6O6donzWlSihBXox7C0sKR6b'
ckeditor = CKEditor(app)
Bootstrap(app)

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///blog.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

login_manager = LoginManager()
login_manager.init_app(app)




def admin_only(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # If id is not 1 then return abort with 403 error
        if current_user.id != 1:
            return abort(403)
        # Otherwise continue with the route function
        return f(*args, **kwargs)

    return decorated_function


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class User(UserMixin, db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(150), unique=True, nullable=False)
    first_name = db.Column(db.String(100), nullable=False)
    last_name = db.Column(db.String(100), nullable=False)
    password = db.Column(db.String(), nullable=False)
    blog_posts = relationship("BlogPost", back_populates="author")
    comments = relationship("Comment", back_populates="comment_author")


class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id = db.Column(db.Integer, primary_key=True)
    author_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    author = relationship("User", back_populates="blog_posts")
    title = db.Column(db.String(250), nullable=False)
    subtitle = db.Column(db.String(), nullable=False)
    date = db.Column(db.String(), nullable=False)
    body = db.Column(db.String(), nullable=False)
    category = db.Column(db.String(100), nullable=False)
    image = db.Column(db.String(), nullable=False)
    comments = relationship("Comment", back_populates="related_blog")


class Comment(db.Model):
    __tablename__ = "comments"
    id = db.Column(db.Integer, primary_key=True)
    author_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    comment_author = relationship("User", back_populates="comments")
    comment = db.Column(db.String(), nullable=False)
    blog_id = db.Column(db.Integer, db.ForeignKey("blog_posts.id"))
    related_blog = relationship("BlogPost", back_populates="comments")


if not os.path.isfile("sqlite:///blog.db"):
    db.create_all()


@app.route('/')
def home():
    all_posts = db.session.query(BlogPost).all()
    recent_posts = BlogPost.query.order_by(BlogPost.id).all()[::-1][:4]
    trending_posts = BlogPost.query.order_by(BlogPost.date).all()
    return render_template("index.html",recent_posts = recent_posts,trending_posts=trending_posts )


@app.route('/login', methods=["GET", "POST"])
def login():
    if request.method == "POST":
        user_email = request.form["email"]
        user = User.query.filter_by(email=user_email).first()
        if not user:
            flash("Incorrect email address! Please try again! ")
            return redirect(url_for("login"))
        elif not check_password_hash(password=request.form["password"], pwhash=user.password):
            flash("Wrong Password! Please try again!")
            return redirect(url_for("login"))
        else:
            login_user(user)
            return redirect(url_for("home"))
    return render_template("login.html")


@app.route('/register', methods=["GET", "POST"])
def register():
    if request.method == "POST":
        user_email = request.form["email"]
        if User.query.filter_by(email=user_email).first():
            flash("You have already registered with this email address! Please Log in.")
            return redirect(url_for("login"))
        first_name = request.form["fname"]
        last_name = request.form["lname"]
        password = request.form["password"]
        hashed_password = generate_password_hash(password, method="pbkdf2:sha256", salt_length=8)
        new_user = User(email=user_email, password=hashed_password, first_name=first_name, last_name=last_name)
        db.session.add(new_user)
        db.session.commit()
        login_user(new_user)
        return redirect(url_for("home"))
    return render_template('register.html')


@app.route('/contact')
def contact():
    return render_template("contact.html")

@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for("home"))


@app.route('/show-post',methods=["GET","POST"])
def show_post():
    post_id = request.args.get('id')
    post = BlogPost.query.get(post_id)
    if request.method=="POST":
        new_comment=Comment(author_id=current_user.id,blog_id=post_id,comment=request.form.get("comment"))
        db.session.add(new_comment)
        db.session.commit()
    return render_template("single-post.html",post=post)


@app.route('/create-post',methods=["GET","POST"])
@admin_only
def make_post():
    form = CreatePostForm()
    current_date = datetime.now().strftime("%d %B, %Y")
    if form.validate_on_submit():
        title = form.title.data
        subtitle = form.subtitle.data
        image = form.img_url.data
        category = form.category.data
        body = form.body.data
        new_blog = BlogPost(title=title,subtitle=subtitle,date=current_date ,image=image,category=category,author_id=current_user.id,body=body)
        db.session.add(new_blog)
        db.session.commit()
        return redirect(url_for('show_post',id=new_blog.id))
    return render_template("create-post.html",form=form)

@app.route('/edit-post',methods=["GET","POST"])
@admin_only
def edit_post():
    post_id = request.args.get("id")
    selected_post = BlogPost.query.get(post_id)
    form = CreatePostForm(title=selected_post.title,subtitle=selected_post.subtitle,img_url=selected_post.image,body=selected_post.body,category=selected_post.category,)
    if request.method=="POST":
        selected_post.title=form.title.data
        selected_post.subtitle=form.subtitle.data
        selected_post.category = form.category.data
        selected_post.image = form.img_url.data
        selected_post.body = form.body.data
        db.session.commit()
        return redirect(url_for("show_post",id=selected_post.id))
    return render_template("create-post.html",form=form)

@app.route('/delete-post',methods=["GET","POST"])
def delete_post():
    post_id = request.args.get('id')
    selected_post = BlogPost.query.get(post_id)
    db.session.delete(selected_post)
    db.session.commit()
    return redirect(url_for('home'))

if __name__ == "__main__":
    app.run(debug=True)
