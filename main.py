from flask import Flask, render_template, session, request, url_for, redirect, flash, abort, session
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from flask_wtf.file import FileField, FileAllowed
from flask_bootstrap import Bootstrap
from wtforms import StringField, PasswordField, SubmitField, BooleanField, TextAreaField
from wtforms.validators import InputRequired, Email, Length, ValidationError
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_mail import Mail, Message
import os
from itsdangerous import TimedJSONWebSignatureSerializer as Serializer
from datetime import datetime
from flask_bcrypt import Bcrypt
from PIL import Image
from flask_admin import Admin, AdminIndexView
from flask_admin.contrib.sqla import ModelView
import secrets

app = Flask(__name__)

app.config['SECRET_KEY'] = 'jfale!@#gys^&*(@jafd00193n'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
Bootstrap(app)
db = SQLAlchemy(app)
app.config['MAIL_SERVER']='smtp.gmail.com'
app.config['MAIL_PORT'] = 465
app.config['MAIL_USERNAME'] = os.environ.get("EMAIL_BLOGGY")
app.config['MAIL_PASSWORD'] = os.environ.get("PASSWORD_BLOGGY")
app.config['MAIL_USE_TLS'] = False
app.config['MAIL_USE_SSL'] = True
mail = Mail(app)
bcrypt = Bcrypt(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.before_request
def make_session_permanent():
    session.permanent = True

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(15), unique=True)
    email = db.Column(db.String(50), unique=True)
    password = db.Column(db.String(80))
    profile_pic = db.Column(db.String(20), nullable=False, default='default.jpg')
    posts = db.relationship('Post', backref='author', lazy=True)
    bio_content = db.Column(db.String(1000))

    def get_reset_token(self, expires_sec=1800):
        s = Serializer(app.config['SECRET_KEY'], expires_sec)
        return s.dumps({'user_id': self.id}).decode('utf-8')

    @staticmethod
    def verify_reset_token(token):
        s = Serializer(app.config['SECRET_KEY'])
        try:
            user_id = s.loads(token)['user_id']
        except:
            return None
        return User.query.get(user_id)


class Post(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    post_title = db.Column(db.String(100), nullable=False)
    post_content = db.Column(db.String(1000), nullable=False)
    post_date = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)



class PostForm(FlaskForm):
    post_title = StringField("Title", validators=[InputRequired(), Length(min=4, max=40)])
    post_content = TextAreaField("Description", validators=[InputRequired(), Length(min=4, max=1000)])
    submit = SubmitField("Upload Post")


class UpdatePostForm(FlaskForm):
    post_title = StringField("Title", validators=[InputRequired(), Length(min=4, max=40)])
    post_content = TextAreaField("Description", validators=[InputRequired(), Length(min=4, max=1000)])
    submit = SubmitField("Update Post")

class LoginForm(FlaskForm):
    username = StringField("Username", validators=[InputRequired(), Length(min=4, max=50)])
    password = PasswordField("Password", validators=[InputRequired(), Length(min=4, max=15)])

class BioForm(FlaskForm):
    # bio = TextAreaField("Bio", validators=[InputRequired(), Length(min=4, max=1000)])
    bio = TextAreaField('Bio', [Length(min=0, max=1000)])

    submit = SubmitField("Update Bio")

class RegisterForm(FlaskForm):
    email = StringField("Email", validators=[InputRequired(), Email(message="Invalid Email"), Length(max=50)], render_kw={"placeholder": "example@gmail.com"})
    username = StringField("Username", validators=[InputRequired(), Length(min=4, max=15)])
    password = PasswordField("Password", validators=[InputRequired(), Length(min=4, max=15)], render_kw={"placeholder": "********"})

    def validate_username(self, username):
        existing_user_username = User.query.filter_by(username=username.data).first()
        if existing_user_username:
            raise ValidationError("That username already exists. Please choose a different one.")

    def validate_email(self, email):
        existing_user_email = User.query.filter_by(email=email.data).first()
        if existing_user_email:
            raise ValidationError("That email address belongs to different user. Please choose a different one.")


class UpdateAccount(FlaskForm):
    email = StringField("Email", validators=[InputRequired(), Email(message="Invalid Email"), Length(max=50)], render_kw={"placeholder": "example@gmail.com"})
    username = StringField("Username", validators=[InputRequired(), Length(min=4, max=15)])
    submit = SubmitField('Update Account')

    
    def validate_username(self, username):
        if current_user.username != username.data:
            user = User.query.filter_by(username=username.data).first()
            if user:
                raise ValidationError("That username already exists. Please choose a different one.")

    def validate_email(self, email):
        if current_user.email != email.data:
            email = User.query.filter_by(email=email.data).first()
            if email:
                raise ValidationError("That email address belongs to different user. Please choose a different one.")


class ForgotPasswordForm(FlaskForm):
    email = StringField("Email", validators=[InputRequired(), Email(message="Invalid Email"), Length(max=50)])

class ResetPasswordForm(FlaskForm):
    email = StringField("Email", validators=[InputRequired(), Email(message="Invalid Email"), Length(max=50)])
    # username = StringField("Username", validators=[InputRequired(), Length(min=4, max=15)])
    password = PasswordField("Password", validators=[InputRequired(), Length(min=4, max=15)])

class ChangePasswordForm(FlaskForm):
    email = StringField("Email", validators=[InputRequired(), Email(message="Invalid Email"), Length(max=50)])
    password = PasswordField("New Password", validators=[InputRequired(), Length(min=4, max=15)])

class DeleteAccountForm(FlaskForm):
    email = StringField("Email", validators=[InputRequired(), Email(message="Invalid Email"), Length(max=50)])
    username = StringField("Username", validators=[InputRequired(), Length(min=4, max=15)])
    password = PasswordField("Password", validators=[InputRequired(), Length(min=4, max=15)])
    submit = SubmitField("Delete My Account")


class MyModelView(ModelView):
    def is_accessible(self):
        return current_user.is_authenticated


    def inaccessible_callback(self, name, **kwargs):
        # redirect to login page if user doesn't have access
        return redirect(url_for('login'))


class MyAdminView(AdminIndexView):
    def is_accessible(self):
        return current_user.is_authenticated


admin = Admin(app, index_view=MyAdminView())
admin.add_view(MyModelView(User, db.session))
admin.add_view(MyModelView(Post, db.session))


# Error handling
@app.errorhandler(404)
def page_not_found(e):
    return "<h1>404 Page Not Found</h1>", 404


@app.errorhandler(403)
def page_not_found(e):
    return "<h1>403 You do not have permission to do that.</h1>", 403


# Admin
@app.route('/admin_login')
def admin_login():
    user = User.query.get(1)
    login_user(user)
    return 'logged in'

@app.route('/admin_logout')
def admin_logout():
    logout_user()
    return 'logged out'

# Home Page
@app.route("/home")
@app.route("/")
def home():
    return render_template("index.html", title="Welcome to Bloggy!")



# User Home Page
@app.route("/userhome")
@login_required
def userhome():
    posts = Post.query.all()
    return render_template("userhome.html", posts=posts, title="My Dashboard")




# User Account Information
@app.route("/profile", methods=['GET', 'POST'])
@login_required
def profile():
    posts = Post.query.filter_by(author=current_user).first()
    form = UpdateAccount()
    if form.validate_on_submit():
        current_user.username = form.username.data
        current_user.email = form.email.data
        db.session.commit()
        flash('Your account has been updated!', 'success')
        return redirect(url_for('profile'))
    elif request.method == 'GET':
        form.username.data = current_user.username
        form.email.data = current_user.email
    return render_template("profile.html", name=current_user.username, email=current_user.email, title="My Profile", form=form, posts=posts, image_file=profile_pic)


# Create Bio
@app.route("/profile/bio", methods=["GET", 'POST'])
@login_required
def bio():
    form = BioForm()
    if form.validate_on_submit():
        current_user.bio_content = form.bio.data
        db.session.commit()
        flash("Your bio has been updated!", 'success')
        return redirect(url_for('profile'))
    elif request.method == 'GET':
        form.bio.data = current_user.bio_content

    return render_template('bio.html', form=form, title="Update Bio")



# If a user visits another user's profile
@app.route("/user/<username>")
@login_required
def user(username):
    user = User.query.filter_by(username=username).first_or_404()
    return render_template('user.html', title=user.username, user=user, posts=user.posts)




# Change Password
@app.route("/changepassword", methods=['GET', 'POST'])
@login_required
def change_password():
    form = ChangePasswordForm()

    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data)
        user = User.query.filter_by(email=form.email.data).first()
        if user is not None:
            user.password = hashed_password
            db.session.commit()

        return redirect(url_for('change_password_redirect'))

    return render_template("changepw.html", form=form, title="Change Password")



# Create the post
@app.route("/post", methods=['GET', 'POST'])
@login_required
def create_post():
    form = PostForm()

    if form.validate_on_submit():
        post = Post(post_title=form.post_title.data, post_content=form.post_content.data, author=current_user)
        db.session.add(post)
        db.session.commit()


        return redirect(url_for('userhome'))
    return render_template("create_post.html", form=form, title="New Post", legend='New Post')



# Post Id
@app.route("/post/<int:post_id>")
@login_required
def post(post_id):
    post = Post.query.get_or_404(post_id)
    return render_template('postid.html', title=post.post_title, post=post)



# Update Posts
@app.route("/post/<int:post_id>/update", methods=['GET', 'POST'])
@login_required
def update_post(post_id):
    form = PostForm()

    post = Post.query.get_or_404(post_id)
    if post.author != current_user:
        abort(403)
    if form.validate_on_submit():
        post.post_title = form.post_title.data
        post.post_content = form.post_content.data
        db.session.commit()
        return redirect(url_for('userhome'))
    elif request.method == 'GET':
        form.post_title.data = post.post_title
        form.post_content.data = post.post_content
    flash("Your post has been updated!", "success")
    return render_template('update_post.html', title='Update Post', form=form, post=post_id)



# Delete the post
@app.route("/post/<int:post_id>/delete", methods=['GET','POST'])
@login_required
def delete_post(post_id):
    form = PostForm()
    post = Post.query.get_or_404(post_id)
    if current_user != post.author:
        abort(403)
    db.session.delete(post)
    db.session.commit()
    flash('Your post has been deleted!', 'success')
    return redirect(url_for('userhome'))


# Delete User Account
@app.route("/delete_account", methods=['GET', 'POST'])
@login_required
def delete_account():
    form = DeleteAccountForm()
    posts = Post.query.filter_by(author=current_user).all()
    user = User.query.filter_by(email=form.email.data).first()
    if form.validate_on_submit():
        for post in posts:
            db.session.delete(post)
        db.session.delete(user)
        db.session.commit()
        flash('Your account has been deleted', 'success')
        return redirect(url_for('login'))
    return render_template("deleteacc.html", form=form, title="Delete My Account")



# Logging In
@app.route('/login', methods=["GET", "POST"])
def login():
    form = LoginForm()

    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            if bcrypt.check_password_hash(user.password, form.password.data):
                login_user(user)
                return redirect(url_for("userhome"))
        flash("User does not exist, or invalid username or password.", 'warning')
    return render_template("login.html", form=form, title="Login")



# Logout
@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("login"))




# Registration
@app.route("/signup", methods=["GET", "POST"])
def signup():
    form = RegisterForm()

    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data)
        new_user = User(username=form.username.data, email=form.email.data, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        msg = Message('Welcome to Bloggy!', sender = 'bloggywebsite@gmail.com', recipients = [form.email.data])
        msg.body = "Hello, welcome to Bloggy!"
        mail.send(msg)


        flash(f"Your account has been created for {form.username.data}", 'success')
        return redirect(url_for('login'))
    return render_template("signup.html", form=form, title="Sign Up")


# Reset email
def send_reset_email(user):
    token = user.get_reset_token()
    msg = Message('Forgot your password?',
                  sender='noreply@demo.com',
                  recipients=[user.email])
    msg.body = f'''To reset your password, visit the following link:
    {url_for('reset_password', token=token, _external=True)}
If you did not make this request then simply ignore this email.
'''
    mail.send(msg)


# Forgot password
@app.route("/forgotpassword", methods=["GET", "POST"])
def forgot_password():
    form = ForgotPasswordForm()
    if current_user.is_authenticated:
        return redirect(url_for('userhome'))
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        send_reset_email(user)
        flash("An email has been sent to reset your password.", 'success')


    return render_template("forgotpw.html", form=form, title="Forgot Password")


# Reset password
@app.route("/resetpassword/<token>", methods=["GET", "POST"])
def reset_password(token):
    if current_user.is_authenticated:
        return redirect(url_for('userhome'))
    user = User.verify_reset_token(token)
    if user is None:
        flash('That is an invalid or expired token', 'warning')
        return redirect(url_for('forgot_password'))
    form = ResetPasswordForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data)
        user.password = hashed_password
        db.session.commit()
        flash('Your password has been updated! You are now able to log in', 'success')
        return redirect(url_for('login'))
    return render_template('resetpw.html', title='Reset Password', form=form)


# Redirect after password changes
@app.route("/passwordchangesuccess")
@login_required
def change_password_redirect():
    return render_template("pwredirect.html")




if __name__ == "__main__":
    app.run(debug=True)
