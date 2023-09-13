import os

from flask import Flask, render_template, request, flash, redirect, session, g,abort
from flask_debugtoolbar import DebugToolbarExtension
from sqlalchemy.exc import IntegrityError
from flask_bcrypt import check_password_hash,bcrypt
# from bcrypt import  check_password_hash
from forms import UserAddForm, LoginForm, MessageForm,EditPassword
from models import db, connect_db, User, Message,bcrypt

CURR_USER_KEY = "curr_user"

app = Flask(__name__)



# Get DB_URI from environ variable (useful for production/testing) or,
# if not set there, use development local db.
app.config['SQLALCHEMY_DATABASE_URI'] = (
    os.environ.get('DATABASE_URL', 'postgresql:///warbler'))

app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_ECHO'] = False
app.config['DEBUG_TB_INTERCEPT_REDIRECTS'] = True
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', "it's a secret")

toolbar = DebugToolbarExtension(app)
# bcrypt = Bcrypt(app)
connect_db(app)
app.app_context().push()
db.create_all()


##############################################################################
# User signup/login/logout


@app.before_request
def add_user_to_g():
    """If we're logged in, add curr user to Flask global."""

    if CURR_USER_KEY in session:
        g.user = User.query.get(session[CURR_USER_KEY])

    else:
        g.user = None


def do_login(user):
    """Log in user."""

    session[CURR_USER_KEY] = user.id


def do_logout():
    """Logout user."""

    if CURR_USER_KEY in session:
        del session[CURR_USER_KEY]


@app.route('/signup', methods=["GET", "POST"])
def signup():
    """Handle user signup.

    Create new user and add to DB. Redirect to home page.

    If form not valid, present form.

    If the there already is a user with that username: flash message
    and re-present form.
    """

    form = UserAddForm()


    if form.validate_on_submit():
        try:
            user = User.signup(
                username=form.username.data,
                password=form.password.data,
                email=form.email.data,
                image_url=form.image_url.data or User.image_url.default.arg,
                location=form.location.data,
                bio=form.bio.data,
                header_image_url=form.header_image_url.data
                
            )
            db.session.commit()
        

        except IntegrityError:
            flash("Username already taken", 'danger')
            return render_template('users/signup.html', form=form)

        do_login(user)

        return redirect("/")

    else:
        return render_template('users/signup.html', form=form)


@app.route('/login', methods=["GET", "POST"])
def login():
    """Handle user login."""

    form = LoginForm()

    if form.validate_on_submit():
        user = User.authenticate(form.username.data,
                                 form.password.data)
        

        if user:
            do_login(user)
            flash(f"Hello, {user.username}!", "success")
        
            return redirect("/")

        flash("Invalid credentials.", 'danger')

            

    return render_template('users/login.html', form=form)


@app.route('/logout')
def logout():
    """Handle logout of user."""
    flash("you have successfuly log out", 'success')
    return redirect('/login')

    # IMPLEMENT THIS


##############################################################################
# General user routes:

@app.route('/users')
def list_users():
    """Page with listing of users.

    Can take a 'q' param in querystring to search by that username.
    """

    search = request.args.get('q')

    if not search:
        users = User.query.all()
    else:
        users = User.query.filter(User.username.like(f"%{search}%")).all()

    return render_template('users/index.html', users=users)



@app.route('/users/<int:user_id>')
def users_show(user_id):
    """Show user profile."""

    user = User.query.get_or_404(user_id)
    # snagging messages in order from the database;
    # user.messages won't be in order by default
    messages = (Message
                .query
                .filter(Message.user_id == user_id)
                .order_by(Message.timestamp.desc())
                .limit(100)
                .all())
    return render_template('users/show.html', user=user, messages=messages)



@app.route('/users/<int:user_id>/following')
def show_following(user_id):
    """Show list of people this user is following."""

    if not g.user:
        flash("Access unauthorized.", "danger")
        return redirect("/")

    user = User.query.get_or_404(user_id)
    import pdb
    pdb.set_trace()
    return render_template('users/following.html', user=user)


@app.route('/users/<int:user_id>/followers')
def users_followers(user_id):
    """Show list of followers of this user."""

    if not g.user:
        flash("Access unauthorized.", "danger")
        return redirect("/")

    user = User.query.get_or_404(user_id)
    return render_template('users/followers.html', user=user)


@app.route('/users/follow/<int:follow_id>', methods=['POST'])
def add_follow(follow_id):
    """Add a follow for the currently-logged-in user."""

    if not g.user:
        flash("Access unauthorized.", "danger")
        return redirect("/")

    followed_user = User.query.get_or_404(follow_id)
    g.user.following.append(followed_user)
    db.session.commit()

    return redirect(f"/users/{g.user.id}/following")


@app.route('/users/stop-following/<int:follow_id>', methods=['POST'])
def stop_following(follow_id):
    """Have currently-logged-in-user stop following this user."""

    if not g.user:
        flash("Access unauthorized.", "danger")
        return redirect("/")

    followed_user = User.query.get(follow_id)
    g.user.following.remove(followed_user)
    db.session.commit()

    return redirect(f"/users/{g.user.id}/following")


@app.route('/users/profile', methods=["GET"])
def profile():
    """Update profile for current user."""

    if not g.user:
        flash("Access unauthorized.", "danger")
        return redirect("/")
    
    
    form=UserAddForm()
    import pdb
    pdb.set_trace()
    return render_template ("users/edit.html",form=form)

@app.route('/users/profile', methods=["POST"])
def handleModification():
    """Handle modification of users' profiles."""
    form=UserAddForm()
    user=g.user
    passwordcorrect=user.password
    password=form.password.data
    # import pdb
    # pdb.set_trace()
    if check_password_hash(passwordcorrect, password):
        username=form.username.data,
        email=form.email.data,
        image_url=form.image_url.data or User.image_url.default.arg,
        location=form.location.data,
        bio=form.bio.data,
        header_image_url=form.header_image_url.data
       
        if form.validate_on_submit():
            user.username=username
            user.email=email
            user.image_url=image_url
            user.location=location
            user.location=location
            user.bio=bio
            user.header_image_url=header_image_url
            db.session.commit()
            flash('Your changes have been saved.', category='success')
            import pdb
            pdb.set_trace()
            # user= User(email=user.email,username=user.username,image_url=user.image_url,location=user.location,bio=user.bio,header_image_url=user.header_image_url)
            # # db.session.add(user)
            return render_template("/users/detail.html",user=user)
        return redirect('users/profile')
    flash("wrong password", 'danger')
    return redirect('/')







    

    
    # user=g.user

    # user=g.user
    # name="jojo"
    # user.username=name
    
    # user=g.user
    # import pdb
    # pdb.set_trace()

    # if form.validate_on_submit():
    #         new_username = form.new_username.data
    #         new_email = form.new_email.data
    #         new_image_url = form.new_image_url.data
    #         new_location=form.new_location.data
    #         new_bio=form.new_bio.data
    #         new_header_image_url=form.new_header_image_url.data

    #         user.username=new_username
    #         user.email=new_email
    #         user.image_url=new_image_url
    #         user.location=new_location
    #         user.bio=new_bio
    #         user.header_image_url=new_header_image_url


            

            #            user.location=new_location #not sure how to do this yet, but will need it eventually
    return render_template ("users/edit.html",form=form)   
 


   

    # if not g.user:
    #     flash("Access unauthorized.","danger")
    #     if form.validate_on_submit():
            
    # return render_template('edit.html')

        





    # IMPLEMENT THIS


@app.route('/users/delete', methods=["POST"])
def delete_user():
    """Delete user."""

    if not g.user:
        flash("Access unauthorized.", "danger")
        return redirect("/")
    

    do_logout()

    db.session.delete(g.user)
    db.session.commit()

    return redirect("/signup")

 
##############################################################################
# Messages routes:

@app.route('/messages/new', methods=["GET", "POST"])
def messages_add():
    """Add a message:

    Show form if GET. If valid, update message and redirect to user page.
    """

    if not g.user:
        flash("Access unauthorized.", "danger")
        return redirect("/")

    form = MessageForm()

    if form.validate_on_submit():
        msg = Message(text=form.text.data)
        g.user.messages.append(msg)
        db.session.commit()

        return redirect(f"/users/{g.user.id}")

    return render_template('messages/new.html', form=form)


@app.route('/messages/<int:message_id>', methods=["GET"])
def messages_show(message_id):
    """Show a message."""

    msg = Message.query.get(message_id)
    return render_template('messages/show.html', message=msg)


@app.route('/messages/<int:message_id>/delete', methods=["POST"])
def messages_destroy(message_id):
    """Delete a message."""

    if not g.user:
        flash("Access unauthorized.", "danger")
        return redirect("/")

    msg = Message.query.get(message_id)
    db.session.delete(msg)
    db.session.commit()

    return redirect(f"/users/{g.user.id}")


##############################################################################
# Homepage and error pages

@app.route('/')
def homepage():
    """Show homepage:

    - anon users: no messages
    - logged in: 100 most recent messages of followed_users
    """

    if g.user:
        following_ids = [f.id for f in g.user.following] + [g.user.id]

        messages = (Message
                    .query
                    .filter(Message.user_id.in_(following_ids))
                    .order_by(Message.timestamp.desc())
                    .limit(100)
                    .all())

        return render_template('home.html', messages=messages)

    else:
        return render_template('home-anon.html')
##############################################################################
# Turn off all caching in Flask
#   (useful for dev; in production, this kind of stuff is typically
#   handled elsewhere)
#
# https://stackoverflow.com/questions/34066804/disabling-caching-in-flask

@app.after_request
def add_header(req):
    """Add non-caching headers on every request."""

    req.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    req.headers["Pragma"] = "no-cache"
    req.headers["Expires"] = "0"
    req.headers['Cache-Control'] = 'public, max-age=0'
    return req


@app.route('/users/<int:user_id>/likes', methods=["GET"])
def show_likes(user_id):
    if not g.user:
        flash("Access unauthorized.", "danger")
        return redirect("/")

    user = User.query.get_or_404(user_id)
    return render_template('users/likes.html', user=user, likes=user.likes)


@app.route('/messages/<int:message_id>/like', methods=['POST'])
def add_like(message_id):
    """Toggle a liked message for the currently-logged-in user."""

    if not g.user:
        flash("Access unauthorized.", "danger")
        return redirect("/")

    liked_message = Message.query.get_or_404(message_id)
    if liked_message.user_id == g.user.id:
        return abort(403)
    

    user_likes = g.user.likes

    if liked_message in user_likes:
        g.user.likes = [like for like in user_likes if like != liked_message]
    else:
        g.user.likes.append(liked_message)

    db.session.commit()

    return redirect("/")

@app.route('/users/password',methods=['GET'])
def get_password():
    form=EditPassword()
    return render_template('users/change.html',form=form)

@app.route('/users/password',methods=['POST'])
def new_password():
    form=EditPassword()
    if form.validate_on_submit():
        Current_password = form.Current_password.data
        new_password = form.new_password.data
        confirm_password = form.confirm_password.data

    # Current_password_hashed=bcrypt.generate_password_hash(Current_password).decode('utf-8')
    # if check_password_hash(correct_password, Current_password_hashed):
        if bcrypt.check_password_hash(Current_password,g.user.password):
            if new_password == confirm_password:
                new_password=form.new_password.data
                confirm_password=form.confirm_password.data
            # Hash the new password before storing it
                hashed_password = bcrypt.generate_password_hash (new_password).decode('utf-8')
                g.user.password = hashed_password
                db.session.commit()
                import pdb
                pdb.set_trace()
                flash("your password has been changed ", 'success')
                return redirect('/')
            flash("your password doesn't match your confirmation password ", 'danger')
        return redirect('/')
    flash("your current password is wrong ", 'danger')
    return redirect('/users/password')





