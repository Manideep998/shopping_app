import os
from flask import Flask, render_template, request, redirect, url_for,flash
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_login import LoginManager, UserMixin, login_required, login_user, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy import delete
from sqlalchemy import update
from sqlalchemy.orm.attributes import flag_modified


app = Flask(__name__)
basedir = os.path.abspath(os.path.dirname(__file__))
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'data.sqlite')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'mykey'

db = SQLAlchemy(app)
Migrate(app, db)

login_manager = LoginManager()
login_manager.init_app(app)

# Tell users what view to go to when they need to login.
login_manager.login_view = "index"

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)

class User(db.Model, UserMixin):

    # Create a table in the db
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key = True)
    first_name = db.Column(db.String(30))
    last_name = db.Column(db.String(30))
    email = db.Column(db.String(64), unique=True, index=True)
    password_hash = db.Column(db.String(128))

    def __init__(self, first_name, last_name, email, password):
        self.first_name = first_name
        self.last_name = last_name
        self.email = email
        self.password_hash = generate_password_hash(password)

    def check_password(self,password):
        return check_password_hash(self.password_hash,password)
    
class Notes(db.Model):
    __tablename__ = "shopping_list"
    id = db.Column(db.Integer, primary_key=True)
    item = db.Column(db.Text)
    quantity = db.Column(db.Integer)
    category = db.Column(db.String(64))
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))

    def __init__(self, item, quantity, category, user_id):
        self.item = item
        self.quantity = quantity
        self.category = category
        self.user_id = user_id

    def __repr__(self):
        return f"Notes - {self.item}, {self.quantity}, {self.category}"


with app.app_context():
    db.create_all()

#Index page
@app.route("/",methods = ['GET','POST'])
def index():
    login_warning = None
    if request.method == "POST":
        user = User.query.filter_by(email=request.form['email']).first()
        if user and user.check_password(request.form['password']):
            login_user(user)
            next = request.args.get('next')
            if next is None or not next.startswith('/'):
                next = url_for('shopping')
            return redirect(next)
        else:
            login_warning = 'Invalid email or password. Please try again.'

    return render_template("index.html", login_warning=login_warning)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == "POST":
        fName = request.form.get('first_name')
        lName = request.form.get('last_name')
        email = request.form.get('email')
        password=request.form.get('password')
        c_password=request.form.get('confirm_password')
        # Check email length
        if len(email) < 7:
            return render_template('register.html', m='Email must be at least 7 characters long.')
        # Check password length
        
        if len(password) < 7:
            return render_template('register.html', m='Password must be at least 7 characters long.')
        # Check if email already exists
        user = User.query.filter_by(email=email).first()
        if not fName:
            return render_template('register.html', m='Please enter a first name.')
        if not lName:
            return render_template('register.html', m='Please enter a last name.')
        if user:
            return render_template('register.html', m='Email already exists.')
        if not email:
            return render_template('register.html', m='Please enter an email.')
        if not password:
            return render_template('register.html', m='Please enter a password.')
        if not c_password:
            return render_template('register.html', m='Please confirm your password.')
        if password==c_password:
            user = User(first_name = fName,
                        last_name = lName,
                        email= email,
                        password= password)
            db.session.add(user)
            db.session.commit()
            return redirect(url_for('index'))
        else:
            return render_template('register.html',m='password missmatch')
        
    return render_template('register.html')


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))


@app.route('/shopping', methods=['GET', 'POST'])
@login_required
def shopping():
    if request.method == "POST":
        item = request.form.get('item')
        quantity = request.form.get('quantity')
        category = request.form.get('category')
        
        if not item or not quantity or not category:
            return render_template('shopping.html', m='Please fill in all fields.')

        user_id = current_user.id
        note_id = request.form.get('note_id') 

        if note_id:
            note = Notes.query.filter_by(id=note_id, user_id=user_id).first()
            if note:
                note.item = item
                note.quantity = quantity
                note.category = category
                db.session.commit()
                return render_template('shopping.html', m='Item updated successfully')

        note = Notes(item=item, quantity=quantity, category=category, user_id=user_id)
        try:
            db.session.add(note)
            db.session.commit()
            return render_template('shopping.html', m='Item added successfully')
        except Exception as e:
            db.session.rollback()
            return render_template('shopping.html', m='Failed to add item')

    user_notes = Notes.query.filter_by(user_id=current_user.id).all()
    return render_template('shopping.html', user_notes=user_notes)

@app.route('/display')
@login_required
def display():
    user_notes = Notes.query.filter_by(user_id=current_user.id).all()
    return render_template('display.html', notes=user_notes)

@app.route('/delete/<int:id>', methods=['GET', 'POST'])
@login_required
def delete(id):
    note = Notes.query.filter_by(id=id, user_id=current_user.id).first()
    if note:
        db.session.delete(note)
        db.session.commit()
        return render_template('display.html', m='Item deleted successfully')
    else:
        return render_template('display.html', m='Item not found')

@app.route('/update/<int:id>', methods=['GET', 'POST'])
@login_required
def update(id):
    note = Notes.query.filter_by(id=id, user_id=current_user.id).first()

    if not note:
        return render_template('shopping.html', m='Item not found')

    if request.method == 'POST':
        if note.user_id == current_user.id:  # Check if the note belongs to the current user
            note.item = request.form['item']
            note.quantity = request.form['quantity']
            note.category = request.form['category']
            db.session.commit()
            return render_template('shopping.html', m='Item updated successfully')
        else:
            return render_template('shopping.html', m='You are not allowed to edit this item')

    return render_template('shopping.html', note=note)

@app.route('/delete_all', methods=['GET', 'POST'])
@login_required
def delete_all():
    user_notes = Notes.query.filter_by(user_id=current_user.id).all()
    for note in user_notes:
        db.session.delete(note)
    db.session.commit()
    return render_template('display.html', m='All items deleted successfully')


@app.route('/profile')
@login_required
def profile():
    users = User.query.all()
    return render_template('profile.html', users = users)


if __name__ == "__main__":
    app.run(debug=True)