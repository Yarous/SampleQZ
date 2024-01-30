from flask import Flask, request, jsonify, session, redirect, url_for, render_template, flash
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask import session


app = Flask(__name__)
app.config['SECRET_KEY'] = '9991secretkey'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///db.sqlite'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {"pool_pre_ping": True}
db = SQLAlchemy(app)
first_request_initialized = False

@app.before_request
def before_request():
    global first_request_initialized
    if not first_request_initialized:
        db.create_all()
        first_request_initialized = True
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    status = db.Column(db.String(100))

#statuses
#0 - user
#1 - helper
#2 - moderator
#3 - admin
#themepicker



@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        user = User.query.filter_by(email=email).first()
        if user:
            flash('Email address already exists')
            return redirect(url_for('register'))

        new_user = User(email=email, password=generate_password_hash(password, method='pbkdf2:sha256'), status=3)
        db.session.add(new_user)
        db.session.commit()
        flash('Registration successful! Please login.')
        return redirect(url_for('login'))
    return render_template('Register.html')


@app.route('/')
def mainpage():
    is_authenticated = 'user_id' in session  # здесь будит True, если пользователь авторизован
    return render_template('Index.html', is_authenticated=is_authenticated)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        user = User.query.filter_by(email=email).first()
        if user and check_password_hash(user.password, password):
            flash('Login successful!')
            print("you loged in!")
            session['user_id'] = user.id
            return redirect(url_for('profile'))
        else:
            flash('Invalid login credentials!')

    return render_template('Login.html')

'''@app.route('/admin', methods=['GET', 'POST'])
def admin():
    global current_theme
    is_authenticated = 'user_id' in session
    if is_authenticated:
        user_id = session.get('user_id')
        print(user_id)
        user = db.session.get(User, user_id)
        print(str(user.status) + " USER")
    # Теперь проверим, достаточно ли у пользователя прав для доступа к админке
        if int(user.status) < 1:
            print(user.status)
            return render_template("access_denied.html")

        # пользователь имеет права админа
        if request.method == 'POST':
            selected_theme = request.form.get('theme')
            if selected_theme:
                current_theme = selected_theme
            return redirect(url_for('login'))
    else:
        return redirect(url_for('login'))
    print(current_theme)
    return render_template('admin.html', theme=current_theme)

'''
# ВЫПИЛИМ АДМИНКУ УАХАХАХАХАХАХАХАХАХАА

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    flash('You have been logged out.')
    return redirect(url_for('login'))


'''@app.route('/process', methods=['POST'])
def process():
    if 'user_id' not in session:
        return jsonify({"error": "Unauthorized access"}), 401

    user_id = session['user_id']
    print(user_id)
    data = request.get_json(force=True)

    page = data.get('page')
    variable = data.get('variable')

    if not page or variable is None:
        return jsonify({"error": "Missing 'page' or 'variable' data"}), 400

    if hasattr(User, page):
        user = db.session.get(User, user_id)
        print(user)
        if user:
            setattr(user, page, variable)
            db.session.commit()
            print("commited!")
            return jsonify({"success": f"Column {page} updated with value {variable} for user {user_id}."})
        else:
            print("dont commited!")
            return jsonify({"error": "User not found"}), 404
    else:
        return jsonify({"error": f"Column {page} does not exist in User model"}), 400 '''
#выше - если надо будет для получения данных из JS


@app.route('/profile')
def profile():
    is_authenticated = 'user_id' in session
    if is_authenticated:
        user_id = session.get('user_id')
        user = db.session.get(User, user_id)

        if user:
            return render_template('profile.html', user=user, is_authenticated=is_authenticated)
        else:
            flash('User not found.')
            return redirect(url_for('login'))
    else:
        flash('You are not logged in.')
        return redirect(url_for('login'))


@app.route('/about')
def about():
    is_authenticated = 'user_id' in session  # здесь будит True, если пользователь авторизован
    return render_template('About.html', is_authenticated=is_authenticated)




if __name__ == '__main__':
    app.run(debug=True,port=80,host="0.0.0.0")
