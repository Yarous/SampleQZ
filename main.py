from flask import Flask, request, jsonify, session, redirect, url_for, render_template, flash
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask import session
from werkzeug.utils import secure_filename
import os
from flask import send_from_directory

UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
app = Flask(__name__)
app.config['SECRET_KEY'] = '9991secretkey'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///db.sqlite'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {"pool_pre_ping": True}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
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
    status = db.Column(db.Integer, default=0)

#statuses
#0 - user
#1 - helper
#2 - moderator
#3 - admin
#themepicker



def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


def get_extension(filename):
    """
    Возвращает расширение файла, начиная с последней точки.

    :param filename: Имя файла с возможным расширением.
    :return: Расширение файла с точкой или пустая строка, если расширение отсутствует.
    """
    # Находим индекс последней точки в строке
    last_dot_index = filename.rfind('.')

    # Проверяем, есть ли после точки какое-либо расширение
    if last_dot_index != -1:
        # Возвращаем расширение файла
        return filename[last_dot_index:]
    else:
        # Возвращаем пустую строку, если точка не найдена
        return ""

# def process_email_for_avatar(email):
#     """
#     Обрезает домен верхнего уровня из email (всё после точки).
#
#     :param email: Исходный email пользователя.
#     :return: Email пользователя без домена верхнего уровня.
#     """
#     # Разделяем email на имя пользователя и домен, затем домен разделяем на части по точке
#     username, domain = email.split('@')
#     domain_without_tld = domain.split('.')[0]  # Берем только первую часть домена до точки
#     modified_email = f'{username}@{domain_without_tld}'
#     return modified_email


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        user = User.query.filter_by(email=email).first()

        if user:
            # Здесь пользователь уже существует, сообщаем об этом
            flash('Email address already exists')
            return redirect(url_for('register'))

        # Если пользователя нет, то создаем нового
        new_user = User(email=email, password=generate_password_hash(password, method='pbkdf2:sha256'), status=0)
        file = request.files['avatar']
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            # Убираем все после '@' и добавляем имя файла
            avatar_filename = email + get_extension(filename)
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], avatar_filename))
            new_user.avatar = avatar_filename

        try:
            # Пытаемся добавить пользователя и сохранить изменения
            db.session.add(new_user)
            db.session.commit()
            flash('Registration successful! Please login.')
            return redirect(url_for('login'))
        except sqlalchemy.exc.IntegrityError:
            # Если возникла ошибка IntegrityError, то откатываем изменения
            db.session.rollback()
            flash('An error occurred. Email might be already registered.')
            return redirect(url_for('register'))

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

@app.route('/tests')
def tests():
    is_authenticated = 'user_id' in session  # здесь будит True, если пользователь авторизован
    return render_template('Tests.html', is_authenticated=is_authenticated)


@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory('uploads', filename)


def find_avatar_filename(email):
    base_dir = os.path.abspath(os.path.dirname(__file__))  # file заменено на __file__
    upload_dir = os.path.join(base_dir, 'uploads')  # убран слеш перед uploads
    print(str(upload_dir) + " directory")

    # Имя файла без расширения, оставляем email без изменений
    filename_without_extension = email

    for extension in ALLOWED_EXTENSIONS:
        # Дополнительно очищаем только расширение файла, но не само имя файла
        safe_extension = secure_filename(extension)
        filename = f"{filename_without_extension}.{safe_extension}"  # Создаем имя файла
        print(str(filename) + " filename")
        file_path = os.path.join(upload_dir, filename)  # Полный путь к файлу
        print(str(file_path) + " filepath")
        if os.path.isfile(file_path):
            return filename

    return None  # Если файл не найден, возвращаем None

# Пример использования
@app.route('/profile')
def profile():
    is_authenticated = 'user_id' in session
    if is_authenticated:
        user_id = session.get('user_id')
        user = db.session.get(User, user_id)
        if user:
            email = user.email
            avatar_filename = find_avatar_filename(email)
            print(avatar_filename)# Получаем имя файла с правильным расширением
            if avatar_filename:
                avatar_url = url_for('uploaded_file', filename=avatar_filename)
            else:
                avatar_url = url_for('static', filename='default-avatar.svg')  # Путь к аватару по умолчанию
            return render_template('profile.html', user=user, is_authenticated=is_authenticated, avatar_url=avatar_url)
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
