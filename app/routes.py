from flask import render_template, redirect, url_for, flash, request
from flask_login import login_required, current_user, login_user, logout_user
from app.forms import EditProfileForm, RegistrationForm, LoginForm
from app import app, db, bcrypt
from .models import User


@app.route('/')
@app.route('/home')
def home():
    return render_template('home.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form = RegistrationForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user = User(username=form.username.data, email=form.email.data, password=hashed_password)
        db.session.add(user)
        db.session.commit()
        flash('Аккаунт создан! Теперь вы можете войти.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', form=form)


@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            login_user(user, remember=form.remember.data)
            next_page = request.args.get('next')
            return redirect(next_page) if next_page else redirect(url_for('home'))
        else:
            flash('Ошибка входа. Проверьте email и пароль.', 'danger')
    return render_template('login.html', form=form)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('home'))


@app.route('/account')
@login_required
def account():
    return render_template('account.html')


@app.route('/edit_profile', methods=['GET', 'POST'])
@login_required  # Только для авторизованных пользователей
def edit_profile():
    form = EditProfileForm(current_user)

    # При первом открытии формы подставляем текущие данные пользователя
    if request.method == 'GET':
        form.username.data = current_user.username
        form.email.data = current_user.email

    if form.validate_on_submit():
        # 1. Проверка текущего пароля
        if not bcrypt.check_password_hash(current_user.password, form.current_password.data):
            flash('Текущий пароль введен неверно.', 'danger')
            return render_template('edit_profile.html', form=form)

        # 2. Обновление имени пользователя и почты
        current_user.username = form.username.data
        current_user.email = form.email.data

        # 3. Обновление пароля, если введен новый
        if form.new_password.data:
            hashed_new_password = bcrypt.generate_password_hash(form.new_password.data).decode('utf-8')
            current_user.password = hashed_new_password

        # Сохранение изменений в базе данных
        db.session.commit()
        flash('Ваш профиль успешно обновлен!', 'success')
        return redirect(url_for('account'))  # Перенаправление на страницу аккаунта

    return render_template('edit_profile.html', form=form)