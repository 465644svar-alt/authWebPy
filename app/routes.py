from flask import render_template, redirect, url_for, flash, request
from flask_login import login_required, current_user
from app.forms import EditProfileForm
from app import app, db, bcrypt
from .models import User


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