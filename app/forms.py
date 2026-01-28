from wtforms import StringField, PasswordField, SubmitField, ValidationError
from wtforms.validators import DataRequired, Length, Email, EqualTo
from flask_wtf import FlaskForm
from app.models import User


class EditProfileForm(FlaskForm):
    # Поля для имени и почты
    username = StringField('Имя пользователя', validators=[DataRequired(), Length(min=2, max=20)])
    email = StringField('Email', validators=[DataRequired(), Email()])

    # Поле для подтверждения текущего пароля
    current_password = PasswordField('Текущий пароль', validators=[DataRequired()])

    # Поля для нового пароля (не обязательные для заполнения)
    new_password = PasswordField('Новый пароль (оставьте пустым, если не хотите менять)', validators=[Length(min=6)])
    confirm_new_password = PasswordField('Подтвердите новый пароль',
                                         validators=[EqualTo('new_password', message='Пароли должны совпадать.')])

    submit = SubmitField('Обновить профиль')

    # Валидация уникальности имени пользователя
    def validate_username(self, username):
        # Проверка, не занято ли имя другим пользователем, кроме текущего
        user = User.query.filter_by(username=username.data).first()
        if user and user.id != current_user.id:
            raise ValidationError('Это имя пользователя уже занято.')

    def validate_email(self, email):
        # Проверка, не используется ли email другим пользователем, кроме текущего
        user = User.query.filter_by(email=email.data).first()
        if user and user.id != current_user.id:
            raise ValidationError('Этот email уже используется.')