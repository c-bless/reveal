from flask import render_template, redirect, url_for, request, abort, flash
from flask_login import login_user, login_required, logout_user

from . import auth_bp
from .forms import LoginForm
from ..models.auth import AuthUser


def is_url_allowed(url, host):
    return True


@auth_bp.route('/', methods=['GET'])
def index():
    return render_template('index.html')


@auth_bp.route("/profile")
@login_required
def profile():
    return 'Profile'


@auth_bp.route("/login", methods=['GET'])
def login():
    print("A")
    form = LoginForm()
    return render_template('login.html', form=form)


@auth_bp.route("/login", methods=['POST'])
def login_post():
    form = LoginForm()
    if form.validate_on_submit():
        user =  AuthUser.query.filter(AuthUser.Username == form.username.data).first()
        if user is None or not user.check_password(form.password.data):
            flash('Invalid username or password')
            return redirect(url_for('auth.login'))
        login_user(user, remember=form.remember_me.data)
        return redirect(url_for('auth.index'))

    return render_template('login.html', form=form)


@auth_bp.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for('auth.index'))




